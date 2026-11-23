"""Certificate Transparency (CT) Log Server.

Maintains an append-only log of X.509 certificates, computes Signed Tree Heads (STH),
issues Signed Certificate Timestamps (SCT), and delivers Merkle inclusion & consistency proofs.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from storage.database import DatabaseManager
from ct.merkle_tree import MerkleTree


class CTLogServer:
    """Manages the CT append-only log, tree state, SCT issuance, and STH signing."""

    def __init__(
        self,
        certs_dir: Optional[str] = None,
        db_manager: Optional[DatabaseManager] = None
    ):
        base_dir = Path(__file__).resolve().parent.parent
        self.certs_dir = Path(certs_dir) if certs_dir else (base_dir / "certs")
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        self.db = db_manager if db_manager else DatabaseManager()

        self.key_path = self.certs_dir / "ct_log.key"
        self.pub_path = self.certs_dir / "ct_log.pub"

        self.log_private_key: Optional[rsa.RSAPrivateKey] = None
        self.log_public_key: Optional[rsa.RSAPublicKey] = None
        self._setup_log_keys()

        # In-memory Merkle Tree synced from database
        self.tree = MerkleTree()
        self._sync_tree_from_db()

    def _setup_log_keys(self) -> None:
        """Loads or generates the CT Log operator's cryptographic key pair."""
        if self.key_path.exists() and self.pub_path.exists():
            self.log_private_key = serialization.load_pem_private_key(
                self.key_path.read_bytes(),
                password=None
            )
            self.log_public_key = serialization.load_pem_public_key(
                self.pub_path.read_bytes()
            )
        else:
            self.log_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.log_public_key = self.log_private_key.public_key()

            priv_pem = self.log_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_pem = self.log_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.key_path.write_bytes(priv_pem)
            self.pub_path.write_bytes(pub_pem)

    def _sync_tree_from_db(self) -> None:
        """Populates the in-memory Merkle Tree from the database records."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.cert_der
                FROM ct_log_entries e
                JOIN certificates c ON e.cert_serial = c.serial_number
                ORDER BY e.entry_index ASC
            """)
            rows = cursor.fetchall()
            if len(rows) > self.tree.size:
                for r in rows[self.tree.size:]:
                    self.tree.append(r["cert_der"])

    def get_log_id(self) -> str:
        """Returns the SHA-256 fingerprint of the CT Log's public key."""
        import hashlib
        pub_der = self.log_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(pub_der).hexdigest()

    # --- SCT (Signed Certificate Timestamp) Issuance ---

    def log_certificate(self, cert_serial: str, cert_der: bytes) -> Dict[str, Any]:
        """Submits a certificate to the append-only CT log and returns a Signed Certificate Timestamp (SCT)."""
        leaf_hash_bytes = MerkleTree.hash_leaf(cert_der)
        leaf_hash_hex = leaf_hash_bytes.hex()

        # Check if already in log
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_index FROM ct_log_entries WHERE cert_serial = ?", (cert_serial,))
            row = cursor.fetchone()

        if row:
            entry_index = row["entry_index"] - 1  # 0-based index
        else:
            entry_index = self.tree.append(cert_der)
            # DB entry_index is 1-based AUTOINCREMENT
            self.db.append_ct_entry(cert_serial=cert_serial, leaf_hash=leaf_hash_hex)

        now_iso = datetime.now(timezone.utc).isoformat()
        
        # Sign the SCT payload: (log_id, timestamp, leaf_hash)
        sct_data = f"SCT:v1:{self.get_log_id()}:{now_iso}:{leaf_hash_hex}".encode("utf-8")
        signature = self.log_private_key.sign(
            sct_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        sct = {
            "sct_version": 1,
            "log_id": self.get_log_id(),
            "timestamp": now_iso,
            "entry_index": entry_index,
            "cert_serial": cert_serial,
            "leaf_hash": leaf_hash_hex,
            "signature": signature.hex()
        }
        return sct

    # --- STH (Signed Tree Head) ---

    def get_signed_tree_head(self) -> Dict[str, Any]:
        """Computes and signs the Signed Tree Head (STH) representing the current log state."""
        self._sync_tree_from_db()
        tree_size = self.tree.size
        root_hash = self.tree.get_root_hash_hex()
        now_iso = datetime.now(timezone.utc).isoformat()

        sth_data = f"STH:v1:{tree_size}:{now_iso}:{root_hash}".encode("utf-8")
        signature = self.log_private_key.sign(
            sth_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return {
            "tree_size": tree_size,
            "timestamp": now_iso,
            "root_hash": root_hash,
            "signature": signature.hex(),
            "log_id": self.get_log_id()
        }

    # --- Proof Retrieval ---

    def get_inclusion_proof_by_serial(self, cert_serial: str) -> Optional[Dict[str, Any]]:
        """Finds a certificate's leaf index and generates its Merkle inclusion proof."""
        self._sync_tree_from_db()
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT entry_index, leaf_hash 
                FROM ct_log_entries 
                WHERE cert_serial = ?
            """, (cert_serial,))
            row = cursor.fetchone()

        if not row:
            return None

        # Convert 1-based database index to 0-based tree index
        leaf_index = row["entry_index"] - 1
        leaf_hash = row["leaf_hash"]
        proof = self.tree.get_audit_proof_hex(leaf_index)
        root_hash = self.tree.get_root_hash_hex()

        return {
            "leaf_index": leaf_index,
            "tree_size": self.tree.size,
            "cert_serial": cert_serial,
            "leaf_hash": leaf_hash,
            "proof": proof,
            "root_hash": root_hash
        }

    def get_consistency_proof(self, old_size: int, new_size: Optional[int] = None) -> Dict[str, Any]:
        """Generates a consistency proof between an older tree size and current/new tree size."""
        self._sync_tree_from_db()
        if new_size is None:
            new_size = self.tree.size

        # Compute historical root for old_size
        old_leaves = self.tree._leaves[:old_size]
        temp_tree = MerkleTree(old_leaves)
        old_root = temp_tree.get_root_hash_hex()

        proof = self.tree.get_consistency_proof_hex(old_size, new_size)
        new_leaves = self.tree._leaves[:new_size]
        new_tree = MerkleTree(new_leaves)
        new_root = new_tree.get_root_hash_hex()

        return {
            "old_size": old_size,
            "new_size": new_size,
            "old_root": old_root,
            "new_root": new_root,
            "consistency_proof": proof
        }
