"""Certificate Transparency Monitor & Rogue Certificate Detection Engine.

Audits CT log entries, verifies Merkle inclusion proofs, validates consistency proofs,
compares certificate public keys against the domain authorization registry,
and automatically triggers certificate revocation upon detecting unauthorized (rogue) issuances.
"""

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from storage.database import DatabaseManager
from ca.root_ca import RootCA
from ct.log_server import CTLogServer
from ct.merkle_tree import MerkleTree


@dataclass
class AuditResult:
    """Represents the outcome of auditing a single certificate entry."""
    entry_index: int
    cert_serial: str
    domain: str
    is_rogue: bool
    status: str  # "LEGITIMATE", "ROGUE_DETECTED", "UNKNOWN_DOMAIN", "TAMPERED_PROOF"
    authorized_owner: Optional[str]
    authorized_fingerprint: Optional[str]
    cert_fingerprint: str
    message: str
    inclusion_verified: bool


class CTMonitor:
    """Continuous or on-demand monitor process for detecting unauthorized certificates."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        ct_log: Optional[CTLogServer] = None,
        root_ca: Optional[RootCA] = None,
        target_domain: Optional[str] = None
    ):
        self.db = db_manager if db_manager else DatabaseManager()
        self.ct_log = ct_log if ct_log else CTLogServer(db_manager=self.db)
        self.ca = root_ca if root_ca else RootCA(db_manager=self.db)
        self.target_domain = target_domain.lower() if target_domain else None

        self.last_audited_size: int = 0
        self.last_verified_root: Optional[str] = None

    @staticmethod
    def compute_key_fingerprint(public_key_pem: str) -> str:
        """Computes a human-readable SHA-256 fingerprint for a public key."""
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.strip().encode("utf-8"))
            der = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return hashlib.sha256(der).hexdigest()[:24]
        except Exception:
            return hashlib.sha256(public_key_pem.strip().encode("utf-8")).hexdigest()[:24]

    def verify_sth_signature(self, sth: Dict[str, Any]) -> bool:
        """Verifies the RSA cryptographic signature on the Signed Tree Head (STH)."""
        try:
            sth_data = f"STH:v1:{sth['tree_size']}:{sth['timestamp']}:{sth['root_hash']}".encode("utf-8")
            sig_bytes = bytes.fromhex(sth["signature"])
            self.ct_log.log_public_key.verify(
                sig_bytes,
                sth_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def audit_log(self, auto_revoke: bool = True) -> List[AuditResult]:
        """Audits the CT log up to the latest STH.

        Steps:
        1. Fetch and cryptographically verify the latest STH from CT log.
        2. Verify consistency proof from last_audited_size to current size.
        3. For each certificate in the log:
           a. Verify Merkle inclusion proof.
           b. Match certificate public key against authorization registry.
           c. If mismatch -> Flag ROGUE, record alert, and auto-revoke in CRL.
        """
        results: List[AuditResult] = []
        sth = self.ct_log.get_signed_tree_head()

        # Step 1: Verify STH signature
        if not self.verify_sth_signature(sth):
            raise ValueError("CRITICAL: Signed Tree Head (STH) has an INVALID signature!")

        current_size = sth["tree_size"]
        current_root = sth["root_hash"]

        if current_size == 0:
            return results

        # Step 2: Verify consistency proof if tree has grown
        if self.last_audited_size > 0 and current_size > self.last_audited_size:
            cons_info = self.ct_log.get_consistency_proof(
                old_size=self.last_audited_size,
                new_size=current_size
            )
            is_consistent = MerkleTree.verify_consistency_proof(
                old_size=cons_info["old_size"],
                new_size=cons_info["new_size"],
                old_root=cons_info["old_root"],
                new_root=cons_info["new_root"],
                proof=cons_info["consistency_proof"]
            )
            if not is_consistent:
                raise ValueError("SECURITY ALERT: Merkle Tree consistency proof failed! Append-only property violated!")

        # Step 3: Fetch entries from database
        entries = self.db.get_ct_entries()

        for e in entries:
            entry_index = e["entry_index"] - 1  # 0-based
            cert_serial = e["cert_serial"]
            domain = e["domain"].lower()

            # Filter by target domain if monitor is configured for a specific domain
            if self.target_domain and domain != self.target_domain:
                continue

            cert_row = self.db.get_certificate(cert_serial)
            if not cert_row:
                continue

            cert_pub_pem = cert_row["public_key_pem"]
            cert_fingerprint = self.compute_key_fingerprint(cert_pub_pem)

            # 3a. Verify Merkle inclusion proof
            proof_info = self.ct_log.get_inclusion_proof_by_serial(cert_serial)
            inclusion_ok = False
            if proof_info:
                inclusion_ok = MerkleTree.verify_audit_proof(
                    leaf_hash=proof_info["leaf_hash"],
                    leaf_index=proof_info["leaf_index"],
                    tree_size=proof_info["tree_size"],
                    proof=proof_info["proof"],
                    expected_root=proof_info["root_hash"]
                )

            if not inclusion_ok:
                res = AuditResult(
                    entry_index=entry_index,
                    cert_serial=cert_serial,
                    domain=domain,
                    is_rogue=True,
                    status="TAMPERED_PROOF",
                    authorized_owner=None,
                    authorized_fingerprint=None,
                    cert_fingerprint=cert_fingerprint,
                    message="Merkle inclusion proof verification FAILED for certificate!",
                    inclusion_verified=False
                )
                results.append(res)
                continue

            # 3b. Check Authorization Registry
            auth_record = self.db.get_authorized_domain(domain)
            if not auth_record:
                res = AuditResult(
                    entry_index=entry_index,
                    cert_serial=cert_serial,
                    domain=domain,
                    is_rogue=False,
                    status="UNKNOWN_DOMAIN",
                    authorized_owner=None,
                    authorized_fingerprint=None,
                    cert_fingerprint=cert_fingerprint,
                    message=f"Domain '{domain}' is not registered in the authorization lookup table.",
                    inclusion_verified=True
                )
                results.append(res)
                continue

            auth_owner = auth_record["owner_name"]
            auth_pub_pem = auth_record["authorized_public_key_pem"]
            auth_fingerprint = self.compute_key_fingerprint(auth_pub_pem)

            # 3c. Key Comparison: Does certificate key match authorized key?
            if cert_pub_pem.strip() == auth_pub_pem.strip():
                res = AuditResult(
                    entry_index=entry_index,
                    cert_serial=cert_serial,
                    domain=domain,
                    is_rogue=False,
                    status="LEGITIMATE",
                    authorized_owner=auth_owner,
                    authorized_fingerprint=auth_fingerprint,
                    cert_fingerprint=cert_fingerprint,
                    message=f"Certificate key matches authorized key for owner '{auth_owner}'.",
                    inclusion_verified=True
                )
                results.append(res)
            else:
                # Key mismatch: ROGUE DETECTED!
                alert_msg = (
                    f"UNAUTHORIZED CERTIFICATE DETECTED for '{domain}'! "
                    f"Public key mismatch. Authorized owner is '{auth_owner}'."
                )

                # Record alert in DB if not already recorded
                if not self.db.is_serial_flagged(cert_serial):
                    self.db.record_monitor_alert(
                        cert_serial=cert_serial,
                        domain=domain,
                        authorized_owner=auth_owner,
                        authorized_key_fingerprint=auth_fingerprint,
                        rogue_key_fingerprint=cert_fingerprint,
                        alert_message=alert_msg
                    )

                # Auto-revoke if enabled
                if auto_revoke and not self.db.is_certificate_revoked(cert_serial):
                    self.db.revoke_certificate(
                        serial_number=cert_serial,
                        domain=domain,
                        reason=f"CT Monitor flagged unauthorized key mismatch for {domain}"
                    )
                    self.ca.generate_crl()

                res = AuditResult(
                    entry_index=entry_index,
                    cert_serial=cert_serial,
                    domain=domain,
                    is_rogue=True,
                    status="ROGUE_DETECTED",
                    authorized_owner=auth_owner,
                    authorized_fingerprint=auth_fingerprint,
                    cert_fingerprint=cert_fingerprint,
                    message=alert_msg,
                    inclusion_verified=True
                )
                results.append(res)

        self.last_audited_size = current_size
        self.last_verified_root = current_root
        return results
