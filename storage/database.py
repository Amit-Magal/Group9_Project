"""Database storage layer for Toy PKI and Certificate Transparency."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Generator


class DatabaseManager:
    """Manages SQLite storage for certificates, authorization registry, CT log, and revocations."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Default to a data directory in the project root
            base_dir = Path(__file__).resolve().parent.parent
            data_dir = base_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(data_dir / "pki_ct.db")
        else:
            self.db_path = db_path
        
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Returns a database connection context that automatically closes when finished."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initializes tables for authorized domains, certificates, CT log, and revocations."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Authorization Registry: Legitimate domain owners and their authorized public keys
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS authorized_domains (
                    domain TEXT PRIMARY KEY,
                    owner_name TEXT NOT NULL,
                    authorized_public_key_pem TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                )
            """)

            # 2. Issued Certificates: All certificates issued by the CA (legitimate or rogue)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    serial_number TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    cert_der BLOB NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    is_rogue INTEGER NOT NULL DEFAULT 0,
                    issued_at TEXT NOT NULL
                )
            """)

            # 3. Certificate Transparency Log: Append-only log of leaf certificates
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ct_log_entries (
                    entry_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    cert_serial TEXT NOT NULL,
                    leaf_hash TEXT NOT NULL,
                    logged_at TEXT NOT NULL,
                    FOREIGN KEY (cert_serial) REFERENCES certificates(serial_number)
                )
            """)

            # 4. Revocation List: Revoked certificates
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS revocations (
                    serial_number TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
            """)

            # 5. Monitor Alerts: Rogue certificate detections
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitor_alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cert_serial TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    authorized_owner TEXT,
                    authorized_key_fingerprint TEXT,
                    rogue_key_fingerprint TEXT,
                    alert_message TEXT NOT NULL
                )
            """)
            conn.commit()

    # --- Authorization Registry Operations ---

    def register_authorized_domain(self, domain: str, owner_name: str, public_key_pem: str) -> None:
        """Registers or updates a domain's legitimate owner and authorized public key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT OR REPLACE INTO authorized_domains 
                (domain, owner_name, authorized_public_key_pem, registered_at)
                VALUES (?, ?, ?, ?)
            """, (domain.lower(), owner_name, public_key_pem.strip(), now))
            conn.commit()

    def get_authorized_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Retrieves authorization details for a given domain."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM authorized_domains WHERE domain = ?", (domain.lower(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_authorized_domains(self) -> List[Dict[str, Any]]:
        """Returns all authorized domains."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM authorized_domains ORDER BY domain ASC")
            return [dict(r) for r in cursor.fetchall()]

    # --- Certificate Operations ---

    def save_certificate(
        self,
        serial_number: str,
        domain: str,
        issuer: str,
        public_key_pem: str,
        cert_pem: str,
        cert_der: bytes,
        not_before: datetime,
        not_after: datetime,
        is_rogue: bool = False
    ) -> None:
        """Saves an issued certificate into the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO certificates (
                    serial_number, domain, issuer, public_key_pem, cert_pem, cert_der,
                    not_before, not_after, is_rogue, issued_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                serial_number,
                domain.lower(),
                issuer,
                public_key_pem.strip(),
                cert_pem.strip(),
                cert_der,
                not_before.isoformat(),
                not_after.isoformat(),
                1 if is_rogue else 0,
                now
            ))
            conn.commit()

    def get_certificate(self, serial_number: str) -> Optional[Dict[str, Any]]:
        """Retrieves a certificate by its serial number."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM certificates WHERE serial_number = ?", (serial_number,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_certificates(self) -> List[Dict[str, Any]]:
        """Retrieves all issued certificates."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM certificates ORDER BY issued_at ASC")
            return [dict(r) for r in cursor.fetchall()]

    # --- CT Log Operations ---

    def append_ct_entry(self, cert_serial: str, leaf_hash: str) -> int:
        """Appends a new certificate hash to the CT log and returns entry_index."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO ct_log_entries (cert_serial, leaf_hash, logged_at)
                VALUES (?, ?, ?)
            """, (cert_serial, leaf_hash, now))
            conn.commit()
            return cursor.lastrowid

    def get_ct_entries(self) -> List[Dict[str, Any]]:
        """Returns all CT log entries in append order."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT e.entry_index, e.cert_serial, e.leaf_hash, e.logged_at,
                       c.domain, c.public_key_pem, c.is_rogue
                FROM ct_log_entries e
                JOIN certificates c ON e.cert_serial = c.serial_number
                ORDER BY e.entry_index ASC
            """)
            return [dict(r) for r in cursor.fetchall()]

    # --- Revocation Operations ---

    def revoke_certificate(self, serial_number: str, domain: str, reason: str = "Key compromise / Unauthorized issuance") -> None:
        """Marks a certificate as revoked."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT OR REPLACE INTO revocations (serial_number, domain, revoked_at, reason)
                VALUES (?, ?, ?, ?)
            """, (serial_number, domain.lower(), now, reason))
            conn.commit()

    def is_certificate_revoked(self, serial_number: str) -> bool:
        """Checks if a certificate serial number is revoked."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM revocations WHERE serial_number = ?", (serial_number,))
            return cursor.fetchone() is not None

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        """Returns all revoked certificates."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM revocations ORDER BY revoked_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    # --- Monitor Alerts Operations ---

    def record_monitor_alert(
        self,
        cert_serial: str,
        domain: str,
        authorized_owner: Optional[str],
        authorized_key_fingerprint: Optional[str],
        rogue_key_fingerprint: str,
        alert_message: str
    ) -> int:
        """Records a detected rogue certificate alert."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO monitor_alerts (
                    cert_serial, domain, detected_at, authorized_owner,
                    authorized_key_fingerprint, rogue_key_fingerprint, alert_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                cert_serial,
                domain.lower(),
                now,
                authorized_owner,
                authorized_key_fingerprint,
                rogue_key_fingerprint,
                alert_message
            ))
            conn.commit()
            return cursor.lastrowid

    def get_monitor_alerts(self) -> List[Dict[str, Any]]:
        """Returns all monitor alerts in reverse chronological order."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM monitor_alerts ORDER BY alert_id DESC")
            return [dict(r) for r in cursor.fetchall()]

    def is_serial_flagged(self, cert_serial: str) -> bool:
        """Checks if a serial number has already been flagged as rogue."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM monitor_alerts WHERE cert_serial = ?", (cert_serial,))
            return cursor.fetchone() is not None
