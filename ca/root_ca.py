"""Toy Root Certificate Authority (CA) implementation.

Handles key generation, self-signed Root CA issuance, leaf certificate issuance,
and Certificate Revocation List (CRL) generation using Python's cryptography library.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union, Tuple, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from storage.database import DatabaseManager


class RootCA:
    """Represents the Toy Root Certificate Authority."""

    def __init__(
        self,
        certs_dir: Optional[str] = None,
        db_manager: Optional[DatabaseManager] = None
    ):
        base_dir = Path(__file__).resolve().parent.parent
        self.certs_dir = Path(certs_dir) if certs_dir else (base_dir / "certs")
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        self.db = db_manager if db_manager else DatabaseManager()

        self.key_path = self.certs_dir / "ca.key"
        self.cert_path = self.certs_dir / "ca.crt"

        self.ca_private_key: Optional[rsa.RSAPrivateKey] = None
        self.ca_cert: Optional[x509.Certificate] = None

    # --- Key and Cert Serialization Utilities ---

    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates a new RSA private/public key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()

    @staticmethod
    def export_private_key_pem(
        private_key: rsa.RSAPrivateKey,
        password: Optional[str] = None
    ) -> str:
        """Exports an RSA private key to PEM format."""
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        return pem_bytes.decode("utf-8")

    @staticmethod
    def export_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
        """Exports an RSA public key to SubjectPublicKeyInfo PEM format."""
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode("utf-8")

    @staticmethod
    def load_public_key_from_pem(pem_str: str) -> rsa.RSAPublicKey:
        """Loads an RSA public key from PEM string."""
        return serialization.load_pem_public_key(pem_str.encode("utf-8"))

    @staticmethod
    def load_private_key_from_pem(
        pem_str: str,
        password: Optional[str] = None
    ) -> rsa.RSAPrivateKey:
        """Loads an RSA private key from PEM string."""
        return serialization.load_pem_private_key(
            pem_str.encode("utf-8"),
            password=password.encode() if password else None
        )

    # --- Root CA Initialization ---

    def setup_ca(
        self,
        common_name: str = "Toy Root CA",
        org_name: str = "Toy PKI Group Project",
        country: str = "US",
        validity_days: int = 3650,
        force: bool = False
    ) -> x509.Certificate:
        """Initializes the Root CA.

        Loads existing CA key & cert if present; otherwise creates and saves a new self-signed Root CA.
        """
        if not force and self.key_path.exists() and self.cert_path.exists():
            # Load existing
            key_bytes = self.key_path.read_bytes()
            cert_bytes = self.cert_path.read_bytes()
            self.ca_private_key = serialization.load_pem_private_key(key_bytes, password=None)
            self.ca_cert = x509.load_pem_x509_certificate(cert_bytes)
            return self.ca_cert

        # Generate new Root CA key pair
        self.ca_private_key, public_key = self.generate_key_pair(key_size=2048)

        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Self-signed Root CA Certificate
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                critical=False
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )

        # Write to disk
        self.key_path.write_text(self.export_private_key_pem(self.ca_private_key), encoding="utf-8")
        self.cert_path.write_text(
            self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            encoding="utf-8"
        )

        return self.ca_cert

    # --- Leaf Certificate Issuance ---

    def issue_certificate(
        self,
        domain: str,
        public_key: Union[rsa.RSAPublicKey, str],
        validity_days: int = 365,
        is_rogue: bool = False,
        auto_save_db: bool = True,
        log_to_ct: bool = True
    ) -> Tuple[x509.Certificate, str, bytes]:
        """Issues an X.509 leaf certificate for a domain signed by this Root CA.

        Args:
            domain: The target domain (e.g. 'alice.domain').
            public_key: Either an RSAPublicKey object or PEM-formatted string.
            validity_days: Duration of certificate validity.
            is_rogue: Tag indicating whether this was an unauthorized/rogue issuance.
            auto_save_db: Whether to record the issued certificate in the SQLite database.
            log_to_ct: Whether to submit the certificate to the Certificate Transparency log.

        Returns:
            Tuple of (x509.Certificate, cert_pem_str, cert_der_bytes)
        """
        if self.ca_private_key is None or self.ca_cert is None:
            self.setup_ca()

        if isinstance(public_key, str):
            leaf_public_key = self.load_public_key_from_pem(public_key)
            leaf_public_key_pem = public_key.strip()
        else:
            leaf_public_key = public_key
            leaf_public_key_pem = self.export_public_key_pem(leaf_public_key).strip()

        now = datetime.now(timezone.utc)
        not_before = now - timedelta(minutes=5)
        not_after = now + timedelta(days=validity_days)
        serial_number = x509.random_serial_number()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain.lower()),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(leaf_public_key)
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain.lower())]),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_private_key.public_key()),
                critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_public_key),
                critical=False
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        if auto_save_db:
            issuer_cn = self.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            self.db.save_certificate(
                serial_number=str(serial_number),
                domain=domain.lower(),
                issuer=issuer_cn,
                public_key_pem=leaf_public_key_pem,
                cert_pem=cert_pem,
                cert_der=cert_der,
                not_before=not_before,
                not_after=not_after,
                is_rogue=is_rogue
            )

        if log_to_ct:
            from ct.log_server import CTLogServer
            ct_log = CTLogServer(certs_dir=str(self.certs_dir), db_manager=self.db)
            ct_log.log_certificate(cert_serial=str(serial_number), cert_der=cert_der)

        return cert, cert_pem, cert_der

    # --- Revocation & CRL Generation ---

    def generate_crl(self, validity_days: int = 7) -> Tuple[x509.CertificateRevocationList, str]:
        """Generates an X.509 Certificate Revocation List (CRL) signed by the Root CA.

        Pulls all revoked certificates from the database and signs a fresh CRL.
        """
        if self.ca_private_key is None or self.ca_cert is None:
            self.setup_ca()

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=validity_days))
        )

        revocations = self.db.get_revoked_certificates()
        for rev in revocations:
            rev_time = datetime.fromisoformat(rev["revoked_at"])
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(rev["serial_number"]))
                .revocation_date(rev_time)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256())
        crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # Save CRL to certs directory
        crl_path = self.certs_dir / "ca.crl"
        crl_path.write_text(crl_pem, encoding="utf-8")

        return crl, crl_pem
