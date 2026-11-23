"""Client certificate verification simulation: Traditional vs CT-Aware clients.

Demonstrates what a client relying on Certificate Transparency and CRL revocation
does differently from a traditional client when presented with a rogue certificate
issued by a compromised Root CA.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID

from storage.database import DatabaseManager
from ca.root_ca import RootCA
from ct.log_server import CTLogServer
from ct.merkle_tree import MerkleTree


@dataclass
class ClientVerificationResult:
    """Outcome of a client's TLS handshake certificate verification."""
    client_type: str
    trusted: bool
    domain: str
    cert_serial: str
    steps: List[str] = field(default_factory=list)
    rejection_reason: Optional[str] = None
    is_mitm_victim: bool = False


class TraditionalClient:
    """Simulates a legacy TLS client (without CT or revocation checking).

    Relies solely on standard X.509 PKI chain validation.
    """

    def __init__(self, root_ca: Optional[RootCA] = None):
        self.ca = root_ca if root_ca else RootCA()
        if self.ca.ca_cert is None:
            self.ca.setup_ca()

    def verify(
        self,
        cert: Union[x509.Certificate, str],
        domain: str
    ) -> ClientVerificationResult:
        """Evaluates a presented certificate using traditional PKI checks only."""
        if isinstance(cert, str):
            cert_obj = x509.load_pem_x509_certificate(cert.encode("utf-8"))
        else:
            cert_obj = cert

        serial_str = str(cert_obj.serial_number)
        steps = []

        # 1. Check validity dates
        now = datetime.now(timezone.utc)
        if now < cert_obj.not_valid_before_utc or now > cert_obj.not_valid_after_utc:
            steps.append("✗ Expiration check FAILED")
            return ClientVerificationResult(
                client_type="Traditional (Non-CT)",
                trusted=False,
                domain=domain,
                cert_serial=serial_str,
                steps=steps,
                rejection_reason="Certificate is expired or not yet valid."
            )
        steps.append("✓ Validity dates check PASSED")

        # 2. Check Domain name / Subject Alternative Name (SAN)
        san_matched = False
        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = [d.lower() for d in san_ext.value.get_values_for_type(x509.DNSName)]
            if domain.lower() in dns_names:
                san_matched = True
        except Exception:
            pass

        if not san_matched:
            steps.append(f"✗ Domain match FAILED: '{domain}' not in SAN")
            return ClientVerificationResult(
                client_type="Traditional (Non-CT)",
                trusted=False,
                domain=domain,
                cert_serial=serial_str,
                steps=steps,
                rejection_reason=f"Hostname mismatch: '{domain}' not present in certificate SAN."
            )
        steps.append(f"✓ Domain match PASSED (SAN contains '{domain}')")

        # 3. Check cryptographic signature against trusted Root CA
        try:
            self.ca.ca_cert.public_key().verify(
                cert_obj.signature,
                cert_obj.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_obj.signature_hash_algorithm
            )
            steps.append("✓ CA Signature check PASSED (Signed by trusted Root CA)")
        except Exception:
            steps.append("✗ CA Signature check FAILED")
            return ClientVerificationResult(
                client_type="Traditional (Non-CT)",
                trusted=False,
                domain=domain,
                cert_serial=serial_str,
                steps=steps,
                rejection_reason="Invalid signature or untrusted CA."
            )

        # Result: The traditional client completely trusts the certificate!
        # If this was a rogue cert, the client is now a victim of interception!
        steps.append("⚠ WARNING: Traditional client has NO CT auditing or revocation check.")
        steps.append("➔ CONNECTION ESTABLISHED: Certificate ACCEPTED.")
        return ClientVerificationResult(
            client_type="Traditional (Non-CT)",
            trusted=True,
            domain=domain,
            cert_serial=serial_str,
            steps=steps,
            rejection_reason=None,
            is_mitm_victim=True  # Vulnerable to rogue CA mis-issuance
        )


class CTAwareClient:
    """Simulates a modern CT-enforcing and revocation-checking TLS client.

    Verifies:
    1. Standard PKI chain to Root CA.
    2. Merkle Tree Inclusion Proof in the append-only CT Log.
    3. Certificate Revocation List (CRL) and Monitor alerts.
    """

    def __init__(
        self,
        root_ca: Optional[RootCA] = None,
        ct_log: Optional[CTLogServer] = None,
        db_manager: Optional[DatabaseManager] = None
    ):
        self.db = db_manager if db_manager else DatabaseManager()
        self.ca = root_ca if root_ca else RootCA(db_manager=self.db)
        self.ct_log = ct_log if ct_log else CTLogServer(db_manager=self.db)
        if self.ca.ca_cert is None:
            self.ca.setup_ca()

    def verify(
        self,
        cert: Union[x509.Certificate, str],
        domain: str,
        require_ct: bool = True,
        check_revocation: bool = True,
        check_monitor_alerts: bool = True
    ) -> ClientVerificationResult:
        """Evaluates a presented certificate using CT proofs and revocation checks."""
        if isinstance(cert, str):
            cert_obj = x509.load_pem_x509_certificate(cert.encode("utf-8"))
        else:
            cert_obj = cert

        serial_str = str(cert_obj.serial_number)
        steps = []

        # 1. Standard PKI chain & validity
        now = datetime.now(timezone.utc)
        if now < cert_obj.not_valid_before_utc or now > cert_obj.not_valid_after_utc:
            steps.append("✗ Expiration check FAILED")
            return ClientVerificationResult(
                client_type="CT-Aware",
                trusted=False,
                domain=domain,
                cert_serial=serial_str,
                steps=steps,
                rejection_reason="Certificate is expired or not yet valid."
            )

        san_matched = False
        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = [d.lower() for d in san_ext.value.get_values_for_type(x509.DNSName)]
            if domain.lower() in dns_names:
                san_matched = True
        except Exception:
            pass

        if not san_matched:
            steps.append(f"✗ Domain match FAILED: '{domain}' not in SAN")
            return ClientVerificationResult(
                client_type="CT-Aware",
                trusted=False,
                domain=domain,
                cert_serial=serial_str,
                steps=steps,
                rejection_reason=f"Hostname mismatch: '{domain}' not present in certificate SAN."
            )

        try:
            self.ca.ca_cert.public_key().verify(
                cert_obj.signature,
                cert_obj.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_obj.signature_hash_algorithm
            )
            steps.append("✓ Standard PKI chain check PASSED (Signed by Root CA)")
        except Exception:
            steps.append("✗ CA Signature check FAILED")
            return ClientVerificationResult(
                client_type="CT-Aware",
                trusted=False,
                domain=domain,
                cert_serial=serial_str,
                steps=steps,
                rejection_reason="Invalid signature or untrusted CA."
            )

        # 2. Certificate Transparency Log Verification
        if require_ct:
            proof_info = self.ct_log.get_inclusion_proof_by_serial(serial_str)
            if not proof_info:
                steps.append("✗ CT ENFORCEMENT FAILED: Certificate is NOT present in the CT log!")
                return ClientVerificationResult(
                    client_type="CT-Aware",
                    trusted=False,
                    domain=domain,
                    cert_serial=serial_str,
                    steps=steps,
                    rejection_reason="Certificate rejected: Missing Certificate Transparency log entry."
                )

            # Cryptographically verify Merkle inclusion proof
            inclusion_ok = MerkleTree.verify_audit_proof(
                leaf_hash=proof_info["leaf_hash"],
                leaf_index=proof_info["leaf_index"],
                tree_size=proof_info["tree_size"],
                proof=proof_info["proof"],
                expected_root=proof_info["root_hash"]
            )
            if not inclusion_ok:
                steps.append("✗ CT AUDIT PROOF FAILED: Merkle proof does not calculate to trusted root!")
                return ClientVerificationResult(
                    client_type="CT-Aware",
                    trusted=False,
                    domain=domain,
                    cert_serial=serial_str,
                    steps=steps,
                    rejection_reason="CT Merkle inclusion proof invalid: Root mismatch."
                )
            steps.append(f"✓ CT Log Inclusion PASSED (Verified via Merkle path of length {len(proof_info['proof'])})")

        # 3. Revocation & CRL Checking
        if check_revocation:
            if self.db.is_certificate_revoked(serial_str):
                steps.append("🚨 REVOCATION CHECK FAILED: Certificate is on the Revocation List (CRL)!")
                return ClientVerificationResult(
                    client_type="CT-Aware",
                    trusted=False,
                    domain=domain,
                    cert_serial=serial_str,
                    steps=steps,
                    rejection_reason="Certificate rejected: Serial number is listed on Certificate Revocation List (CRL)."
                )
            steps.append("✓ Revocation check PASSED (Certificate is NOT revoked)")

        # 4. Monitor Rogue Alert Checking
        if check_monitor_alerts:
            if self.db.is_serial_flagged(serial_str):
                steps.append("🚨 MONITOR ALERT CHECK FAILED: Flagged as Rogue Certificate!")
                return ClientVerificationResult(
                    client_type="CT-Aware",
                    trusted=False,
                    domain=domain,
                    cert_serial=serial_str,
                    steps=steps,
                    rejection_reason="Certificate rejected: Public key flagged as unauthorized by CT Monitor."
                )
            steps.append("✓ Monitor alert check PASSED (No rogue alerts for this certificate)")

        steps.append("➔ CONNECTION ESTABLISHED: Certificate fully verified and TRUSTED.")
        return ClientVerificationResult(
            client_type="CT-Aware",
            trusted=True,
            domain=domain,
            cert_serial=serial_str,
            steps=steps,
            rejection_reason=None,
            is_mitm_victim=False
        )
