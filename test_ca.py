"""Verification test for the Toy Root CA and database storage."""

import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from storage.database import DatabaseManager
from ca.root_ca import RootCA
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


def test_ca_lifecycle():
    print("=" * 60)
    print("  TOY PKI & ROOT CA VERIFICATION TEST")
    print("=" * 60)

    # 1. Use temporary directory for testing isolation
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_path = str(tmp_path / "test_pki.db")
        certs_dir = str(tmp_path / "certs")

        print("\n[Step 1] Initializing Database & Root CA...")
        db = DatabaseManager(db_path=db_path)
        ca = RootCA(certs_dir=certs_dir, db_manager=db)
        root_cert = ca.setup_ca(
            common_name="Toy Root CA",
            org_name="University Security Lab",
            country="US"
        )
        print(f"  ✓ Root CA Subject: {root_cert.subject.rfc4514_string()}")
        print(f"  ✓ Root CA Serial: {root_cert.serial_number}")
        assert (Path(certs_dir) / "ca.key").exists(), "CA key file missing"
        assert (Path(certs_dir) / "ca.crt").exists(), "CA cert file missing"

        # 2. Register Authorized Domain Owner (Alice)
        print("\n[Step 2] Registering Authorized Domain Owner (Alice for alice.domain)...")
        alice_priv, alice_pub = RootCA.generate_key_pair()
        alice_pub_pem = RootCA.export_public_key_pem(alice_pub)

        db.register_authorized_domain(
            domain="alice.domain",
            owner_name="Alice (True Owner)",
            public_key_pem=alice_pub_pem
        )
        auth_record = db.get_authorized_domain("alice.domain")
        assert auth_record is not None, "Failed to retrieve authorized domain"
        print(f"  ✓ Domain: {auth_record['domain']}, Owner: {auth_record['owner_name']}")

        # 3. Issue Legitimate Certificate
        print("\n[Step 3] Issuing Legitimate Certificate for alice.domain...")
        legit_cert, legit_pem, legit_der = ca.issue_certificate(
            domain="alice.domain",
            public_key=alice_pub,
            validity_days=365,
            is_rogue=False
        )
        print(f"  ✓ Legit Cert Serial: {legit_cert.serial_number}")
        print(f"  ✓ Legit Cert Subject: {legit_cert.subject.rfc4514_string()}")
        
        # Verify SAN extension
        san_ext = legit_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "alice.domain" in san_names, "SAN does not match domain"
        print(f"  ✓ SAN extension verified: {san_names}")

        # 4. Issue Rogue Certificate (Compromised CA Scenario)
        print("\n[Step 4] Simulating Compromised CA: Issuing Rogue Cert for alice.domain...")
        attacker_priv, attacker_pub = RootCA.generate_key_pair()
        attacker_pub_pem = RootCA.export_public_key_pem(attacker_pub)

        rogue_cert, rogue_pem, rogue_der = ca.issue_certificate(
            domain="alice.domain",
            public_key=attacker_pub,
            validity_days=90,
            is_rogue=True
        )
        print(f"  ✓ Rogue Cert Serial: {rogue_cert.serial_number}")
        print(f"  ✓ Rogue Cert Subject: {rogue_cert.subject.rfc4514_string()}")
        assert rogue_cert.serial_number != legit_cert.serial_number

        # 5. Verify Database Records
        print("\n[Step 5] Checking Database Records...")
        all_certs = db.get_all_certificates()
        assert len(all_certs) == 2, f"Expected 2 certs, found {len(all_certs)}"
        print(f"  ✓ Total certificates in database: {len(all_certs)}")
        for c in all_certs:
            status = "ROGUE" if c["is_rogue"] else "LEGITIMATE"
            print(f"    - Serial: {c['serial_number'][:16]}... Domain: {c['domain']} [{status}]")

        # 6. Revoke Rogue Certificate & Generate CRL
        print("\n[Step 6] Revoking Rogue Certificate & Generating CRL...")
        db.revoke_certificate(
            serial_number=str(rogue_cert.serial_number),
            domain="alice.domain",
            reason="Compromised CA unauthorized issuance"
        )
        assert db.is_certificate_revoked(str(rogue_cert.serial_number)), "Rogue cert not marked revoked"
        assert not db.is_certificate_revoked(str(legit_cert.serial_number)), "Legit cert incorrectly revoked"

        crl, crl_pem = ca.generate_crl()
        print(f"  ✓ CRL generated with {len(crl)} revoked entries")
        revoked_serial = crl.get_revoked_certificate_by_serial_number(rogue_cert.serial_number)
        assert revoked_serial is not None, "Revoked cert not found in CRL object"
        print(f"  ✓ Successfully verified rogue serial {rogue_cert.serial_number} in signed X.509 CRL")

    print("\n" + "=" * 60)
    print("  ALL TOY CA TESTS PASSED SUCCESSFULLY! ")
    print("=" * 60)


if __name__ == "__main__":
    test_ca_lifecycle()
