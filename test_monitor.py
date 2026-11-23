"""Test suite for CT Monitor and Client Verification."""

import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from storage.database import DatabaseManager
from ca.root_ca import RootCA
from ct.log_server import CTLogServer
from monitor.auditor import CTMonitor
from client.verifier import TraditionalClient, CTAwareClient


def test_monitor_and_client_verification():
    print("=" * 68)
    print("  TEST: CT MONITOR & CLIENT VERIFICATION")
    print("=" * 68)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_path = str(tmp_path / "test_monitor.db")
        certs_dir = str(tmp_path / "certs")

        db = DatabaseManager(db_path=db_path)
        ca = RootCA(certs_dir=certs_dir, db_manager=db)
        ca.setup_ca()

        # 1. Register Bob for bob.test
        bob_priv, bob_pub = RootCA.generate_key_pair()
        bob_pub_pem = RootCA.export_public_key_pem(bob_pub)
        db.register_authorized_domain("bob.test", "Bob", bob_pub_pem)

        # 2. Issue Legitimate Certificate
        legit_cert, legit_pem, _ = ca.issue_certificate("bob.test", bob_pub, is_rogue=False)
        print(f"  ✓ Legitimate cert issued: serial={legit_cert.serial_number}")

        # 3. Issue Rogue Certificate with Attacker Key
        att_priv, att_pub = RootCA.generate_key_pair()
        rogue_cert, rogue_pem, _ = ca.issue_certificate("bob.test", att_pub, is_rogue=True)
        print(f"  ✓ Rogue cert issued: serial={rogue_cert.serial_number}")

        # 4. Traditional Client Check
        trad_client = TraditionalClient(root_ca=ca)
        trad_legit = trad_client.verify(legit_pem, "bob.test")
        trad_rogue = trad_client.verify(rogue_pem, "bob.test")

        assert trad_legit.trusted is True, "Traditional client rejected legitimate cert"
        assert trad_rogue.trusted is True, "Traditional client unexpectedly rejected rogue cert"
        print("  ✓ Traditional client: Blindly accepted both legitimate AND rogue certificates (vulnerable)")

        # 5. Monitor Audit
        monitor = CTMonitor(db_manager=db, root_ca=ca)
        results = monitor.audit_log(auto_revoke=True)
        assert len(results) == 2, f"Expected 2 audited certs, got {len(results)}"

        legit_res = next(r for r in results if r.cert_serial == str(legit_cert.serial_number))
        rogue_res = next(r for r in results if r.cert_serial == str(rogue_cert.serial_number))

        assert legit_res.status == "LEGITIMATE"
        assert legit_res.inclusion_verified is True
        print("  ✓ Monitor: Legitimate cert confirmed (key matched authorized registry)")

        assert rogue_res.status == "ROGUE_DETECTED"
        assert rogue_res.inclusion_verified is True
        assert db.is_certificate_revoked(str(rogue_cert.serial_number))
        print("  ✓ Monitor: Rogue cert detected (key mismatch), alert recorded, cert auto-revoked")

        # 6. CT-Aware Client Check AFTER Monitor
        ct_client = CTAwareClient(root_ca=ca, db_manager=db)
        ct_legit = ct_client.verify(legit_pem, "bob.test")
        ct_rogue = ct_client.verify(rogue_pem, "bob.test")

        assert ct_legit.trusted is True, f"CT client rejected legitimate cert: {ct_legit.rejection_reason}"
        assert ct_rogue.trusted is False, "CT client accepted rogue cert after revocation"
        assert "Revocation List" in ct_rogue.rejection_reason
        print(f"  ✓ CT-Aware client: Trusted legitimate cert, REJECTED rogue cert ({ct_rogue.rejection_reason})")

    print("\n" + "=" * 68)
    print("  ALL MONITOR & CLIENT TESTS PASSED SUCCESSFULLY! ")
    print("=" * 68)


if __name__ == "__main__":
    test_monitor_and_client_verification()
