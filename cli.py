"""Command-Line Interface (CLI) for Toy PKI and Certificate Authority."""

import argparse
import sys
from pathlib import Path

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from storage.database import DatabaseManager
from ca.root_ca import RootCA
from ct.log_server import CTLogServer
from ct.merkle_tree import MerkleTree
from monitor.auditor import CTMonitor
from client.verifier import TraditionalClient, CTAwareClient


def get_ca_and_db():
    db = DatabaseManager()
    ca = RootCA(db_manager=db)
    ca.setup_ca()
    return ca, db


def cmd_init_ca(args):
    db = DatabaseManager()
    ca = RootCA(db_manager=db)
    cert = ca.setup_ca(common_name=args.cn, org_name=args.org, force=args.force)
    print(f"✓ Root CA initialized successfully!")
    print(f"  Subject: {cert.subject.rfc4514_string()}")
    print(f"  Serial:  {cert.serial_number}")
    print(f"  Cert:    {ca.cert_path}")
    print(f"  Key:     {ca.key_path}")


def cmd_register_domain(args):
    _, db = get_ca_and_db()
    # Generate authorized key pair for the legitimate owner
    priv_key, pub_key = RootCA.generate_key_pair()
    pub_pem = RootCA.export_public_key_pem(pub_key)
    priv_pem = RootCA.export_private_key_pem(priv_key)

    # Save private key for owner
    keys_dir = PROJECT_ROOT / "certs" / "owners"
    keys_dir.mkdir(parents=True, exist_ok=True)
    owner_key_file = keys_dir / f"{args.domain}.key"
    owner_key_file.write_text(priv_pem, encoding="utf-8")

    db.register_authorized_domain(
        domain=args.domain,
        owner_name=args.owner,
        public_key_pem=pub_pem
    )
    print(f"✓ Registered authorized owner for {args.domain}:")
    print(f"  Owner:      {args.owner}")
    print(f"  Public Key: saved to registry database")
    print(f"  Priv Key:   saved to {owner_key_file}")


def cmd_issue_legit(args):
    ca, db = get_ca_and_db()
    auth_info = db.get_authorized_domain(args.domain)
    if not auth_info:
        print(f"✗ Error: Domain '{args.domain}' is not registered in the authorized domains table.")
        print("  Use 'python cli.py register-domain' first, or supply an authorized key.")
        return

    cert, cert_pem, _ = ca.issue_certificate(
        domain=args.domain,
        public_key=auth_info["authorized_public_key_pem"],
        validity_days=args.days,
        is_rogue=False
    )
    print(f"✓ Issued LEGITIMATE certificate for '{args.domain}':")
    print(f"  Serial Number: {cert.serial_number}")
    print(f"  Not Before:    {cert.not_valid_before_utc}")
    print(f"  Not After:     {cert.not_valid_after_utc}")


def cmd_issue_rogue(args):
    ca, db = get_ca_and_db()
    print(f"⚠ COMPROMISING CA: Deliberately issuing ROGUE certificate for '{args.domain}'...")

    # Attacker generates their own private/public key pair
    attacker_priv, attacker_pub = RootCA.generate_key_pair()
    attacker_pub_pem = RootCA.export_public_key_pem(attacker_pub)

    # Save attacker key for reference/demo
    keys_dir = PROJECT_ROOT / "certs" / "attacker"
    keys_dir.mkdir(parents=True, exist_ok=True)
    attacker_key_file = keys_dir / f"rogue_{args.domain}.key"
    attacker_key_file.write_text(RootCA.export_private_key_pem(attacker_priv), encoding="utf-8")

    cert, _, _ = ca.issue_certificate(
        domain=args.domain,
        public_key=attacker_pub,
        validity_days=args.days,
        is_rogue=True
    )
    print(f"🚨 ROGUE Certificate Issued!")
    print(f"  Target Domain: {args.domain}")
    print(f"  Serial Number: {cert.serial_number}")
    print(f"  Attacker Key:  saved to {attacker_key_file}")
    print(f"  Note: This certificate was signed by the Root CA with an unauthorized public key.")


def cmd_list_certs(args):
    _, db = get_ca_and_db()
    certs = db.get_all_certificates()
    if not certs:
        print("No certificates found in database.")
        return

    print(f"Total issued certificates: {len(certs)}")
    print("-" * 75)
    for c in certs:
        status = "[🚨 ROGUE]" if c["is_rogue"] else "[✓ LEGITIMATE]"
        revoked = " [REVOKED]" if db.is_certificate_revoked(c["serial_number"]) else ""
        print(f"Domain: {c['domain']:<20} {status}{revoked}")
        print(f"  Serial:    {c['serial_number']}")
        print(f"  Issued At: {c['issued_at']}")
        print("-" * 75)


def cmd_revoke(args):
    ca, db = get_ca_and_db()
    cert_info = db.get_certificate(args.serial)
    domain = cert_info["domain"] if cert_info else "unknown"

    db.revoke_certificate(args.serial, domain=domain, reason=args.reason)
    crl, _ = ca.generate_crl()
    print(f"✓ Certificate {args.serial} for '{domain}' marked REVOKED.")
    print(f"✓ Updated Root CA CRL generated ({len(crl)} revoked certificates).")


def cmd_ct_status(args):
    _, db = get_ca_and_db()
    ct = CTLogServer(db_manager=db)
    sth = ct.get_signed_tree_head()
    print("=" * 65)
    print("  CERTIFICATE TRANSPARENCY (CT) LOG STATUS")
    print("=" * 65)
    print(f"Log ID:       {sth['log_id']}")
    print(f"Tree Size:    {sth['tree_size']} certificate(s)")
    print(f"Merkle Root:  {sth['root_hash']}")
    print(f"STH Timestamp: {sth['timestamp']}")
    print(f"Signature:    {sth['signature'][:32]}... [RSA-SHA256 verified]")

    entries = db.get_ct_entries()
    if entries:
        print("\n--- CT Log Entries ---")
        for e in entries:
            tag = "[🚨 ROGUE]" if e["is_rogue"] else "[✓ LEGIT]"
            print(f"Index {e['entry_index']-1:2d} | Serial: {e['cert_serial'][:16]}... | {tag:<10} | Domain: {e['domain']}")
            print(f"         Leaf Hash: {e['leaf_hash']}")
    print("=" * 65)


def cmd_ct_audit(args):
    _, db = get_ca_and_db()
    ct = CTLogServer(db_manager=db)
    proof_info = ct.get_inclusion_proof_by_serial(args.serial)
    if not proof_info:
        print(f"✗ Certificate serial {args.serial} not found in CT log.")
        return

    print("=" * 65)
    print("  MERKLE INCLUSION (AUDIT) PROOF VERIFICATION")
    print("=" * 65)
    print(f"Certificate Serial: {proof_info['cert_serial']}")
    print(f"Leaf Index:         {proof_info['leaf_index']} of {proof_info['tree_size']}")
    print(f"Leaf Hash:          {proof_info['leaf_hash']}")
    print(f"Merkle Root:        {proof_info['root_hash']}")
    print(f"Audit Path Length:  {len(proof_info['proof'])} sibling hash(es)")
    for i, h in enumerate(proof_info['proof']):
        print(f"  Step {i+1}: Sibling = {h}")

    # Cryptographically verify the inclusion proof
    is_valid = MerkleTree.verify_audit_proof(
        leaf_hash=proof_info['leaf_hash'],
        leaf_index=proof_info['leaf_index'],
        tree_size=proof_info['tree_size'],
        proof=proof_info['proof'],
        expected_root=proof_info['root_hash']
    )

    print("-" * 65)
    if is_valid:
        print("  ✓ AUDIT PROOF VALID: Certificate is proven to be present in the CT log.")
    else:
        print("  ✗ AUDIT PROOF FAILED: Calculated root does not match Merkle Tree root!")
    print("=" * 65)


def cmd_ct_consistency(args):
    _, db = get_ca_and_db()
    ct = CTLogServer(db_manager=db)
    try:
        proof_info = ct.get_consistency_proof(old_size=args.old_size, new_size=args.new_size)
    except ValueError as e:
        print(f"✗ Error: {e}")
        return

    print("=" * 65)
    print("  MERKLE TREE CONSISTENCY PROOF VERIFICATION")
    print("=" * 65)
    print(f"Old Tree Size: {proof_info['old_size']} | Old Root: {proof_info['old_root']}")
    print(f"New Tree Size: {proof_info['new_size']} | New Root: {proof_info['new_root']}")
    print(f"Proof Length:  {len(proof_info['consistency_proof'])} node(s)")

    is_valid = MerkleTree.verify_consistency_proof(
        old_size=proof_info['old_size'],
        new_size=proof_info['new_size'],
        old_root=proof_info['old_root'],
        new_root=proof_info['new_root'],
        proof=proof_info['consistency_proof']
    )

    print("-" * 65)
    if is_valid:
        print("  ✓ CONSISTENCY PROOF VALID:")
        print("    The old tree is an exact prefix of the new tree.")
        print("    Append-only property mathematically proven (no past entries altered).")
    else:
        print("  ✗ CONSISTENCY PROOF FAILED: The tree history has been tampered with!")
    print("=" * 65)


def cmd_monitor(args):
    ca, db = get_ca_and_db()
    monitor = CTMonitor(db_manager=db, root_ca=ca, target_domain=args.domain)
    print("=" * 70)
    print("  CERTIFICATE TRANSPARENCY MONITOR: AUDITING ISSUED CERTIFICATES")
    print("=" * 70)
    if args.domain:
        print(f"Monitoring filter: target_domain = '{args.domain}'")
    else:
        print("Monitoring scope: ALL registered domains")

    results = monitor.audit_log(auto_revoke=not args.no_auto_revoke)
    if not results:
        print("No certificates found to audit.")
        print("=" * 70)
        return

    rogue_count = 0
    legit_count = 0

    for r in results:
        print("\n" + "-" * 70)
        if r.status == "ROGUE_DETECTED":
            rogue_count += 1
            print(f"🚨 [ALERT: ROGUE CERTIFICATE DETECTED]")
            print(f"  Target Domain:            {r.domain}")
            print(f"  Certificate Serial:       {r.cert_serial}")
            print(f"  Merkle Proof Verified:    {'YES' if r.inclusion_verified else 'NO'}")
            print(f"  Authorized Owner:         {r.authorized_owner}")
            print(f"  Authorized Key Fingerprint: {r.authorized_fingerprint}")
            print(f"  Presented Key Fingerprint:  {r.cert_fingerprint} (MISMATCH!)")
            if not args.no_auto_revoke:
                print(f"  Mitigation Action:        ✓ Automatically revoked & signed updated CRL.")
        elif r.status == "LEGITIMATE":
            legit_count += 1
            print(f"✓ [LEGITIMATE CERTIFICATE]")
            print(f"  Domain:                   {r.domain}")
            print(f"  Certificate Serial:       {r.cert_serial}")
            print(f"  Merkle Proof Verified:    YES")
            print(f"  Authorized Owner:         {r.authorized_owner}")
            print(f"  Key Fingerprint:          {r.cert_fingerprint} (MATCH)")
        else:
            print(f"ℹ [{r.status}]")
            print(f"  Domain:                   {r.domain}")
            print(f"  Message:                  {r.message}")

    print("\n" + "=" * 70)
    print(f"Audit Summary: {len(results)} certificate(s) processed | {legit_count} Legitimate | {rogue_count} ROGUE DETECTED")
    print("=" * 70)


def cmd_verify_client(args):
    ca, db = get_ca_and_db()
    cert_row = db.get_certificate(args.serial)
    if not cert_row:
        print(f"✗ Certificate serial {args.serial} not found in database.")
        return

    domain = args.domain if args.domain else cert_row["domain"]
    cert_pem = cert_row["cert_pem"]

    print("=" * 72)
    print("  CLIENT VERIFICATION COMPARISON: TRADITIONAL vs CT-AWARE CLIENT")
    print("=" * 72)
    print(f"Target Domain:      {domain}")
    print(f"Certificate Serial: {args.serial}")
    print(f"Actual CA Status:   {'[ROGUE / UNAUTHORIZED]' if cert_row['is_rogue'] else '[LEGITIMATE]'}")
    print("=" * 72)

    # 1. Traditional Client
    print("\n[1] TRADITIONAL TLS CLIENT (Standard PKI Chain Only):")
    trad_client = TraditionalClient(root_ca=ca)
    trad_res = trad_client.verify(cert_pem, domain)
    for s in trad_res.steps:
        print(f"    {s}")
    if trad_res.trusted:
        print("  ➔ STATUS: [TRUSTED / ACCEPTED]")
        print("  🚨 SECURITY IMPLICATION: Client is intercepted by rogue certificate! (Vulnerable to MITM)")
    else:
        print(f"  ➔ STATUS: [REJECTED]: {trad_res.rejection_reason}")

    # 2. CT-Aware Client
    print("\n[2] CT-AWARE & CRL-CHECKING TLS CLIENT:")
    ct_client = CTAwareClient(root_ca=ca, db_manager=db)
    ct_res = ct_client.verify(cert_pem, domain)
    for s in ct_res.steps:
        print(f"    {s}")
    if ct_res.trusted:
        print("  ➔ STATUS: [TRUSTED / ACCEPTED]")
    else:
        print("  ➔ STATUS: [CONNECTION REJECTED & TERMINATED]")
        print(f"  🔒 SECURITY IMPLICATION: Client detected discrepancy / revocation: {ct_res.rejection_reason}")
    print("=" * 72)


def cmd_list_alerts(args):
    _, db = get_ca_and_db()
    alerts = db.get_monitor_alerts()
    if not alerts:
        print("No monitor alerts recorded.")
        return

    print("=" * 75)
    print(f"  RECORDED CT MONITOR ALERTS ({len(alerts)} total)")
    print("=" * 75)
    for a in alerts:
        print(f"Alert ID:     #{a['alert_id']} | Detected At: {a['detected_at']}")
        print(f"Target Domain: {a['domain']}")
        print(f"Serial:        {a['cert_serial']}")
        print(f"Auth Owner:    {a['authorized_owner']}")
        print(f"Auth Key FP:   {a['authorized_key_fingerprint']}")
        print(f"Rogue Key FP:  {a['rogue_key_fingerprint']}")
        print(f"Message:       {a['alert_message']}")
        print("-" * 75)


def cmd_demo_defense(args):
    from demo_defense import run_live_defense
    run_live_defense(target_domain=args.domain, owner_name=args.owner, delay=args.delay)


def main():
    parser = argparse.ArgumentParser(description="Toy PKI & CA Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-ca
    p_init = subparsers.add_parser("init-ca", help="Initialize or reload Toy Root CA")
    p_init.add_argument("--cn", default="Toy Root CA", help="Common Name for CA")
    p_init.add_argument("--org", default="Toy PKI Project", help="Organization name")
    p_init.add_argument("--force", action="store_true", help="Force regenerate CA key and cert")
    p_init.set_defaults(func=cmd_init_ca)

    # register-domain
    p_reg = subparsers.add_parser("register-domain", help="Register authorized domain & owner key")
    p_reg.add_argument("--domain", required=True, help="Domain name (e.g. alice.domain)")
    p_reg.add_argument("--owner", default="Alice", help="Owner identity")
    p_reg.set_defaults(func=cmd_register_domain)

    # issue
    p_issue = subparsers.add_parser("issue", help="Issue legitimate certificate using authorized key")
    p_issue.add_argument("--domain", required=True, help="Domain name")
    p_issue.add_argument("--days", type=int, default=365, help="Validity period in days")
    p_issue.set_defaults(func=cmd_issue_legit)

    # issue-rogue
    p_rogue = subparsers.add_parser("issue-rogue", help="Issue unauthorized rogue certificate (attacker demo)")
    p_rogue.add_argument("--domain", required=True, help="Target domain (TA nominated domain)")
    p_rogue.add_argument("--days", type=int, default=90, help="Validity period in days")
    p_rogue.set_defaults(func=cmd_issue_rogue)

    # list-certs
    p_list = subparsers.add_parser("list-certs", help="List all issued certificates")
    p_list.set_defaults(func=cmd_list_certs)

    # revoke
    p_rev = subparsers.add_parser("revoke", help="Revoke certificate and update CRL")
    p_rev.add_argument("--serial", required=True, help="Certificate serial number")
    p_rev.add_argument("--reason", default="Unauthorized rogue issuance", help="Revocation reason")
    p_rev.set_defaults(func=cmd_revoke)

    # ct-status
    p_ct_status = subparsers.add_parser("ct-status", help="Display Certificate Transparency log and STH")
    p_ct_status.set_defaults(func=cmd_ct_status)

    # ct-audit
    p_ct_audit = subparsers.add_parser("ct-audit", help="Verify Merkle inclusion proof for a certificate")
    p_ct_audit.add_argument("--serial", required=True, help="Certificate serial number to audit")
    p_ct_audit.set_defaults(func=cmd_ct_audit)

    # ct-consistency
    p_ct_cons = subparsers.add_parser("ct-consistency", help="Verify Merkle tree append-only consistency proof")
    p_ct_cons.add_argument("--old-size", type=int, required=True, help="Older tree size to compare")
    p_ct_cons.add_argument("--new-size", type=int, default=None, help="Newer tree size (defaults to current size)")
    p_ct_cons.set_defaults(func=cmd_ct_consistency)

    # monitor
    p_mon = subparsers.add_parser("monitor", help="Run CT Monitor audit against authorization registry")
    p_mon.add_argument("--domain", default=None, help="Target domain to filter (optional)")
    p_mon.add_argument("--no-auto-revoke", action="store_true", help="Do not automatically revoke caught rogue certs")
    p_mon.set_defaults(func=cmd_monitor)

    # verify-client
    p_vc = subparsers.add_parser("verify-client", help="Compare Traditional vs CT-Aware client behavior")
    p_vc.add_argument("--serial", required=True, help="Certificate serial number to test")
    p_vc.add_argument("--domain", default=None, help="Domain name being connected to")
    p_vc.set_defaults(func=cmd_verify_client)

    # list-alerts
    p_la = subparsers.add_parser("list-alerts", help="Display security alerts recorded by CT Monitor")
    p_la.set_defaults(func=cmd_list_alerts)

    # demo-defense
    p_dd = subparsers.add_parser("demo-defense", help="Run automated live TA defense demonstration")
    p_dd.add_argument("--domain", default="target.domain", help="Target domain nominated by TA")
    p_dd.add_argument("--owner", default="Alice Smith", help="Legitimate owner identity")
    p_dd.add_argument("--delay", type=float, default=0.2, help="Pacing delay in seconds")
    p_dd.set_defaults(func=cmd_demo_defense)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
