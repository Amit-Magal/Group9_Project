"""Comprehensive test suite for Merkle Tree and Certificate Transparency Log."""

import sys
import tempfile
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ct.merkle_tree import MerkleTree
from ct.log_server import CTLogServer
from storage.database import DatabaseManager
from ca.root_ca import RootCA


def test_merkle_tree_math():
    print("=" * 65)
    print("  TEST 1: MERKLE TREE RFC 6962 ALGORITHM & TAMPER DETECTION")
    print("=" * 65)

    # Test trees of various sizes
    for size in [1, 2, 3, 5, 8, 11]:
        entries = [f"certificate_payload_{i}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(entries)
        root = tree.get_root_hash()
        assert tree.size == size, f"Tree size mismatch: {tree.size} != {size}"

        # Test inclusion proof for each leaf
        for idx in range(size):
            proof = tree.get_audit_proof(idx)
            leaf_h = tree.get_leaf_hash(idx)

            # 1. Valid proof verification
            is_valid = MerkleTree.verify_audit_proof(
                leaf_hash=leaf_h,
                leaf_index=idx,
                tree_size=size,
                proof=proof,
                expected_root=root
            )
            assert is_valid, f"Inclusion proof failed for leaf {idx} in tree of size {size}"

            # 2. Tamper Test: Modify leaf data
            tampered_leaf = MerkleTree.hash_leaf(b"TAMPERED_DATA")
            tamper_detected = not MerkleTree.verify_audit_proof(
                leaf_hash=tampered_leaf,
                leaf_index=idx,
                tree_size=size,
                proof=proof,
                expected_root=root
            )
            assert tamper_detected, "Security failure: Tampered leaf hash was accepted!"

            # 3. Tamper Test: Modify root hash
            tampered_root = bytes([root[0] ^ 0xFF]) + root[1:]
            root_tamper_detected = not MerkleTree.verify_audit_proof(
                leaf_hash=leaf_h,
                leaf_index=idx,
                tree_size=size,
                proof=proof,
                expected_root=tampered_root
            )
            assert root_tamper_detected, "Security failure: Tampered root hash was accepted!"

        print(f"  ✓ Tree size {size:2d}: All {size} inclusion proofs verified & tamper tests passed.")

    # Consistency proof test (Append-only verification)
    total_entries = [f"log_cert_{i}".encode() for i in range(12)]
    full_tree = MerkleTree(total_entries)

    print("\n  Testing Consistency Proofs (Append-only Verification)...")
    for old_size in [1, 3, 6, 8]:
        for new_size in [old_size + 1, old_size + 3, len(total_entries)]:
            old_root = MerkleTree(total_entries[:old_size]).get_root_hash()
            new_root = MerkleTree(total_entries[:new_size]).get_root_hash()
            cons_proof = MerkleTree(total_entries[:new_size]).get_consistency_proof(old_size, new_size)

            valid_cons = MerkleTree.verify_consistency_proof(
                old_size=old_size,
                new_size=new_size,
                old_root=old_root,
                new_root=new_root,
                proof=cons_proof
            )
            assert valid_cons, f"Consistency proof failed for {old_size} -> {new_size}"

            # Tamper test on consistency
            tampered_old_root = bytes([old_root[0] ^ 0xFF]) + old_root[1:]
            assert not MerkleTree.verify_consistency_proof(
                old_size=old_size,
                new_size=new_size,
                old_root=tampered_old_root,
                new_root=new_root,
                proof=cons_proof
            ), "Consistency check failed to catch tampered old root!"

    print("  ✓ All consistency proofs verified successfully.")


def test_ct_log_and_ca_integration():
    print("\n" + "=" * 65)
    print("  TEST 2: CT LOG SERVER & ROOT CA INTEGRATION")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_path = str(tmp_path / "test_ct.db")
        certs_dir = str(tmp_path / "certs")

        db = DatabaseManager(db_path=db_path)
        ca = RootCA(certs_dir=certs_dir, db_manager=db)
        ca.setup_ca(common_name="Toy Root CA")

        ct_log = CTLogServer(certs_dir=certs_dir, db_manager=db)
        print(f"  ✓ CT Log Initialized (Log ID: {ct_log.get_log_id()[:16]}...)")

        # 1. Register Alice and issue legitimate certificate
        _, alice_pub = RootCA.generate_key_pair()
        alice_pub_pem = RootCA.export_public_key_pem(alice_pub)
        db.register_authorized_domain("alice.domain", "Alice", alice_pub_pem)

        legit_cert, _, legit_der = ca.issue_certificate("alice.domain", alice_pub)
        print(f"  ✓ Issued Legitimate Cert (Serial: {legit_cert.serial_number})")

        # 2. Issue Rogue certificate
        _, attacker_pub = RootCA.generate_key_pair()
        rogue_cert, _, rogue_der = ca.issue_certificate("alice.domain", attacker_pub, is_rogue=True)
        print(f"  ✓ Issued Rogue Cert (Serial: {rogue_cert.serial_number})")

        # 3. Check CT Log State
        sth = ct_log.get_signed_tree_head()
        assert sth["tree_size"] == 2, f"Expected tree size 2, got {sth['tree_size']}"
        print(f"  ✓ CT Tree Size: {sth['tree_size']}")
        print(f"  ✓ CT Merkle Root: {sth['root_hash']}")

        # 4. Audit Proof for Legitimate Certificate
        legit_proof = ct_log.get_inclusion_proof_by_serial(str(legit_cert.serial_number))
        assert legit_proof is not None
        assert MerkleTree.verify_audit_proof(
            leaf_hash=legit_proof["leaf_hash"],
            leaf_index=legit_proof["leaf_index"],
            tree_size=legit_proof["tree_size"],
            proof=legit_proof["proof"],
            expected_root=legit_proof["root_hash"]
        )
        print("  ✓ Legitimate certificate inclusion proof: VERIFIED")

        # 5. Audit Proof for Rogue Certificate
        rogue_proof = ct_log.get_inclusion_proof_by_serial(str(rogue_cert.serial_number))
        assert rogue_proof is not None
        assert MerkleTree.verify_audit_proof(
            leaf_hash=rogue_proof["leaf_hash"],
            leaf_index=rogue_proof["leaf_index"],
            tree_size=rogue_proof["tree_size"],
            proof=rogue_proof["proof"],
            expected_root=rogue_proof["root_hash"]
        )
        print("  ✓ Rogue certificate inclusion proof: VERIFIED")

        # 6. Test Persistence & Reloading from DB
        ct_log_reloaded = CTLogServer(certs_dir=certs_dir, db_manager=db)
        assert ct_log_reloaded.tree.size == 2
        assert ct_log_reloaded.tree.get_root_hash_hex() == sth["root_hash"]
        print("  ✓ CT Log Server reloaded from DB: Merkle Tree state identical")

    print("\n" + "=" * 65)
    print("  ALL MERKLE TREE & CT LOG TESTS PASSED SUCCESSFULLY! ")
    print("=" * 65)


if __name__ == "__main__":
    test_merkle_tree_math()
    test_ct_log_and_ca_integration()
