"""RFC 6962 compliant SHA-256 Merkle Tree implementation for Certificate Transparency.

Provides:
- Leaf and interior node hashing with domain separation prefixes:
    Leaf Hash:   SHA-256(0x00 || leaf_data)
    Node Hash:   SHA-256(0x01 || left_hash || right_hash)
- Deterministic tree construction using the largest power-of-2 split rule.
- Merkle root computation.
- Logarithmic-time Audit / Inclusion Proof generation and verification.
- Consistency Proof generation and verification (verifying append-only property).
"""

import hashlib
from typing import List, Tuple, Optional, Union


class MerkleTree:
    """Append-only Merkle Tree for CT log verification."""

    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"

    def __init__(self, leaves: Optional[List[bytes]] = None):
        self._leaves: List[bytes] = []
        if leaves:
            self.extend(leaves)

    @property
    def size(self) -> int:
        """Returns the number of leaves in the tree."""
        return len(self._leaves)

    def append(self, data: bytes) -> int:
        """Appends a new leaf to the tree and returns its 0-based index."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Leaf data must be bytes or bytearray.")
        self._leaves.append(bytes(data))
        return len(self._leaves) - 1

    def extend(self, data_list: List[bytes]) -> None:
        """Appends multiple leaves to the tree."""
        for item in data_list:
            self.append(item)

    @classmethod
    def hash_leaf(cls, data: bytes) -> bytes:
        """Computes the leaf hash: SHA-256(0x00 || data)."""
        return hashlib.sha256(cls.LEAF_PREFIX + data).digest()

    @classmethod
    def hash_node(cls, left: bytes, right: bytes) -> bytes:
        """Computes interior node hash: SHA-256(0x01 || left || right)."""
        return hashlib.sha256(cls.NODE_PREFIX + left + right).digest()

    @staticmethod
    def _largest_power_of_2_less_than(n: int) -> int:
        """Returns the largest power of 2 strictly less than n (for n >= 2)."""
        if n < 2:
            return 0
        return 1 << ((n - 1).bit_length() - 1)

    # --- Merkle Tree Hash (MTH) Computation ---

    def _mth(self, entries: List[bytes]) -> bytes:
        """Computes the Merkle Tree Hash for a slice of leaves."""
        n = len(entries)
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return self.hash_leaf(entries[0])
        
        k = self._largest_power_of_2_less_than(n)
        left_mth = self._mth(entries[:k])
        right_mth = self._mth(entries[k:])
        return self.hash_node(left_mth, right_mth)

    def get_root_hash(self) -> bytes:
        """Computes and returns the 32-byte Merkle root hash."""
        return self._mth(self._leaves)

    def get_root_hash_hex(self) -> str:
        """Computes and returns the Merkle root hash as a hex string."""
        return self.get_root_hash().hex()

    def get_leaf_hash(self, index: int) -> bytes:
        """Returns the SHA-256 leaf hash for the leaf at index."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError("Leaf index out of bounds.")
        return self.hash_leaf(self._leaves[index])

    def get_leaf_hash_hex(self, index: int) -> str:
        """Returns the SHA-256 leaf hash as a hex string."""
        return self.get_leaf_hash(index).hex()

    # --- Audit / Inclusion Proof (RFC 6962 Section 2.1.1) ---

    def _audit_path(self, m: int, entries: List[bytes]) -> List[bytes]:
        """Recursive generation of inclusion proof path."""
        n = len(entries)
        if n <= 1:
            return []
        k = self._largest_power_of_2_less_than(n)
        if m < k:
            return self._audit_path(m, entries[:k]) + [self._mth(entries[k:])]
        else:
            return self._audit_path(m - k, entries[k:]) + [self._mth(entries[:k])]

    def get_audit_proof(self, index: int) -> List[bytes]:
        """Generates an inclusion proof (audit path) for the leaf at index."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError("Leaf index out of bounds.")
        return self._audit_path(index, self._leaves)

    def get_audit_proof_hex(self, index: int) -> List[str]:
        """Generates an inclusion proof with hashes represented as hex strings."""
        return [p.hex() for p in self.get_audit_proof(index)]

    @classmethod
    def verify_audit_proof(
        cls,
        leaf_hash: Union[bytes, str],
        leaf_index: int,
        tree_size: int,
        proof: List[Union[bytes, str]],
        expected_root: Union[bytes, str]
    ) -> bool:
        """Verifies that a leaf is included in the tree with the given root hash.

        Args:
            leaf_hash: 32-byte hash (or hex string) of the leaf.
            leaf_index: 0-based index of the leaf.
            tree_size: Total number of leaves in the tree at time of proof.
            proof: List of sibling hashes (bytes or hex strings).
            expected_root: Expected 32-byte Merkle root hash (or hex string).

        Returns:
            True if the calculated root matches expected_root, False otherwise.
        """
        if isinstance(leaf_hash, str):
            leaf_hash = bytes.fromhex(leaf_hash)
        if isinstance(expected_root, str):
            expected_root = bytes.fromhex(expected_root)
        
        byte_proof: List[bytes] = [
            bytes.fromhex(p) if isinstance(p, str) else p for p in proof
        ]

        if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
            return False

        def _compute_root(idx: int, size: int, path: List[bytes]) -> bytes:
            if size == 1:
                return leaf_hash
            k = cls._largest_power_of_2_less_than(size)
            if not path:
                raise ValueError("Proof path ended prematurely.")
            sibling = path[-1]
            rem_path = path[:-1]
            if idx < k:
                left = _compute_root(idx, k, rem_path)
                return cls.hash_node(left, sibling)
            else:
                right = _compute_root(idx - k, size - k, rem_path)
                return cls.hash_node(sibling, right)

        try:
            computed_root = _compute_root(leaf_index, tree_size, byte_proof)
            return computed_root == expected_root
        except Exception:
            return False

    # --- Consistency Proof (RFC 6962 Section 2.1.2) ---

    def _subproof(self, m: int, entries: List[bytes], b: bool) -> List[bytes]:
        """Recursive generation of consistency proof."""
        n = len(entries)
        if m == n:
            return [] if b else [self._mth(entries)]
        k = self._largest_power_of_2_less_than(n)
        if m <= k:
            return self._subproof(m, entries[:k], b) + [self._mth(entries[k:])]
        else:
            return self._subproof(m - k, entries[k:], False) + [self._mth(entries[:k])]

    def get_consistency_proof(self, old_size: int, new_size: Optional[int] = None) -> List[bytes]:
        """Generates a consistency proof that tree of old_size is a prefix of tree of new_size."""
        if new_size is None:
            new_size = len(self._leaves)
        if old_size <= 0 or old_size > new_size or new_size > len(self._leaves):
            raise ValueError(f"Invalid sizes: old_size={old_size}, new_size={new_size}, total={len(self._leaves)}")
        return self._subproof(old_size, self._leaves[:new_size], True)

    def get_consistency_proof_hex(self, old_size: int, new_size: Optional[int] = None) -> List[str]:
        """Returns consistency proof with hashes represented as hex strings."""
        return [p.hex() for p in self.get_consistency_proof(old_size, new_size)]

    @classmethod
    def verify_consistency_proof(
        cls,
        old_size: int,
        new_size: int,
        old_root: Union[bytes, str],
        new_root: Union[bytes, str],
        proof: List[Union[bytes, str]]
    ) -> bool:
        """Verifies that old_root (at old_size) is consistent with new_root (at new_size).

        Proves that no leaves were modified, reordered, or deleted (append-only property).
        """
        if isinstance(old_root, str):
            old_root = bytes.fromhex(old_root)
        if isinstance(new_root, str):
            new_root = bytes.fromhex(new_root)

        byte_proof: List[bytes] = [
            bytes.fromhex(p) if isinstance(p, str) else p for p in proof
        ]

        if old_size == new_size:
            return old_root == new_root and len(byte_proof) == 0
        if old_size > new_size or old_size <= 0:
            return False

        def _verify_rec(
            m_sub: int,
            n_sub: int,
            p: List[bytes],
            complete: bool
        ) -> Tuple[bytes, bytes, List[bytes]]:
            if m_sub == n_sub:
                if complete:
                    return old_root, old_root, p
                else:
                    if not p:
                        raise ValueError("Proof exhausted")
                    h = p[0]
                    return h, h, p[1:]
            k = cls._largest_power_of_2_less_than(n_sub)
            if m_sub <= k:
                old_h, new_left, rem_p = _verify_rec(m_sub, k, p, complete)
                if not rem_p:
                    raise ValueError("Proof exhausted")
                right_h = rem_p[0]
                return old_h, cls.hash_node(new_left, right_h), rem_p[1:]
            else:
                old_right, new_right, rem_p = _verify_rec(m_sub - k, n_sub - k, p, False)
                if not rem_p:
                    raise ValueError("Proof exhausted")
                left_h = rem_p[0]
                return cls.hash_node(left_h, old_right), cls.hash_node(left_h, new_right), rem_p[1:]

        try:
            calc_old, calc_new, remaining = _verify_rec(old_size, new_size, byte_proof, True)
            return calc_old == old_root and calc_new == new_root and len(remaining) == 0
        except Exception:
            return False
