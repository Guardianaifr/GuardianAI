"""
Tests for MerkleTree and MerkleAnchor — tree construction, proof generation,
proof verification, and chain anchoring.
"""

import hashlib
import pytest

from guardian.cortex.merkle_anchor import (
    MerkleTree, MerkleAnchor, MerkleProof, AnchorResult,
    CHAIN_CONFIGS, _sha256_hex,
)


def _make_leaves(n: int) -> list[str]:
    """Generate n deterministic leaf hashes."""
    return [hashlib.sha256(f"event-{i}".encode()).hexdigest() for i in range(n)]


# ── MerkleTree ────────────────────────────────────────────────

class TestMerkleTree:

    def test_single_leaf(self):
        leaves = _make_leaves(1)
        tree = MerkleTree(leaves)
        assert tree.root is not None
        assert tree.leaf_count == 1

    def test_two_leaves(self):
        leaves = _make_leaves(2)
        tree = MerkleTree(leaves)
        assert tree.root is not None
        assert tree.leaf_count == 2

    def test_power_of_two(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 4

    def test_non_power_of_two(self):
        """Non-power-of-2 leaf counts should pad internally."""
        leaves = _make_leaves(3)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 3

    def test_large_tree(self):
        leaves = _make_leaves(100)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 100
        assert len(tree.root) == 64  # 256-bit hex

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            MerkleTree([])

    def test_deterministic_root(self):
        """Same leaves should produce same root."""
        leaves = _make_leaves(8)
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.root == tree2.root

    def test_different_leaves_different_root(self):
        tree1 = MerkleTree(_make_leaves(4))
        tree2 = MerkleTree([_sha256_hex(f"different-{i}") for i in range(4)])
        assert tree1.root != tree2.root

    def test_cve_2012_2459_duplicate_leaf_collision_prevented(self):
        """Regression test: duplicate leaf padding in [A, B, C] must NOT collide with [A, B, C, C]."""
        leaves_3 = ["aa" * 32, "bb" * 32, "cc" * 32]
        leaves_4 = ["aa" * 32, "bb" * 32, "cc" * 32, "cc" * 32]
        t1 = MerkleTree(leaves_3)
        t2 = MerkleTree(leaves_4)
        assert t1.root != t2.root, "Collision detected between 3-leaf and 4-leaf tree (CVE-2012-2459 regression)!"

    def test_all_odd_tree_sizes_generate_valid_proofs(self):
        """Verify inclusion proofs for various odd and prime tree sizes."""
        for size in [1, 3, 5, 7, 9, 13, 17, 33, 57]:
            leaves = _make_leaves(size)
            tree = MerkleTree(leaves)
            for idx in range(size):
                proof = tree.get_proof(idx)
                assert MerkleTree.verify_proof(proof.leaf, proof.proof, tree.root) is True


class TestMerkleProof:

    def test_generate_proof_first_leaf(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        assert proof.leaf == leaves[0]
        assert proof.root == tree.root
        assert len(proof.proof) > 0

    def test_generate_proof_last_leaf(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(3)
        assert proof.leaf == leaves[3]

    def test_proof_index_out_of_range(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        with pytest.raises(IndexError):
            tree.get_proof(4)

    def test_verify_valid_proof(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        for i in range(len(leaves)):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(proof.leaf, proof.proof, proof.root) is True

    def test_verify_invalid_leaf(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        fake_leaf = _sha256_hex("tampered-data")
        assert MerkleTree.verify_proof(fake_leaf, proof.proof, proof.root) is False

    def test_verify_tampered_proof(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        tampered = list(proof.proof)
        tampered[0] = _sha256_hex("tampered-sibling")
        assert MerkleTree.verify_proof(proof.leaf, tampered, proof.root) is False

    def test_verify_wrong_root(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        fake_root = _sha256_hex("fake-root")
        assert MerkleTree.verify_proof(proof.leaf, proof.proof, fake_root) is False

    def test_proof_serialization(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        d = proof.to_dict()
        assert "leaf" in d
        assert "root" in d
        assert "proof" in d
        assert d["tree_size"] == 4


# ── MerkleAnchor ──────────────────────────────────────────────

class TestMerkleAnchor:

    def test_default_chain_is_monad(self):
        anchor = MerkleAnchor()
        assert anchor.primary_chain == "monad"
        assert anchor.chain_config["chain_id"] == 10143

    def test_invalid_chain_raises(self):
        with pytest.raises(ValueError, match="Unknown chain"):
            MerkleAnchor(primary_chain="solana")

    def test_build_batch(self):
        anchor = MerkleAnchor()
        leaves = _make_leaves(10)
        tree, proofs = anchor.build_batch(leaves)
        assert tree.leaf_count == 10
        assert len(proofs) == 10
        for p in proofs:
            assert MerkleTree.verify_proof(p.leaf, p.proof, p.root) is True

    def test_anchor_to_monad(self):
        anchor = MerkleAnchor(primary_chain="monad")
        leaves = _make_leaves(5)
        tree, _ = anchor.build_batch(leaves)
        result = anchor.anchor_to_chain(
            merkle_root=tree.root, event_count=5, agent_id="test-agent",
        )
        assert result.success is True
        assert result.chain_id == "monad"
        assert result.tx_hash != ""
        assert result.simulated is True
        assert "monadscan.com" in result.explorer_url

    def test_anchor_to_base(self):
        anchor = MerkleAnchor(primary_chain="base")
        result = anchor.anchor_to_chain(
            merkle_root=_sha256_hex("root"), event_count=3,
        )
        assert result.success is True
        assert result.chain_id == "base"
        assert "basescan.org" in result.explorer_url

    def test_anchor_unknown_chain(self):
        anchor = MerkleAnchor()
        result = anchor.anchor_to_chain(
            merkle_root=_sha256_hex("root"), event_count=1, chain_id="invalid",
        )
        assert result.success is False
        assert "Unknown chain" in result.error

    def test_supported_chains(self):
        anchor = MerkleAnchor()
        chains = anchor.get_supported_chains()
        chain_names = [c["chain_id_name"] for c in chains]
        assert "monad" in chain_names
        assert "base" in chain_names
        assert "ethereum" in chain_names

    def test_monad_priority(self):
        """Monad should have highest priority (1)."""
        assert CHAIN_CONFIGS["monad"]["priority"] == 1
        assert CHAIN_CONFIGS["base"]["priority"] == 2
        assert CHAIN_CONFIGS["ethereum"]["priority"] == 3
