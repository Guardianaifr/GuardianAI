import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianInterlockRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianInterlockRegistry", function () {
  let registry: GuardianInterlockRegistry;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const AGENT_A    = ethers.keccak256(ethers.toUtf8Bytes("agent-a"));
  const AGENT_B    = ethers.keccak256(ethers.toUtf8Bytes("agent-b"));
  const PROOF_HASH = ethers.keccak256(ethers.toUtf8Bytes("interlock-proof"));
  const NONCE      = 12345;

  // Replicates the on-chain interlockId computation
  function computeInterlockId(agentA: string, agentB: string, proofHash: string, nonce: number): string {
    return ethers.keccak256(
      ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "uint256"],
        [agentA, agentB, proofHash, nonce]
      )
    );
  }

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianInterlockRegistry");
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

  // ── registerInterlock — existing tests preserved unchanged ────────────

  describe("registerInterlock", function () {
    it("should register a valid interlock proof", async function () {
      const tx = await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const receipt = await tx.wait();

      expect(await registry.getInterlockCount()).to.equal(1);

      // Verify the event was emitted
      const event = receipt?.logs[0];
      expect(event).to.not.be.undefined;
    });

    it("should revert if agent hashes are invalid", async function () {
      await expect(
        registry.registerInterlock(ethers.ZeroHash, AGENT_B, PROOF_HASH, NONCE)
      ).to.be.revertedWithCustomError(registry, "InvalidAgentHash");
    });

    it("should revert if proof hash is invalid", async function () {
      await expect(
        registry.registerInterlock(AGENT_A, AGENT_B, ethers.ZeroHash, NONCE)
      ).to.be.revertedWithCustomError(registry, "InvalidProofHash");
    });

    it("should revert if registering a duplicate", async function () {
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      await expect(
        registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE)
      ).to.be.revertedWithCustomError(registry, "InterlockAlreadyExists");
    });

    it("should revert if called by non-owner", async function () {
      await expect(
        registry.connect(nonOwner).registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ── verifyInterlock — existing tests preserved + revoked-record case ──

  describe("verifyInterlock", function () {
    it("should return correct proof hash for valid interlock", async function () {
      const tx = await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      await tx.wait();

      const computedId = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const verifiedProofHash = await registry.verifyInterlock(computedId);
      expect(verifiedProofHash).to.equal(PROOF_HASH);
    });

    it("should revert for unknown interlock ID", async function () {
      const unknownId = ethers.ZeroHash;
      await expect(
        registry.verifyInterlock(unknownId)
      ).to.be.revertedWithCustomError(registry, "InterlockNotFound");
    });

    it("verifyInterlock() reverts InterlockAlreadyRevoked on a revoked record", async function () {
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const id = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);

      await registry.revokeInterlock(id);

      await expect(
        registry.verifyInterlock(id)
      ).to.be.revertedWithCustomError(registry, "InterlockAlreadyRevoked");
    });
  });

  // ── IR-2: revokeInterlock ─────────────────────────────────────────────

  describe("revokeInterlock (IR-2)", function () {
    let interlockId: string;

    beforeEach(async function () {
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      interlockId = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
    });

    it("owner can revoke a valid record — emits InterlockRevoked", async function () {
      await expect(registry.revokeInterlock(interlockId))
        .to.emit(registry, "InterlockRevoked")
        .withArgs(interlockId);
    });

    it("non-owner cannot call revokeInterlock", async function () {
      await expect(
        registry.connect(nonOwner).revokeInterlock(interlockId)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("revokeInterlock() on a nonexistent interlockId reverts InterlockNotFound", async function () {
      const badId = ethers.keccak256(ethers.toUtf8Bytes("does-not-exist"));
      await expect(
        registry.revokeInterlock(badId)
      ).to.be.revertedWithCustomError(registry, "InterlockNotFound");
    });

    it("revokeInterlock() on an already-revoked record reverts InterlockAlreadyRevoked", async function () {
      await registry.revokeInterlock(interlockId);
      await expect(
        registry.revokeInterlock(interlockId)
      ).to.be.revertedWithCustomError(registry, "InterlockAlreadyRevoked");
    });

    it("revokeInterlock() while paused reverts (whenNotPaused enforcement)", async function () {
      await registry.pause();
      await expect(
        registry.revokeInterlock(interlockId)
      ).to.be.revertedWithCustomError(registry, "EnforcedPause");
    });
  });

  // ── IR-2: getInterlock() preserves full revoked record ────────────────

  describe("getInterlock after revocation (IR-2)", function () {
    it("getInterlock() returns full record with revoked=true — history intact, not deleted", async function () {
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const id = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);

      await registry.revokeInterlock(id);

      // getInterlock should NOT revert — record is still there
      const proof = await registry.getInterlock(id);
      expect(proof.agentA).to.equal(AGENT_A);
      expect(proof.agentB).to.equal(AGENT_B);
      expect(proof.proofHash).to.equal(PROOF_HASH);
      expect(proof.nonce).to.equal(NONCE);
      expect(proof.registeredAt).to.be.gt(0n);
      expect(proof.revoked).to.be.true;
    });

    it("getInterlock() on a NON-revoked record has revoked=false", async function () {
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const id = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const proof = await registry.getInterlock(id);
      expect(proof.revoked).to.be.false;
    });

    it("revocation does not remove the interlockId from the interlockIds list", async function () {
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const id = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      await registry.revokeInterlock(id);

      // Count unchanged — the registry is append-only; revocation is a status flag only
      expect(await registry.getInterlockCount()).to.equal(1);
      // The entry at index 0 is still the same interlockId
      expect(await registry.interlockIds(0)).to.equal(id);
    });

    it("re-registration after revocation succeeds IF a new unique interlockId is used", async function () {
      // Register original
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const id = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      await registry.revokeInterlock(id);

      // Use different nonce → different interlockId → registration must succeed
      const NONCE2 = NONCE + 1;
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE2);
      expect(await registry.getInterlockCount()).to.equal(2);

      const id2 = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE2);
      const proof = await registry.getInterlock(id2);
      expect(proof.revoked).to.be.false;
    });

    it("re-registration with same inputs (same interlockId) reverts InterlockAlreadyExists even after revocation", async function () {
      // This verifies that revocation doesn't open a re-registration loophole
      // for the exact same proof — you must use a new nonce to create a corrective record.
      await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      const id = computeInterlockId(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      await registry.revokeInterlock(id);

      await expect(
        registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE)
      ).to.be.revertedWithCustomError(registry, "InterlockAlreadyExists");
    });
  });
});
