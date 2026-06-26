import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianInterlockRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianInterlockRegistry", function () {
  let registry: GuardianInterlockRegistry;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const AGENT_A = ethers.keccak256(ethers.toUtf8Bytes("agent-a"));
  const AGENT_B = ethers.keccak256(ethers.toUtf8Bytes("agent-b"));
  const PROOF_HASH = ethers.keccak256(ethers.toUtf8Bytes("interlock-proof"));
  const NONCE = 12345;

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianInterlockRegistry");
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

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

  describe("verifyInterlock", function () {
    it("should return correct proof hash for valid interlock", async function () {
      const tx = await registry.registerInterlock(AGENT_A, AGENT_B, PROOF_HASH, NONCE);
      await tx.wait();

      const computedId = ethers.keccak256(
        ethers.solidityPacked(
          ["bytes32", "bytes32", "bytes32", "uint256"],
          [AGENT_A, AGENT_B, PROOF_HASH, NONCE]
        )
      );

      const verifiedProofHash = await registry.verifyInterlock(computedId);
      expect(verifiedProofHash).to.equal(PROOF_HASH);
    });

    it("should revert for unknown interlock ID", async function () {
      const unknownId = ethers.ZeroHash;
      await expect(
        registry.verifyInterlock(unknownId)
      ).to.be.revertedWithCustomError(registry, "InterlockNotFound");
    });
  });
});
