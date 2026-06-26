import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianPassportSBT } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianPassportSBT", function () {
  let sbt: GuardianPassportSBT;
  let owner: SignerWithAddress;
  let user1: SignerWithAddress;
  let user2: SignerWithAddress;

  const AGENT_HASH = ethers.keccak256(ethers.toUtf8Bytes("agent-001"));
  const AGENT_HASH_2 = ethers.keccak256(ethers.toUtf8Bytes("agent-002"));
  const INITIAL_SCORE = 5000; // 50.00
  const METADATA_URI = "ipfs://QmTest123";

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianPassportSBT");
    sbt = await Factory.deploy();
    await sbt.waitForDeployment();
  });

  describe("mint", function () {
    it("should mint a passport SBT", async function () {
      const tx = await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);
      await tx.wait();

      expect(await sbt.ownerOf(1)).to.equal(user1.address);
      expect(await sbt.activePassportCount()).to.equal(1);

      const passport = await sbt.getPassport(1);
      expect(passport.agentHash).to.equal(AGENT_HASH);
      expect(passport.trustScore).to.equal(INITIAL_SCORE);
      expect(passport.tier).to.equal(1); // SILVER (5000 >= 4000)
      expect(passport.revoked).to.be.false;
    });

    it("should revert for duplicate agent", async function () {
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);
      await expect(
        sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI)
      ).to.be.revertedWithCustomError(sbt, "AgentAlreadyHasPassport");
    });

    it("should revert for invalid score (> 10000)", async function () {
      await expect(
        sbt.mint(user1.address, AGENT_HASH, 10001, METADATA_URI)
      ).to.be.revertedWithCustomError(sbt, "InvalidScore");
    });

    it("should revert when called by non-owner", async function () {
      await expect(
        sbt.connect(user1).mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI)
      ).to.be.revertedWithCustomError(sbt, "OwnableUnauthorizedAccount");
    });
  });

  describe("Soulbound (transfer blocking)", function () {
    it("should block transfers", async function () {
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);

      await expect(
        sbt.connect(user1).transferFrom(user1.address, user2.address, 1)
      ).to.be.revertedWithCustomError(sbt, "SoulboundTransferBlocked");
    });

    it("should block safeTransferFrom", async function () {
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);

      await expect(
        sbt.connect(user1)["safeTransferFrom(address,address,uint256)"](
          user1.address, user2.address, 1
        )
      ).to.be.revertedWithCustomError(sbt, "SoulboundTransferBlocked");
    });
  });

  describe("updateScore", function () {
    beforeEach(async function () {
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);
    });

    it("should update trust score and tier", async function () {
      await sbt.updateScore(1, 9500); // DIAMOND tier

      const passport = await sbt.getPassport(1);
      expect(passport.trustScore).to.equal(9500);
      expect(passport.tier).to.equal(3); // DIAMOND
    });

    it("should revert for non-existent token", async function () {
      await expect(
        sbt.updateScore(999, 5000)
      ).to.be.revertedWithCustomError(sbt, "PassportNotFound");
    });

    it("should revert for invalid score", async function () {
      await expect(
        sbt.updateScore(1, 10001)
      ).to.be.revertedWithCustomError(sbt, "InvalidScore");
    });
  });

  describe("revoke", function () {
    beforeEach(async function () {
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);
    });

    it("should revoke and burn the passport", async function () {
      await sbt.revoke(1);

      expect(await sbt.activePassportCount()).to.equal(0);

      // Token should be burned
      await expect(sbt.ownerOf(1)).to.be.reverted;

      // Agent slot should be freed — can mint again
      const agentTokenId = await sbt.getAgentTokenId(AGENT_HASH);
      expect(agentTokenId).to.equal(0);
    });

    it("should revert for already revoked passport", async function () {
      await sbt.revoke(1);
      await expect(
        sbt.revoke(1)
      ).to.be.revertedWithCustomError(sbt, "PassportAlreadyRevoked");
    });

    it("should allow re-minting after revocation", async function () {
      await sbt.revoke(1);
      // Should work — agent slot was freed
      await sbt.mint(user1.address, AGENT_HASH, 7500, METADATA_URI);
      expect(await sbt.activePassportCount()).to.equal(1);
    });
  });

  describe("locked (ERC-5192)", function () {
    it("should return true for minted tokens", async function () {
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);
      expect(await sbt.locked(1)).to.be.true;
    });

    it("should revert for non-existent tokens", async function () {
      await expect(sbt.locked(999)).to.be.reverted;
    });
  });

  describe("supportsInterface (ERC-165)", function () {
    it("should support ERC-721", async function () {
      // ERC-721 interface ID
      expect(await sbt.supportsInterface("0x80ac58cd")).to.be.true;
    });

    it("should support ERC-165", async function () {
      expect(await sbt.supportsInterface("0x01ffc9a7")).to.be.true;
    });

    it("should support ERC-5192", async function () {
      expect(await sbt.supportsInterface("0xb45a3c0e")).to.be.true;
    });
  });

  describe("Pausable", function () {
    it("should block mint when paused", async function () {
      await sbt.pause();
      await expect(
        sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI)
      ).to.be.revertedWithCustomError(sbt, "EnforcedPause");
    });

    it("should resume after unpause", async function () {
      await sbt.pause();
      await sbt.unpause();
      await sbt.mint(user1.address, AGENT_HASH, INITIAL_SCORE, METADATA_URI);
      expect(await sbt.activePassportCount()).to.equal(1);
    });
  });

  describe("Ownable2Step", function () {
    it("should support two-step ownership transfer", async function () {
      await sbt.transferOwnership(user1.address);
      expect(await sbt.owner()).to.equal(owner.address); // Not transferred yet

      await sbt.connect(user1).acceptOwnership();
      expect(await sbt.owner()).to.equal(user1.address);
    });
  });

  describe("Tier classification", function () {
    it("should classify UNVERIFIED for score < 4000", async function () {
      await sbt.mint(user1.address, AGENT_HASH, 3999, METADATA_URI);
      const passport = await sbt.getPassport(1);
      expect(passport.tier).to.equal(0); // UNVERIFIED
    });

    it("should classify SILVER for score 4000-6999", async function () {
      await sbt.mint(user1.address, AGENT_HASH, 5000, METADATA_URI);
      const passport = await sbt.getPassport(1);
      expect(passport.tier).to.equal(1); // SILVER
    });

    it("should classify GOLD for score 7000-8999", async function () {
      await sbt.mint(user1.address, AGENT_HASH, 8000, METADATA_URI);
      const passport = await sbt.getPassport(1);
      expect(passport.tier).to.equal(2); // GOLD
    });

    it("should classify DIAMOND for score >= 9000", async function () {
      await sbt.mint(user1.address, AGENT_HASH, 9500, METADATA_URI);
      const passport = await sbt.getPassport(1);
      expect(passport.tier).to.equal(3); // DIAMOND
    });
  });
});
