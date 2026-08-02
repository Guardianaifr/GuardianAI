import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianThreatFeedRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianThreatFeedRegistry", function () {
  let registry: GuardianThreatFeedRegistry;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const MALICIOUS_ADDR  = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const MALICIOUS_ADDR2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  const MALICIOUS_STR   = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
  const MALICIOUS_STR2  = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
  const REASON          = "Phishing Campaign";

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianThreatFeedRegistry");
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

  // ── addAddress ───────────────────────────────────────────────────────

  describe("addAddress", function () {
    it("should allow owner to add EVM address", async function () {
      await registry.addAddress(MALICIOUS_ADDR, REASON);
      expect(await registry.evmAddressCount()).to.equal(1);

      const [isMal, reason] = await registry.isMalicious(MALICIOUS_ADDR);
      expect(isMal).to.be.true;
      expect(reason).to.equal(REASON);
    });

    it("should revert if caller is not the owner", async function () {
      await expect(
        registry.connect(nonOwner).addAddress(MALICIOUS_ADDR, REASON)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ── removeAddress ────────────────────────────────────────────────────

  describe("removeAddress", function () {
    it("should allow owner to remove a malicious EVM address", async function () {
      await registry.addAddress(MALICIOUS_ADDR, REASON);
      await registry.removeAddress(MALICIOUS_ADDR);

      const [isMal] = await registry.isMalicious(MALICIOUS_ADDR);
      expect(isMal).to.be.false;
      expect(await registry.evmAddressCount()).to.equal(0);
    });

    it("should revert if caller is not the owner", async function () {
      await registry.addAddress(MALICIOUS_ADDR, REASON);
      await expect(
        registry.connect(nonOwner).removeAddress(MALICIOUS_ADDR)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ── addStringAddress ─────────────────────────────────────────────────

  describe("addStringAddress", function () {
    it("should allow owner to add a non-EVM address string", async function () {
      await registry.addStringAddress(MALICIOUS_STR, REASON);
      expect(await registry.stringAddressCount()).to.equal(1);

      const [isMal, reason] = await registry.isMaliciousString(MALICIOUS_STR);
      expect(isMal).to.be.true;
      expect(reason).to.equal(REASON);
    });

    it("should revert if caller is not the owner", async function () {
      await expect(
        registry.connect(nonOwner).addStringAddress(MALICIOUS_STR, REASON)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ── removeStringAddress ──────────────────────────────────────────────

  describe("removeStringAddress", function () {
    it("should allow owner to remove a non-EVM string address", async function () {
      await registry.addStringAddress(MALICIOUS_STR, REASON);
      await registry.removeStringAddress(MALICIOUS_STR);

      const [isMal] = await registry.isMaliciousString(MALICIOUS_STR);
      expect(isMal).to.be.false;
      expect(await registry.stringAddressCount()).to.equal(0);
    });

    it("should revert if caller is not the owner", async function () {
      await registry.addStringAddress(MALICIOUS_STR, REASON);
      await expect(
        registry.connect(nonOwner).removeStringAddress(MALICIOUS_STR)
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ── addAddressesBatch ────────────────────────────────────────────────

  describe("addAddressesBatch", function () {
    it("should allow owner to batch-add EVM addresses", async function () {
      await registry.addAddressesBatch(
        [MALICIOUS_ADDR, MALICIOUS_ADDR2],
        [REASON, REASON]
      );
      expect(await registry.evmAddressCount()).to.equal(2);

      const [isMal1] = await registry.isMalicious(MALICIOUS_ADDR);
      const [isMal2] = await registry.isMalicious(MALICIOUS_ADDR2);
      expect(isMal1).to.be.true;
      expect(isMal2).to.be.true;
    });

    it("should revert if caller is not the owner", async function () {
      await expect(
        registry.connect(nonOwner).addAddressesBatch(
          [MALICIOUS_ADDR],
          [REASON]
        )
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("should revert if batch size exceeds 50", async function () {
      const addrs = Array(51).fill(MALICIOUS_ADDR);
      const reasons = Array(51).fill(REASON);
      await expect(
        registry.addAddressesBatch(addrs, reasons)
      ).to.be.revertedWith("Batch too large");
    });
  });

  // ── addStringAddressesBatch ──────────────────────────────────────────

  describe("addStringAddressesBatch", function () {
    it("should allow owner to batch-add string addresses", async function () {
      await registry.addStringAddressesBatch(
        [MALICIOUS_STR, MALICIOUS_STR2],
        [REASON, REASON]
      );
      expect(await registry.stringAddressCount()).to.equal(2);

      const [isMal1] = await registry.isMaliciousString(MALICIOUS_STR);
      const [isMal2] = await registry.isMaliciousString(MALICIOUS_STR2);
      expect(isMal1).to.be.true;
      expect(isMal2).to.be.true;
    });

    it("should revert if caller is not the owner", async function () {
      await expect(
        registry.connect(nonOwner).addStringAddressesBatch(
          [MALICIOUS_STR],
          [REASON]
        )
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });

  // ── Ownable2Step ─────────────────────────────────────────────────────

  describe("Ownable2Step", function () {
    it("should support two-step ownership transfer", async function () {
      await registry.transferOwnership(nonOwner.address);
      // pendingOwner is set; owner has not changed yet
      expect(await registry.owner()).to.equal(owner.address);
      expect(await registry.pendingOwner()).to.equal(nonOwner.address);

      // nonOwner accepts
      await registry.connect(nonOwner).acceptOwnership();
      expect(await registry.owner()).to.equal(nonOwner.address);
    });
  });

  // ── Pausable ─────────────────────────────────────────────────────────

  describe("Pausable", function () {
    it("should block addAddress when paused", async function () {
      await registry.pause();
      await expect(
        registry.addAddress(MALICIOUS_ADDR, REASON)
      ).to.be.revertedWithCustomError(registry, "EnforcedPause");
    });

    it("should resume after unpause", async function () {
      await registry.pause();
      await registry.unpause();
      await registry.addAddress(MALICIOUS_ADDR, REASON);
      expect(await registry.evmAddressCount()).to.equal(1);
    });

    it("should revert pause if caller is not the owner", async function () {
      await expect(
        registry.connect(nonOwner).pause()
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
  });
});
