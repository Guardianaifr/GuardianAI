import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianThreatFeedRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianThreatFeedRegistry", function () {
  let registry: GuardianThreatFeedRegistry;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const MALICIOUS_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const MALICIOUS_STR = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
  const REASON = "Phishing Campaign";

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianThreatFeedRegistry");
    registry = await Factory.deploy();
    await registry.waitForDeployment();
  });

  describe("addAddress", function () {
    it("should allow FEED_WRITER_ROLE to add EVM address", async function () {
      await registry.addAddress(MALICIOUS_ADDR, REASON);
      expect(await registry.evmAddressCount()).to.equal(1);

      const [isMal, reason] = await registry.isMalicious(MALICIOUS_ADDR);
      expect(isMal).to.be.true;
      expect(reason).to.equal(REASON);
    });

    it("should revert if caller does not have FEED_WRITER_ROLE", async function () {
      await expect(
        registry.connect(nonOwner).addAddress(MALICIOUS_ADDR, REASON)
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    });
  });

  describe("removeAddress", function () {
    it("should allow removing malicious address", async function () {
      await registry.addAddress(MALICIOUS_ADDR, REASON);
      await registry.removeAddress(MALICIOUS_ADDR);

      const [isMal] = await registry.isMalicious(MALICIOUS_ADDR);
      expect(isMal).to.be.false;
    });
  });

  describe("addStringAddress", function () {
    it("should add a non-EVM address string", async function () {
      await registry.addStringAddress(MALICIOUS_STR, REASON);
      expect(await registry.stringAddressCount()).to.equal(1);

      const [isMal, reason] = await registry.isMaliciousString(MALICIOUS_STR);
      expect(isMal).to.be.true;
      expect(reason).to.equal(REASON);
    });
  });
});
