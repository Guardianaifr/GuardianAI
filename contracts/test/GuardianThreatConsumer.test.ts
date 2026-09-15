import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianThreatConsumer } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianThreatConsumer", function () {
  let consumer: GuardianThreatConsumer;
  let owner: SignerWithAddress;
  let forwarder: SignerWithAddress;
  let unauthorized: SignerWithAddress;
  let newForwarder: SignerWithAddress;

  const sampleReportData = (blocked: bigint, intercepted: bigint, passed: bigint, digest: string) => {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    return abiCoder.encode(
      ["uint256", "uint256", "uint256", "string"],
      [blocked, intercepted, passed, digest]
    );
  };

  beforeEach(async function () {
    [owner, forwarder, unauthorized, newForwarder] = await ethers.getSigners();

    const factory = await ethers.getContractFactory("GuardianThreatConsumer");
    consumer = await factory.deploy(forwarder.address);
    await consumer.waitForDeployment();
  });

  describe("Deployment & Initial State", function () {
    it("should set the deployer as owner", async function () {
      expect(await consumer.owner()).to.equal(owner.address);
    });

    it("should set the initial forwarder address", async function () {
      expect(await consumer.forwarderAddress()).to.equal(forwarder.address);
    });

    it("should initialize reportCount to 0", async function () {
      expect(await consumer.reportCount()).to.equal(0n);
    });

    it("should deploy cleanly with address(0) forwarder", async function () {
      const factory = await ethers.getContractFactory("GuardianThreatConsumer");
      const unconfigured = await factory.deploy(ethers.ZeroAddress);
      await unconfigured.waitForDeployment();
      expect(await unconfigured.forwarderAddress()).to.equal(ethers.ZeroAddress);
      expect(await unconfigured.owner()).to.equal(owner.address);
    });
  });

  describe("Access Control & Admin Controls", function () {
    it("should allow owner to update forwarderAddress", async function () {
      await expect(consumer.connect(owner).setForwarderAddress(newForwarder.address))
        .to.emit(consumer, "ForwarderUpdated")
        .withArgs(forwarder.address, newForwarder.address);

      expect(await consumer.forwarderAddress()).to.equal(newForwarder.address);
    });

    it("should revert setForwarderAddress when called by non-owner", async function () {
      await expect(
        consumer.connect(unauthorized).setForwarderAddress(newForwarder.address)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(unauthorized.address);
    });

    it("should allow owner to transfer ownership", async function () {
      await expect(consumer.connect(owner).transferOwnership(newForwarder.address))
        .to.emit(consumer, "OwnershipTransferred")
        .withArgs(owner.address, newForwarder.address);

      expect(await consumer.owner()).to.equal(newForwarder.address);
    });

    it("should revert transferOwnership to zero address", async function () {
      await expect(
        consumer.connect(owner).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(consumer, "ZeroAddress");
    });

    it("should revert transferOwnership when called by non-owner", async function () {
      await expect(
        consumer.connect(unauthorized).transferOwnership(unauthorized.address)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(unauthorized.address);
    });
  });

  describe("onReport Ingestion & Forwarder Verification", function () {
    it("should accept verified report from authorized forwarder", async function () {
      const payload = sampleReportData(15n, 100n, 85n, "0xabcdef1234567890");

      await expect(consumer.connect(forwarder).onReport(payload))
        .to.emit(consumer, "ThreatReportReceived")
        .withArgs(1n, 15n, 100n, 85n, "0xabcdef1234567890");

      expect(await consumer.reportCount()).to.equal(1n);

      const latest = await consumer.latestReport();
      expect(latest.blocked).to.equal(15n);
      expect(latest.intercepted).to.equal(100n);
      expect(latest.passed).to.equal(85n);
      expect(latest.threatDigest).to.equal("0xabcdef1234567890");
    });

    it("should accept verified report from owner", async function () {
      const payload = sampleReportData(5n, 50n, 45n, "0x1111222233334444");

      await expect(consumer.connect(owner).onReport(payload))
        .to.emit(consumer, "ThreatReportReceived")
        .withArgs(1n, 5n, 50n, 45n, "0x1111222233334444");

      expect(await consumer.reportCount()).to.equal(1n);
    });

    it("should revert onReport when called by unauthorized third-party", async function () {
      const payload = sampleReportData(99n, 100n, 1n, "0xmalicious");

      await expect(
        consumer.connect(unauthorized).onReport(payload)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(unauthorized.address);

      expect(await consumer.reportCount()).to.equal(0n);
    });

    it("should correctly increment report IDs and maintain report history", async function () {
      const p1 = sampleReportData(10n, 100n, 90n, "0xfirst");
      const p2 = sampleReportData(20n, 200n, 180n, "0xsecond");

      await consumer.connect(forwarder).onReport(p1);
      await consumer.connect(forwarder).onReport(p2);

      expect(await consumer.reportCount()).to.equal(2n);

      const r1 = await consumer.reports(1);
      expect(r1.blocked).to.equal(10n);
      expect(r1.threatDigest).to.equal("0xfirst");

      const r2 = await consumer.reports(2);
      expect(r2.blocked).to.equal(20n);
      expect(r2.threatDigest).to.equal("0xsecond");

      const latest = await consumer.latestReport();
      expect(latest.blocked).to.equal(20n);
      expect(latest.threatDigest).to.equal("0xsecond");
    });
  });

  describe("Analytics Views: isActivelyProtecting & blockRateBps", function () {
    it("should return false for isActivelyProtecting when 0 threats blocked", async function () {
      expect(await consumer.isActivelyProtecting()).to.be.false;

      const cleanPayload = sampleReportData(0n, 100n, 100n, "0xclean");
      await consumer.connect(forwarder).onReport(cleanPayload);

      expect(await consumer.isActivelyProtecting()).to.be.false;
    });

    it("should return true for isActivelyProtecting when > 0 threats blocked", async function () {
      const threatPayload = sampleReportData(1n, 100n, 99n, "0xthreat");
      await consumer.connect(forwarder).onReport(threatPayload);

      expect(await consumer.isActivelyProtecting()).to.be.true;
    });

    it("should return 0 basis points when 0 intercepted", async function () {
      expect(await consumer.blockRateBps()).to.equal(0n);
    });

    it("should calculate correct basis points for blockRateBps", async function () {
      // 50 blocked out of 1000 intercepted = 5.00% = 500 bps
      const payload = sampleReportData(50n, 1000n, 950n, "0xmetrics");
      await consumer.connect(forwarder).onReport(payload);

      expect(await consumer.blockRateBps()).to.equal(500n);
    });

    it("should return 10,000 basis points (100%) when blocked equals intercepted", async function () {
      const payload = sampleReportData(100n, 100n, 0n, "0xallblocked");
      await consumer.connect(forwarder).onReport(payload);

      expect(await consumer.blockRateBps()).to.equal(10000n);
    });

    it("should handle block rate calculation when blocked exceeds intercepted (telemetry anomaly)", async function () {
      const payload = sampleReportData(200n, 100n, 0n, "0xanomaly");
      await consumer.connect(forwarder).onReport(payload);

      expect(await consumer.blockRateBps()).to.equal(20000n);
    });
  });

  describe("Forwarder Lifecycle & Access Invariants", function () {
    it("should revoke previous forwarder rights when forwarder is rotated", async function () {
      await consumer.connect(owner).setForwarderAddress(newForwarder.address);

      const payload = sampleReportData(1n, 10n, 9n, "0xrotation_test");

      // Previous forwarder should now be rejected
      await expect(
        consumer.connect(forwarder).onReport(payload)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(forwarder.address);

      // New forwarder should be accepted
      await expect(consumer.connect(newForwarder).onReport(payload))
        .to.emit(consumer, "ThreatReportReceived");
    });

    it("should revoke previous owner rights when ownership is transferred", async function () {
      await consumer.connect(owner).transferOwnership(unauthorized.address);

      const payload = sampleReportData(1n, 10n, 9n, "0xowner_revocation");

      // Old owner can no longer call setForwarderAddress
      await expect(
        consumer.connect(owner).setForwarderAddress(newForwarder.address)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(owner.address);

      // Old owner can no longer transfer ownership
      await expect(
        consumer.connect(owner).transferOwnership(owner.address)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(owner.address);

      // Old owner can no longer submit reports via onReport
      await expect(
        consumer.connect(owner).onReport(payload)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(owner.address);

      // New owner has full admin and report access
      await expect(consumer.connect(unauthorized).onReport(payload))
        .to.emit(consumer, "ThreatReportReceived");
    });

    it("should allow disabling forwarder by setting to address(0)", async function () {
      await consumer.connect(owner).setForwarderAddress(ethers.ZeroAddress);
      expect(await consumer.forwarderAddress()).to.equal(ethers.ZeroAddress);

      const payload = sampleReportData(1n, 10n, 9n, "0xdisabled");

      // Forwarder is now rejected
      await expect(
        consumer.connect(forwarder).onReport(payload)
      ).to.be.revertedWithCustomError(consumer, "UnauthorizedCaller").withArgs(forwarder.address);

      // Owner can still deliver reports
      await expect(consumer.connect(owner).onReport(payload))
        .to.emit(consumer, "ThreatReportReceived");
    });

    it("should revert onReport if payload is truncated / malformed calldata", async function () {
      const truncated = "0x123456";
      await expect(
        consumer.connect(forwarder).onReport(truncated)
      ).to.be.reverted;
    });

    it("should accept empty string threatDigest and extreme unicode values", async function () {
      const emptyDigestPayload = sampleReportData(0n, 50n, 50n, "");
      await consumer.connect(forwarder).onReport(emptyDigestPayload);

      let latest = await consumer.latestReport();
      expect(latest.threatDigest).to.equal("");

      const unicodePayload = sampleReportData(0n, 50n, 50n, "🔒 🛡️ ⚠️ Threat-Digest-Unicode-Audit-§§§");
      await consumer.connect(forwarder).onReport(unicodePayload);

      latest = await consumer.latestReport();
      expect(latest.threatDigest).to.equal("🔒 🛡️ ⚠️ Threat-Digest-Unicode-Audit-§§§");
    });
  });
});

