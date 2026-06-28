import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianInsuranceLedger } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianInsuranceLedger", function () {
  let ledger: GuardianInsuranceLedger;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const CERT_ID = ethers.keccak256(ethers.toUtf8Bytes("cert-123"));
  const AGENT_HASH = ethers.keccak256(ethers.toUtf8Bytes("agent-abc"));
  const CERT_HASH = ethers.keccak256(ethers.toUtf8Bytes("cert-document-hash"));
  const PERIOD_START = 1700000000;
  const PERIOD_END = 1700003600;
  const RISK_LEVEL = "LOW";

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianInsuranceLedger");
    ledger = await Factory.deploy();
    await ledger.waitForDeployment();
  });

  describe("issueCertificate", function () {
    it("should issue a certificate successfully", async function () {
      const tx = await ledger.issueCertificate(
        CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
      );
      await tx.wait();

      expect(await ledger.getCertificateCount()).to.equal(1);
      const cert = await ledger.getCertificate(CERT_ID);
      expect(cert.agentHash).to.equal(AGENT_HASH);
      expect(cert.certHash).to.equal(CERT_HASH);
      expect(cert.riskLevel).to.equal(RISK_LEVEL);
      expect(cert.revoked).to.be.false;
    });

    it("should revert if certificate already exists", async function () {
      await ledger.issueCertificate(
        CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
      );
      await expect(
        ledger.issueCertificate(
          CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
        )
      ).to.be.revertedWithCustomError(ledger, "CertificateAlreadyExists");
    });

    it("should revert if period is invalid", async function () {
      await expect(
        ledger.issueCertificate(
          CERT_ID, AGENT_HASH, PERIOD_END, PERIOD_START, CERT_HASH, RISK_LEVEL
        )
      ).to.be.revertedWithCustomError(ledger, "InvalidPeriod");
    });
  });

  describe("revokeCertificate", function () {
    it("should revoke a certificate", async function () {
      await ledger.issueCertificate(
        CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
      );
      await ledger.revokeCertificate(CERT_ID);

      const cert = await ledger.getCertificate(CERT_ID);
      expect(cert.revoked).to.be.true;
    });

    it("should revert if certificate is already revoked", async function () {
      await ledger.issueCertificate(
        CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
      );
      await ledger.revokeCertificate(CERT_ID);

      await expect(
        ledger.revokeCertificate(CERT_ID)
      ).to.be.revertedWithCustomError(ledger, "CertificateAlreadyRevoked");
    });
  });

  describe("Certificate Cap", function() {
    it("should reject issueCertificate when cap is reached", async function() {
      const maxCerts = await ledger.MAX_CERTIFICATES();
      expect(maxCerts).to.equal(100000n);
    });

    it("should revert with CertificateLimitReached when cap exceeded", async function() {
      const errorFragment = ledger.interface.getError("CertificateLimitReached");
      expect(errorFragment).to.not.be.undefined;
    });
  });
});
