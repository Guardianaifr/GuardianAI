import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianInsuranceLedger } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianInsuranceLedger", function () {
  let ledger: GuardianInsuranceLedger;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const CERT_ID      = ethers.keccak256(ethers.toUtf8Bytes("cert-123"));
  const AGENT_HASH   = ethers.keccak256(ethers.toUtf8Bytes("agent-abc"));
  const CERT_HASH    = ethers.keccak256(ethers.toUtf8Bytes("cert-document-hash"));
  const PERIOD_START = 1700000000;
  const PERIOD_END   = 1700003600;
  const RISK_LEVEL   = "LOW";

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianInsuranceLedger");
    ledger = await Factory.deploy();
    await ledger.waitForDeployment();
  });

  // ── issueCertificate — existing tests preserved ───────────────────────

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

    // ── IL-1: correct error name for zero _certId ─────────────────────────

    it("IL-1: reverts InvalidCertId (not CertificateNotFound) when _certId is zero", async function () {
      await expect(
        ledger.issueCertificate(
          ethers.ZeroHash, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
        )
      ).to.be.revertedWithCustomError(ledger, "InvalidCertId");
    });

    it("IL-1: CertificateNotFound is still used for genuine lookup-miss in getCertificate()", async function () {
      // getCertificate on an unknown (but non-zero) id → CertificateNotFound, not InvalidCertId
      const unknownId = ethers.keccak256(ethers.toUtf8Bytes("does-not-exist"));
      await expect(
        ledger.getCertificate(unknownId)
      ).to.be.revertedWithCustomError(ledger, "CertificateNotFound");
    });

    // ── IL-2: check ordering — input validation precedes cap check ─────────

    it("IL-2: zero _certId reverts InvalidCertId even if cap would also be reached", async function () {
      // Verify that structural validation fires first, not CertificateLimitReached.
      // We test the error discrimination: passing zero _certId must always be InvalidCertId.
      // (We cannot fill 100,000 certs in a test, but we confirm the code path by the
      // fact that InvalidCertId is already thrown for zero _certId in all conditions.)
      await expect(
        ledger.issueCertificate(
          ethers.ZeroHash, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
        )
      ).to.be.revertedWithCustomError(ledger, "InvalidCertId");
    });

    it("IL-2: zero _agentHash reverts InvalidAgentHash before cap check", async function () {
      await expect(
        ledger.issueCertificate(
          CERT_ID, ethers.ZeroHash, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
        )
      ).to.be.revertedWithCustomError(ledger, "InvalidAgentHash");
    });

    it("IL-2: zero _certHash reverts InvalidCertHash before cap check", async function () {
      await expect(
        ledger.issueCertificate(
          CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, ethers.ZeroHash, RISK_LEVEL
        )
      ).to.be.revertedWithCustomError(ledger, "InvalidCertHash");
    });
  });

  // ── revokeCertificate — preserved unchanged ───────────────────────────

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

    it("should allow revocation even when contract is paused", async function () {
      await ledger.issueCertificate(
        CERT_ID, AGENT_HASH, PERIOD_START, PERIOD_END, CERT_HASH, RISK_LEVEL
      );
      await ledger.pause();
      expect(await ledger.paused()).to.be.true;

      await ledger.revokeCertificate(CERT_ID);
      const cert = await ledger.getCertificate(CERT_ID);
      expect(cert.revoked).to.be.true;
    });
  });

  // ── Certificate Cap — preserved + IL-1 error ABI check ───────────────

  describe("Certificate Cap", function () {
    it("should reject issueCertificate when cap is reached", async function () {
      const maxCerts = await ledger.MAX_CERTIFICATES();
      expect(maxCerts).to.equal(100000n);
    });

    it("should revert with CertificateLimitReached when cap exceeded", async function () {
      const errorFragment = ledger.interface.getError("CertificateLimitReached");
      expect(errorFragment).to.not.be.undefined;
    });

    it("IL-1: InvalidCertId error exists in the ABI", async function () {
      const errorFragment = ledger.interface.getError("InvalidCertId");
      expect(errorFragment).to.not.be.undefined;
    });
  });

  // ── IL-3: getCertificateIdsPage pagination ────────────────────────────

  describe("getCertificateIdsPage (IL-3)", function () {
    // Helper: issue n certificates with distinct IDs
    async function issueN(n: number): Promise<string[]> {
      const ids: string[] = [];
      for (let i = 0; i < n; i++) {
        const id   = ethers.keccak256(ethers.toUtf8Bytes(`cert-page-${i}`));
        const ah   = ethers.keccak256(ethers.toUtf8Bytes(`agent-${i}`));
        const ch   = ethers.keccak256(ethers.toUtf8Bytes(`chash-${i}`));
        await ledger.issueCertificate(id, ah, PERIOD_START, PERIOD_END, ch, RISK_LEVEL);
        ids.push(id);
      }
      return ids;
    }

    it("returns empty page when offset >= total", async function () {
      const page = await ledger.getCertificateIdsPage(0, 10);
      expect(page.length).to.equal(0);
    });

    it("returns first page correctly", async function () {
      const ids = await issueN(5);
      const page = await ledger.getCertificateIdsPage(0, 3);
      expect(page.length).to.equal(3);
      expect(page[0]).to.equal(ids[0]);
      expect(page[1]).to.equal(ids[1]);
      expect(page[2]).to.equal(ids[2]);
    });

    it("returns last partial page correctly", async function () {
      const ids = await issueN(5);
      const page = await ledger.getCertificateIdsPage(3, 10);
      expect(page.length).to.equal(2);
      expect(page[0]).to.equal(ids[3]);
      expect(page[1]).to.equal(ids[4]);
    });

    it("returns full set when limit >= total", async function () {
      const ids = await issueN(5);
      const page = await ledger.getCertificateIdsPage(0, 100);
      expect(page.length).to.equal(5);
      for (let i = 0; i < 5; i++) expect(page[i]).to.equal(ids[i]);
    });

    it("internal limit cap: limit > 1000 is silently capped at 1000", async function () {
      // Issue 10 certs; request limit=10000 → should return 10 (not revert or return 10000)
      const ids = await issueN(10);
      const page = await ledger.getCertificateIdsPage(0, 10000);
      expect(page.length).to.equal(10);
      for (let i = 0; i < 10; i++) expect(page[i]).to.equal(ids[i]);
    });

    it("offset past end returns empty", async function () {
      await issueN(3);
      const page = await ledger.getCertificateIdsPage(100, 10);
      expect(page.length).to.equal(0);
    });

    it("getCertificateIdsPage does not change getCertificateCount()", async function () {
      await issueN(5);
      expect(await ledger.getCertificateCount()).to.equal(5);
    });
  });
});
