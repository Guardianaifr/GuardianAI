import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianRiskAttestation } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianRiskAttestation", function () {
  let attestation: GuardianRiskAttestation;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const TARGET  = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const CHAIN   = "monad";
  const SCORE   = 92;
  const GRADE   = "A";
  const SIG     = ethers.keccak256(ethers.toUtf8Bytes("signals"));

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianRiskAttestation");
    attestation = await Factory.deploy();
    await attestation.waitForDeployment();
  });

  // ── Core attest (preserved + extended) ───────────────────────────────

  describe("attest", function () {
    it("should attest a contract risk profile", async function () {
      await attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG);
      expect(await attestation.totalAttestations()).to.equal(1);
      const att = await attestation.getAttestation(TARGET, CHAIN);
      expect(att.score).to.equal(SCORE);
      expect(att.grade).to.equal(GRADE);
      expect(att.signalsHash).to.equal(SIG);
    });

    it("should revert if score is invalid (> 10000)", async function () {
      await expect(
        attestation.attest(TARGET, CHAIN, 12000, GRADE, SIG)
      ).to.be.revertedWithCustomError(attestation, "InvalidScore");
    });

    it("should revert if called by non-owner", async function () {
      await expect(
        attestation.connect(nonOwner).attest(TARGET, CHAIN, SCORE, GRADE, SIG)
      ).to.be.revertedWithCustomError(attestation, "OwnableUnauthorizedAccount");
    });
  });

  // ── RA-1: Pausable ───────────────────────────────────────────────────

  describe("Pausable (RA-1)", function () {
    it("attest() reverts when paused", async function () {
      await attestation.pause();
      await expect(
        attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG)
      ).to.be.revertedWithCustomError(attestation, "EnforcedPause");
    });

    it("non-owner cannot pause", async function () {
      await expect(
        attestation.connect(nonOwner).pause()
      ).to.be.revertedWithCustomError(attestation, "OwnableUnauthorizedAccount");
    });

    it("non-owner cannot unpause", async function () {
      await attestation.pause();
      await expect(
        attestation.connect(nonOwner).unpause()
      ).to.be.revertedWithCustomError(attestation, "OwnableUnauthorizedAccount");
    });

    it("owner can pause then unpause and attest() works again", async function () {
      await attestation.pause();
      await attestation.unpause();
      await attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG);
      expect(await attestation.totalAttestations()).to.equal(1);
    });
  });

  // ── RA-3: Grade allowlist ────────────────────────────────────────────

  describe("Grade allowlist (RA-3)", function () {
    const BOOTSTRAPPED_GRADES = ["A", "B", "C", "D", "F"];

    it("all 5 bootstrapped grades are valid", async function () {
      for (const g of BOOTSTRAPPED_GRADES) {
        expect(await attestation.isValidGrade(g)).to.be.true;
      }
    });

    it("attest() succeeds with each of the 5 bootstrapped grades", async function () {
      const target2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
      for (const [i, g] of BOOTSTRAPPED_GRADES.entries()) {
        // Use a different chain per grade to avoid overwrite (keeps totalAttestations clean)
        const chain = `chain${i}`;
        await attestation.attest(TARGET, chain, SCORE, g, SIG);
        const att = await attestation.getAttestation(TARGET, chain);
        expect(att.grade).to.equal(g);
      }
      // Verify they counted as 5 unique attestations
      expect(await attestation.totalAttestations()).to.equal(5);
    });

    it("attest() reverts with GradeNotAllowed for an unlisted grade ('A+')", async function () {
      await expect(
        attestation.attest(TARGET, CHAIN, SCORE, "A+", SIG)
      ).to.be.revertedWithCustomError(attestation, "GradeNotAllowed");
    });

    it("attest() reverts with GradeNotAllowed for junk input", async function () {
      await expect(
        attestation.attest(TARGET, CHAIN, SCORE, "junk", SIG)
      ).to.be.revertedWithCustomError(attestation, "GradeNotAllowed");
    });

    it("attest() reverts with GradeNotAllowed for empty string", async function () {
      await expect(
        attestation.attest(TARGET, CHAIN, SCORE, "", SIG)
      ).to.be.revertedWithCustomError(attestation, "GradeNotAllowed");
    });
  });

  // ── RA-3: setValidGrade ───────────────────────────────────────────────

  describe("setValidGrade (RA-3)", function () {
    it("owner can add 'A+' and then attest() with 'A+' succeeds", async function () {
      await attestation.setValidGrade("A+", true);
      expect(await attestation.isValidGrade("A+")).to.be.true;
      await attestation.attest(TARGET, CHAIN, 97, "A+", SIG);
      const att = await attestation.getAttestation(TARGET, CHAIN);
      expect(att.grade).to.equal("A+");
    });

    it("owner can revoke a bootstrapped grade ('F') and attest() then reverts", async function () {
      await attestation.setValidGrade("F", false);
      expect(await attestation.isValidGrade("F")).to.be.false;
      await expect(
        attestation.attest(TARGET, CHAIN, 10, "F", SIG)
      ).to.be.revertedWithCustomError(attestation, "GradeNotAllowed");
    });

    it("non-owner cannot call setValidGrade", async function () {
      await expect(
        attestation.connect(nonOwner).setValidGrade("A+", true)
      ).to.be.revertedWithCustomError(attestation, "OwnableUnauthorizedAccount");
    });

    it("setValidGrade reverts for empty grade string", async function () {
      await expect(
        attestation.setValidGrade("", true)
      ).to.be.revertedWithCustomError(attestation, "InvalidGradeLength");
    });

    it("setValidGrade reverts for grade string longer than 3 bytes ('AAAA')", async function () {
      await expect(
        attestation.setValidGrade("AAAA", true)
      ).to.be.revertedWithCustomError(attestation, "InvalidGradeLength");
    });

    it("setValidGrade emits ValidGradeSet event", async function () {
      await expect(attestation.setValidGrade("A+", true))
        .to.emit(attestation, "ValidGradeSet")
        .withArgs("A+", true);
    });

    it("adding all 9 canonical grades and attesting with each works", async function () {
      const canonicalGrades = ["A+", "A-", "B+", "B-"];
      for (const g of canonicalGrades) {
        await attestation.setValidGrade(g, true);
      }
      // "A", "B", "C", "D", "F" already bootstrapped — total 9 canonical grades
      const allGrades = ["A+", "A", "A-", "B+", "B", "B-", "C", "D", "F"];
      for (const [i, g] of allGrades.entries()) {
        const chain = `canonical_${i}`;
        await attestation.attest(TARGET, chain, 80, g, SIG);
        const att = await attestation.getAttestation(TARGET, chain);
        expect(att.grade).to.equal(g);
      }
    });
  });

  // ── RA-4: Distinct events for new vs. overwrite ───────────────────────

  describe("Event distinction: RiskAttested vs AttestationUpdated (RA-4)", function () {
    it("first attestation emits RiskAttested (not AttestationUpdated)", async function () {
      await expect(attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG))
        .to.emit(attestation, "RiskAttested")
        .withArgs(TARGET, CHAIN, SCORE, GRADE, SIG);
    });

    it("first attestation does NOT emit AttestationUpdated", async function () {
      const tx = await attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG);
      const receipt = await tx.wait();
      const iface = attestation.interface;
      const updatedTopic = iface.getEvent("AttestationUpdated")!.topicHash;
      const emitted = receipt!.logs.some(l => l.topics[0] === updatedTopic);
      expect(emitted).to.be.false;
    });

    it("second attestation emits AttestationUpdated (not RiskAttested)", async function () {
      await attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG);
      const newSig = ethers.keccak256(ethers.toUtf8Bytes("updated-signals"));
      await expect(attestation.attest(TARGET, CHAIN, 85, "B", newSig))
        .to.emit(attestation, "AttestationUpdated")
        .withArgs(TARGET, CHAIN, 85, "B", newSig);
    });

    it("second attestation does NOT emit RiskAttested", async function () {
      await attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG);
      const newSig = ethers.keccak256(ethers.toUtf8Bytes("updated-signals"));
      const tx = await attestation.attest(TARGET, CHAIN, 85, "B", newSig);
      const receipt = await tx.wait();
      const iface = attestation.interface;
      const attestedTopic = iface.getEvent("RiskAttested")!.topicHash;
      const emitted = receipt!.logs.some(l => l.topics[0] === attestedTopic);
      expect(emitted).to.be.false;
    });

    it("totalAttestations increments only on first attestation, not on overwrite", async function () {
      await attestation.attest(TARGET, CHAIN, SCORE, GRADE, SIG);
      expect(await attestation.totalAttestations()).to.equal(1);
      // Overwrite
      await attestation.attest(TARGET, CHAIN, 80, "B", SIG);
      // Still 1, not 2
      expect(await attestation.totalAttestations()).to.equal(1);
    });

    it("overwrite stores the new score and grade", async function () {
      await attestation.attest(TARGET, CHAIN, SCORE, "A", SIG);
      const newSig = ethers.keccak256(ethers.toUtf8Bytes("v2"));
      await attestation.attest(TARGET, CHAIN, 75, "B", newSig);
      const att = await attestation.getAttestation(TARGET, CHAIN);
      expect(att.score).to.equal(75);
      expect(att.grade).to.equal("B");
      expect(att.signalsHash).to.equal(newSig);
    });
  });

  // ── getAttestation ────────────────────────────────────────────────────

  describe("getAttestation", function () {
    it("reverts with AttestationNotFound for unattest contract", async function () {
      await expect(
        attestation.getAttestation(TARGET, CHAIN)
      ).to.be.revertedWithCustomError(attestation, "AttestationNotFound");
    });
  });
});
