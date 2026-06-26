import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianRiskAttestation } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianRiskAttestation", function () {
  let attestation: GuardianRiskAttestation;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;

  const TARGET_CONTRACT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const CHAIN = "monad";
  const SCORE = 92;
  const GRADE = "A";
  const SIGNALS_HASH = ethers.keccak256(ethers.toUtf8Bytes("signals"));

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("GuardianRiskAttestation");
    attestation = await Factory.deploy();
    await attestation.waitForDeployment();
  });

  describe("attest", function () {
    it("should attest a contract risk profile", async function () {
      await attestation.attest(TARGET_CONTRACT, CHAIN, SCORE, GRADE, SIGNALS_HASH);
      expect(await attestation.totalAttestations()).to.equal(1);

      const att = await attestation.getAttestation(TARGET_CONTRACT, CHAIN);
      expect(att.score).to.equal(SCORE);
      expect(att.grade).to.equal(GRADE);
      expect(att.signalsHash).to.equal(SIGNALS_HASH);
    });

    it("should revert if score is invalid (> 10000)", async function () {
      await expect(
        attestation.attest(TARGET_CONTRACT, CHAIN, 12000, GRADE, SIGNALS_HASH)
      ).to.be.revertedWithCustomError(attestation, "InvalidScore");
    });

    it("should revert if called by non-owner", async function () {
      await expect(
        attestation.connect(nonOwner).attest(TARGET_CONTRACT, CHAIN, SCORE, GRADE, SIGNALS_HASH)
      ).to.be.revertedWithCustomError(attestation, "OwnableUnauthorizedAccount");
    });
  });
});
