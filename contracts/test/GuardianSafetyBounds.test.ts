import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianInsuranceLedger, GuardianTimelock } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianSafetyBounds Validation", function () {
  let ledger: GuardianInsuranceLedger;
  let timelock: GuardianTimelock;
  let owner: SignerWithAddress;
  let proposer: SignerWithAddress;
  let deployer: SignerWithAddress;

  beforeEach(async function () {
    [owner, proposer, deployer] = await ethers.getSigners();
    
    // Deploy GuardianInsuranceLedger
    const LedgerFactory = await ethers.getContractFactory("GuardianInsuranceLedger");
    ledger = await LedgerFactory.deploy();
    await ledger.waitForDeployment();

    // Deploy GuardianTimelock
    const TimelockFactory = await ethers.getContractFactory("GuardianTimelock");
    timelock = (await TimelockFactory.deploy(
      [proposer.address],
      [ethers.ZeroAddress],
      owner.address
    )) as GuardianTimelock;
    await timelock.waitForDeployment();
  });

  it("should verify MAX_CERTIFICATES cap is set to 100,000", async function () {
    const maxCerts = await ledger.MAX_CERTIFICATES();
    expect(maxCerts).to.equal(100000n);
  });

  it("should verify MIN_DELAY constant is set to 24 hours (86,400 seconds)", async function () {
    const minDelay = await timelock.MIN_DELAY();
    expect(minDelay).to.equal(BigInt(24 * 60 * 60)); // 86400 seconds
  });

  it("should verify GuardianInsuranceLedger reverts with CertificateLimitReached custom error when cap is exceeded", async function () {
    const ledgerAddress = await ledger.getAddress();
    
    // Dynamically find the storage slot for certificateIds array length
    let arraySlot = -1;
    for (let i = 0; i < 20; i++) {
      const slotHex = ethers.toBeHex(i, 32);
      const initialVal = await ethers.provider.getStorage(ledgerAddress, slotHex);

      // Temporarily set length to 100,001
      await ethers.provider.send("hardhat_setStorageAt", [
        ledgerAddress,
        slotHex,
        ethers.toBeHex(100001, 32)
      ]);
      
      const count = await ledger.getCertificateCount();
      if (count === 100001n) {
        arraySlot = i;
        // Keep the slot set to 100,001 for the test
      } else {
        // Restore to initial value
        await ethers.provider.send("hardhat_setStorageAt", [
          ledgerAddress,
          slotHex,
          initialVal
        ]);
      }
    }

    expect(arraySlot).to.not.equal(-1, "Could not find storage slot for certificateIds length");

    // Try to issue a certificate — should revert with CertificateLimitReached
    const certId = ethers.keccak256(ethers.toUtf8Bytes("validation-cert"));
    const agentHash = ethers.keccak256(ethers.toUtf8Bytes("agent-1"));
    const certHash = ethers.keccak256(ethers.toUtf8Bytes("cert-hash"));
    const start = 1700000000;
    const end = 1700003600;

    await expect(
      ledger.issueCertificate(
        certId,
        agentHash,
        start,
        end,
        certHash,
        "LOW"
      )
    ).to.be.revertedWithCustomError(ledger, "CertificateLimitReached");
  });
});
