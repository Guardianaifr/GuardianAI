import { expect } from "chai";
import { ethers } from "hardhat";
import { 
  GuardianRiskAttestation, 
  GuardianThreatFeedRegistry,
  GuardianProtectedVault,
  MockERC20 
} from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianCircuitBreaker", function () {
  let riskAttestation: GuardianRiskAttestation;
  let threatFeed: GuardianThreatFeedRegistry;
  let vault: GuardianProtectedVault;
  let mockToken: MockERC20;
  
  let owner: SignerWithAddress;
  let user1: SignerWithAddress;
  let user2: SignerWithAddress;
  let maliciousUser: SignerWithAddress;

  const DEPOSIT_AMOUNT = ethers.parseUnits("100", 18);
  const CHAIN = "monad";
  const SIG = ethers.keccak256(ethers.toUtf8Bytes("signals"));

  beforeEach(async function () {
    [owner, user1, user2, maliciousUser] = await ethers.getSigners();

    // Deploy Mock ERC20
    const MockERC20Factory = await ethers.getContractFactory("MockERC20");
    mockToken = await MockERC20Factory.deploy();
    await mockToken.waitForDeployment();

    // Deploy Risk Attestation
    const RiskFactory = await ethers.getContractFactory("GuardianRiskAttestation");
    riskAttestation = await RiskFactory.deploy();
    await riskAttestation.waitForDeployment();

    // Deploy Threat Feed
    const ThreatFeedFactory = await ethers.getContractFactory("GuardianThreatFeedRegistry");
    threatFeed = await ThreatFeedFactory.deploy();
    await threatFeed.waitForDeployment();

    // Deploy Vault
    const VaultFactory = await ethers.getContractFactory("GuardianProtectedVault");
    vault = await VaultFactory.deploy(
      await mockToken.getAddress(),
      await riskAttestation.getAddress(),
      await threatFeed.getAddress()
    );
    await vault.waitForDeployment();

    // Setup: Mint tokens to users and approve vault
    await mockToken.mint(user1.address, DEPOSIT_AMOUNT * 10n);
    await mockToken.connect(user1).approve(await vault.getAddress(), DEPOSIT_AMOUNT * 10n);

    await mockToken.mint(user2.address, DEPOSIT_AMOUNT * 10n);
    await mockToken.connect(user2).approve(await vault.getAddress(), DEPOSIT_AMOUNT * 10n);

    await mockToken.mint(maliciousUser.address, DEPOSIT_AMOUNT * 10n);
    await mockToken.connect(maliciousUser).approve(await vault.getAddress(), DEPOSIT_AMOUNT * 10n);
    
    // Add malicious user to threat feed
    await threatFeed.addAddress(maliciousUser.address, "Phishing");
  });

  // 1. Normal operation with guardianProtected (fail-open when no attestation)
  it("guardianProtected allows execution if no attestation exists (fail-open)", async function () {
    // Vault has no attestation. user1 is not malicious.
    await expect(vault.connect(user1).deposit(DEPOSIT_AMOUNT))
      .to.emit(vault, "Deposited")
      .withArgs(user1.address, DEPOSIT_AMOUNT);
  });

  // 2. Normal operation with guardianProtected but user is malicious (revert)
  it("guardianProtected reverts if caller is malicious", async function () {
    await expect(vault.connect(maliciousUser).deposit(DEPOSIT_AMOUNT))
      .to.be.revertedWithCustomError(vault, "CallerFlaggedMalicious")
      .withArgs(maliciousUser.address);
  });

  // 3. Normal operation with guardianProtected but score is too low (revert)
  it("guardianProtected reverts if contract score < threshold", async function () {
    const vaultAddress = await vault.getAddress();
    // Attest vault with score 5000 (< 6000 threshold)
    await riskAttestation.attest(vaultAddress, CHAIN, 5000, "F", SIG);

    await expect(vault.connect(user1).deposit(DEPOSIT_AMOUNT))
      .to.be.revertedWithCustomError(vault, "ContractRiskTooHigh")
      .withArgs(5000, 6000);
  });

  // Success case for guardianProtected when score >= threshold
  it("guardianProtected allows execution if score >= threshold and caller not malicious", async function () {
    const vaultAddress = await vault.getAddress();
    // Attest vault with score 8000 (>= 6000 threshold)
    await riskAttestation.attest(vaultAddress, CHAIN, 8000, "B", SIG);

    await expect(vault.connect(user1).deposit(DEPOSIT_AMOUNT))
      .to.emit(vault, "Deposited")
      .withArgs(user1.address, DEPOSIT_AMOUNT);
  });

  // 4. Normal operation with guardianProtected Strict (fail-closed when no attestation) -> revert
  it("guardianProtectedStrict reverts if no attestation exists (fail-closed)", async function () {
    // Note: getAttestation on GuardianRiskAttestation reverts with AttestationNotFound if no attestation exists
    await expect(vault.connect(owner).emergencyWithdraw())
      .to.be.revertedWithCustomError(riskAttestation, "AttestationNotFound");
  });

  // 5. Strict with attestation (pass)
  it("guardianProtectedStrict allows execution if score >= threshold and caller not malicious", async function () {
    // Deposit some funds first using fail-open
    await vault.connect(user1).deposit(DEPOSIT_AMOUNT);

    const vaultAddress = await vault.getAddress();
    // Attest vault with score 8000 (>= 6000 threshold)
    await riskAttestation.attest(vaultAddress, CHAIN, 8000, "B", SIG);

    await expect(vault.connect(owner).emergencyWithdraw())
      .to.emit(vault, "EmergencyWithdrawn")
      .withArgs(owner.address, DEPOSIT_AMOUNT);
  });

  // 6. Strict with malicious user (revert)
  it("guardianProtectedStrict reverts if caller is malicious", async function () {
    // Transfer ownership to malicious user to test emergencyWithdraw
    await vault.transferOwnership(maliciousUser.address);
    await vault.connect(maliciousUser).acceptOwnership();

    await expect(vault.connect(maliciousUser).emergencyWithdraw())
      .to.be.revertedWithCustomError(vault, "CallerFlaggedMalicious")
      .withArgs(maliciousUser.address);
  });

  // 7. Strict with low score (revert)
  it("guardianProtectedStrict reverts if contract score < threshold", async function () {
    const vaultAddress = await vault.getAddress();
    // Attest vault with score 5000 (< 6000 threshold)
    await riskAttestation.attest(vaultAddress, CHAIN, 5000, "F", SIG);

    await expect(vault.connect(owner).emergencyWithdraw())
      .to.be.revertedWithCustomError(vault, "ContractRiskTooHigh")
      .withArgs(5000, 6000);
  });

  // 8. Admin functions (toggle active, set threshold, transfer admin)
  it("admin functions revert for non-admin and work for admin", async function () {
    // Non-admin tests
    await expect(vault.connect(user1).setCircuitBreakerActive(false))
      .to.be.revertedWithCustomError(vault, "NotCircuitBreakerAdmin");

    await expect(vault.connect(user1).setRiskScoreThreshold(5000))
      .to.be.revertedWithCustomError(vault, "NotCircuitBreakerAdmin");

    await expect(vault.connect(user1).transferCircuitBreakerAdmin(user1.address))
      .to.be.revertedWithCustomError(vault, "NotCircuitBreakerAdmin");

    // Admin tests
    await expect(vault.connect(owner).setCircuitBreakerActive(false))
      .to.emit(vault, "CircuitBreakerToggled")
      .withArgs(false);
    expect(await vault.circuitBreakerActive()).to.be.false;

    await expect(vault.connect(owner).setRiskScoreThreshold(7000))
      .to.emit(vault, "RiskThresholdUpdated")
      .withArgs(6000, 7000);
    expect(await vault.riskScoreThreshold()).to.equal(7000);

    await expect(vault.connect(owner).transferCircuitBreakerAdmin(user1.address))
      .to.emit(vault, "CircuitBreakerAdminTransferred")
      .withArgs(owner.address, user1.address);
    expect(await vault.circuitBreakerAdmin()).to.equal(user1.address);
  });

  // 9. Pausing (vault logic)
  it("pausing prevents operations", async function () {
    await vault.connect(owner).pause();
    
    await expect(vault.connect(user1).deposit(DEPOSIT_AMOUNT))
      .to.be.revertedWithCustomError(vault, "EnforcedPause");
      
    await vault.connect(owner).unpause();
    
    await expect(vault.connect(user1).deposit(DEPOSIT_AMOUNT))
      .to.emit(vault, "Deposited");
  });

  // 10. Toggling circuit breaker active off bypasses checks
  it("toggling circuit breaker active off bypasses checks", async function () {
    await vault.connect(owner).setCircuitBreakerActive(false);

    // Malicious user should be able to deposit
    await expect(vault.connect(maliciousUser).deposit(DEPOSIT_AMOUNT))
      .to.emit(vault, "Deposited")
      .withArgs(maliciousUser.address, DEPOSIT_AMOUNT);

    const vaultAddress = await vault.getAddress();
    // Vault with low score
    await riskAttestation.attest(vaultAddress, CHAIN, 5000, "F", SIG);

    // emergencyWithdraw (strict) should also work without reverting for AttestationNotFound or ContractRiskTooHigh
    await expect(vault.connect(owner).emergencyWithdraw())
      .to.emit(vault, "EmergencyWithdrawn");
  });
});
