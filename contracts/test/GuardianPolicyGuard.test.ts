import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianPolicyGuard, MockTargetContract } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianPolicyGuard", function () {
  let policyGuard: GuardianPolicyGuard;
  let mockTarget: MockTargetContract;
  let owner: SignerWithAddress;
  let attestationSigner: SignerWithAddress;
  let unauthorizedSigner: SignerWithAddress;
  let user: SignerWithAddress;

  const AGENT_A = ethers.keccak256(ethers.toUtf8Bytes("agent-monad-001"));
  const AGENT_B = ethers.keccak256(ethers.toUtf8Bytes("agent-monad-002"));

  async function getDomain() {
    const network = await ethers.provider.getNetwork();
    return {
      name: "GuardianPolicyGuard",
      version: "1",
      chainId: network.chainId,
      verifyingContract: await policyGuard.getAddress(),
    };
  }

  const types = {
    SafetyAttestation: [
      { name: "agentId", type: "bytes32" },
      { name: "targetContract", type: "address" },
      { name: "calldataHash", type: "bytes32" },
      { name: "value", type: "uint256" },
      { name: "riskScore", type: "uint8" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  async function createAttestation(overrides: Partial<{
    agentId: string;
    targetContract: string;
    calldataHash: string;
    value: bigint;
    riskScore: number;
    nonce: bigint;
    deadline: number;
  }> = {}) {
    const latestBlock = await ethers.provider.getBlock("latest");
    const now = latestBlock ? latestBlock.timestamp : Math.floor(Date.now() / 1000);

    return {
      agentId: overrides.agentId ?? AGENT_A,
      targetContract: overrides.targetContract ?? (await mockTarget.getAddress()),
      calldataHash: overrides.calldataHash ?? ethers.keccak256("0x"),
      value: overrides.value ?? 0n,
      riskScore: overrides.riskScore ?? 10,
      nonce: overrides.nonce ?? 1n,
      deadline: overrides.deadline ?? now + 3600,
    };
  }

  async function signAttestation(attestation: any, signer: SignerWithAddress = attestationSigner) {
    const domain = await getDomain();
    return await signer.signTypedData(domain, types, attestation);
  }

  beforeEach(async function () {
    [owner, attestationSigner, unauthorizedSigner, user] = await ethers.getSigners();

    const MockFactory = await ethers.getContractFactory("MockTargetContract");
    mockTarget = await MockFactory.deploy();
    await mockTarget.waitForDeployment();

    const GuardFactory = await ethers.getContractFactory("GuardianPolicyGuard");
    policyGuard = await GuardFactory.deploy(attestationSigner.address);
    await policyGuard.waitForDeployment();
  });

  describe("Group 1: Deployment & Configuration", function () {
    it("should deploy with the correct attestation signer", async function () {
      expect(await policyGuard.attestationSigner()).to.equal(attestationSigner.address);
      expect(await policyGuard.maxAllowedRiskScore()).to.equal(25);
    });

    it("should revert deployment if signer is address(0) (Audit M-01-R2)", async function () {
      const GuardFactory = await ethers.getContractFactory("GuardianPolicyGuard");
      await expect(GuardFactory.deploy(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(policyGuard, "InvalidSignerAddress");
    });
  });

  describe("Group 2: Happy Path Execution", function () {
    it("should execute target function with riskScore = 0 (L-04-R2 Boundary)", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [42]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        riskScore: 0,
        nonce: 100n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature)
      ).to.emit(policyGuard, "ActionExecutedWithAttestation")
        .withArgs(attestation.agentId, targetAddress, 0, 100n);

      expect(await mockTarget.counter()).to.equal(42);
    });

    it("should execute target function with riskScore = 25 (Exact Max Threshold)", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [10]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        riskScore: 25,
        nonce: 101n,
      });
      const signature = await signAttestation(attestation);

      await policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature);
      expect(await mockTarget.counter()).to.equal(10);
    });

    it("should forward msg.value to payable target function (L-04-R2 Value Forwarding)", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomethingPayable");
      const calldataHash = ethers.keccak256(callData);
      const sendValue = ethers.parseEther("1.5");

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        value: sendValue,
        nonce: 102n,
      });
      const signature = await signAttestation(attestation);

      await policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature, {
        value: sendValue,
      });

      expect(await mockTarget.getBalance()).to.equal(sendValue);
      expect(await mockTarget.counter()).to.equal(1);
    });
  });

  describe("Group 3: Security & Invariant Rejections", function () {
    it("should revert AttestationExpired when current timestamp > deadline", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const latestBlock = await ethers.provider.getBlock("latest");
      const pastDeadline = (latestBlock ? latestBlock.timestamp : 1000) - 100;

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        deadline: pastDeadline,
        nonce: 201n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "AttestationExpired");
    });

    it("should revert RiskScoreExceedsThreshold when riskScore = 26", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        riskScore: 26,
        nonce: 202n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "RiskScoreExceedsThreshold")
        .withArgs(26, 25);
    });

    it("should revert NonceAlreadyUsed on replay attack", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        nonce: 203n,
      });
      const signature = await signAttestation(attestation);

      // First execution succeeds
      await policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature);

      // Replay fails
      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "NonceAlreadyUsed")
        .withArgs(attestation.agentId, 203n);
    });

    it("should revert InvalidAttestationSignature when signed with unauthorized key", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        nonce: 204n,
      });
      const badSignature = await signAttestation(attestation, unauthorizedSigner);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, badSignature)
      ).to.be.revertedWithCustomError(policyGuard, "InvalidAttestationSignature");
    });

    it("should revert CalldataHashMismatch when calldata is tampered", async function () {
      const targetAddress = await mockTarget.getAddress();
      const originalCallData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const tamperedCallData = mockTarget.interface.encodeFunctionData("doSomething", [999]);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash: ethers.keccak256(originalCallData),
        nonce: 205n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, tamperedCallData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "CalldataHashMismatch");
    });

    it("should revert TargetMismatch when target differs from signed targetContract", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        nonce: 206n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(user.address, callData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "TargetMismatch")
        .withArgs(targetAddress, user.address);
    });

    it("should revert ValueMismatch if msg.value != attestation.value (Audit M-01)", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        value: ethers.parseEther("1.0"),
        nonce: 207n,
      });
      const signature = await signAttestation(attestation);

      // Sending 0 instead of 1.0
      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature, { value: 0n })
      ).to.be.revertedWithCustomError(policyGuard, "ValueMismatch")
        .withArgs(ethers.parseEther("1.0"), 0n);
    });

    it("should revert SelfCallProhibited if target is policyGuard itself (Audit M-02)", async function () {
      const guardAddress = await policyGuard.getAddress();
      const callData = policyGuard.interface.encodeFunctionData("pause");
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: guardAddress,
        calldataHash,
        nonce: 208n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(guardAddress, callData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "SelfCallProhibited");
    });

    it("should revert InvalidTargetAddress if target is address(0) (Audit M-02)", async function () {
      const callData = "0x";
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: ethers.ZeroAddress,
        calldataHash,
        nonce: 209n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(ethers.ZeroAddress, callData, attestation, signature)
      ).to.be.revertedWithCustomError(policyGuard, "InvalidTargetAddress");
    });
  });

  describe("Group 4: Transparency & Error Bubbling (Audit L-01)", function () {
    it("should bubble up revert string from target call", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("alwaysReverts", ["Target: Custom Revert Message"]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        nonce: 301n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature)
      ).to.be.revertedWith("Target: Custom Revert Message");
    });

    it("should bubble up custom error from target call", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("customErrorReverts", [404]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        nonce: 302n,
      });
      const signature = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, signature)
      ).to.be.revertedWithCustomError(mockTarget, "MockTargetCustomError")
        .withArgs(404);
    });
  });

  describe("Group 5: Parallel Agent Isolation", function () {
    it("should allow Agent A and Agent B to use the exact same nonce independently", async function () {
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      // Agent A uses nonce 1
      const attestationA = await createAttestation({
        agentId: AGENT_A,
        targetContract: targetAddress,
        calldataHash,
        nonce: 1n,
      });
      const signatureA = await signAttestation(attestationA);

      await policyGuard.executeWithAttestation(targetAddress, callData, attestationA, signatureA);
      expect(await policyGuard.usedNonces(AGENT_A, 1n)).to.be.true;
      expect(await policyGuard.usedNonces(AGENT_B, 1n)).to.be.false;

      // Agent B ALSO uses nonce 1 (No collision!)
      const attestationB = await createAttestation({
        agentId: AGENT_B,
        targetContract: targetAddress,
        calldataHash,
        nonce: 1n,
      });
      const signatureB = await signAttestation(attestationB);

      await policyGuard.executeWithAttestation(targetAddress, callData, attestationB, signatureB);
      expect(await policyGuard.usedNonces(AGENT_B, 1n)).to.be.true;
      expect(await mockTarget.counter()).to.equal(2);
    });
  });

  describe("Group 6: Admin Controls & Recovery", function () {
    it("should rotate attestation signer and reject old signer signatures", async function () {
      await expect(policyGuard.setAttestationSigner(unauthorizedSigner.address))
        .to.emit(policyGuard, "AttestationSignerUpdated")
        .withArgs(attestationSigner.address, unauthorizedSigner.address);

      expect(await policyGuard.attestationSigner()).to.equal(unauthorizedSigner.address);

      // Sign with old signer -> should revert
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);
      const attestation = await createAttestation({ targetContract: targetAddress, calldataHash, nonce: 501n });
      const oldSig = await signAttestation(attestation, attestationSigner);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, oldSig)
      ).to.be.revertedWithCustomError(policyGuard, "InvalidAttestationSignature");

      // Sign with new signer -> should succeed
      const newSig = await signAttestation(attestation, unauthorizedSigner);
      await policyGuard.executeWithAttestation(targetAddress, callData, attestation, newSig);
      expect(await mockTarget.counter()).to.equal(1);
    });

    it("should revert setAttestationSigner if newSigner is address(0) (Audit L-02-R2)", async function () {
      await expect(policyGuard.setAttestationSigner(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(policyGuard, "InvalidSignerAddress");
    });

    it("should update maxAllowedRiskScore and allow higher risk if configured", async function () {
      await expect(policyGuard.setMaxAllowedRiskScore(50))
        .to.emit(policyGuard, "MaxAllowedRiskScoreUpdated")
        .withArgs(25, 50);

      expect(await policyGuard.maxAllowedRiskScore()).to.equal(50);

      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);

      const attestation = await createAttestation({
        targetContract: targetAddress,
        calldataHash,
        riskScore: 40, // Previously rejected (40 > 25), now accepted (40 <= 50)
        nonce: 502n,
      });
      const sig = await signAttestation(attestation);

      await policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig);
      expect(await mockTarget.counter()).to.equal(1);
    });

    it("should enforce pause / unpause controls", async function () {
      await policyGuard.pause();

      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [1]);
      const calldataHash = ethers.keccak256(callData);
      const attestation = await createAttestation({ targetContract: targetAddress, calldataHash, nonce: 503n });
      const sig = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)
      ).to.be.revertedWithCustomError(policyGuard, "EnforcedPause");

      await policyGuard.unpause();
      await policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig);
      expect(await mockTarget.counter()).to.equal(1);
    });

    it("should allow sweepETH by owner and transfer stuck balance (Audit L-03-R2)", async function () {
      const guardAddress = await policyGuard.getAddress();
      const sweepAmount = ethers.parseEther("2.5");

      // Force balance onto the contract via hardhat_setBalance
      await ethers.provider.send("hardhat_setBalance", [
        guardAddress,
        "0x" + sweepAmount.toString(16),
      ]);
      expect(await ethers.provider.getBalance(guardAddress)).to.equal(sweepAmount);

      const recipientBefore = await ethers.provider.getBalance(user.address);
      await policyGuard.sweepETH(user.address);
      const recipientAfter = await ethers.provider.getBalance(user.address);

      expect(await ethers.provider.getBalance(guardAddress)).to.equal(0n);
      expect(recipientAfter - recipientBefore).to.equal(sweepAmount);
    });

    it("should revert sweepETH if called by non-owner or if recipient is address(0)", async function () {
      await expect(
        policyGuard.connect(user).sweepETH(user.address)
      ).to.be.revertedWithCustomError(policyGuard, "OwnableUnauthorizedAccount");

      await expect(
        policyGuard.sweepETH(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(policyGuard, "InvalidTargetAddress");
    });
  });

  describe("Group 7: Monad Track 04 Protocol Primitives", function () {
    it("should allow owner to set passport registry and emit event", async function () {
      const dummyRegistry = ethers.Wallet.createRandom().address;
      await expect(policyGuard.setPassportRegistry(dummyRegistry))
        .to.emit(policyGuard, "PassportRegistryUpdated")
        .withArgs(ethers.ZeroAddress, dummyRegistry);
      expect(await policyGuard.passportRegistry()).to.equal(dummyRegistry);
    });

    it("should revert setPassportRegistry if called by non-owner", async function () {
      await expect(
        policyGuard.connect(user).setPassportRegistry(user.address)
      ).to.be.revertedWithCustomError(policyGuard, "OwnableUnauthorizedAccount");
    });

    it("should allow execution when passportRegistry is address(0) (backward compatibility)", async function () {
      expect(await policyGuard.passportRegistry()).to.equal(ethers.ZeroAddress);
      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [100]);
      const calldataHash = ethers.keccak256(callData);
      const attestation = await createAttestation({ targetContract: targetAddress, calldataHash, nonce: 7001n });
      const sig = await signAttestation(attestation);

      await expect(policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)).to.not.be.reverted;
    });

    it("should validate active passport and execute when passport is active", async function () {
      const PassportFactory = await ethers.getContractFactory("GuardianPassportSBT");
      const passport = await PassportFactory.deploy();
      await passport.waitForDeployment();

      await policyGuard.setPassportRegistry(await passport.getAddress());

      // Mint passport for AGENT_A
      await passport.mint(user.address, AGENT_A, 9000n, "ipfs://QmAgentPassport01");
      expect(await passport.isPassportActive(AGENT_A)).to.be.true;

      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [200]);
      const calldataHash = ethers.keccak256(callData);
      const attestation = await createAttestation({ agentId: AGENT_A, targetContract: targetAddress, calldataHash, nonce: 7002n });
      const sig = await signAttestation(attestation);

      await expect(policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)).to.not.be.reverted;
    });

    it("should revert PassportRevokedOrInactive if agent has no passport", async function () {
      const PassportFactory = await ethers.getContractFactory("GuardianPassportSBT");
      const passport = await PassportFactory.deploy();
      await passport.waitForDeployment();

      await policyGuard.setPassportRegistry(await passport.getAddress());

      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [300]);
      const calldataHash = ethers.keccak256(callData);
      // AGENT_B has no passport
      const attestation = await createAttestation({ agentId: AGENT_B, targetContract: targetAddress, calldataHash, nonce: 7003n });
      const sig = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)
      ).to.be.revertedWithCustomError(policyGuard, "PassportRevokedOrInactive")
        .withArgs(AGENT_B);
    });

    it("should revert PassportRevokedOrInactive if agent passport was revoked", async function () {
      const PassportFactory = await ethers.getContractFactory("GuardianPassportSBT");
      const passport = await PassportFactory.deploy();
      await passport.waitForDeployment();

      await policyGuard.setPassportRegistry(await passport.getAddress());

      // Mint then revoke for AGENT_A
      await passport.mint(user.address, AGENT_A, 8500n, "ipfs://QmAgentPassport01");
      const tokenId = await passport.getAgentTokenId(AGENT_A);
      await passport.revoke(tokenId);

      expect(await passport.isPassportActive(AGENT_A)).to.be.false;

      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [400]);
      const calldataHash = ethers.keccak256(callData);
      const attestation = await createAttestation({ agentId: AGENT_A, targetContract: targetAddress, calldataHash, nonce: 7004n });
      const sig = await signAttestation(attestation);

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)
      ).to.be.revertedWithCustomError(policyGuard, "PassportRevokedOrInactive")
        .withArgs(AGENT_A);
    });

    it("should expose RIP7212_P256_PRECOMPILE constant and verifyP256Signature helper (fail-closed on non-precompile EVM)", async function () {
      expect(await policyGuard.RIP7212_P256_PRECOMPILE()).to.equal("0x0000000000000000000000000000000000000100");
      const dummyHash = ethers.keccak256(ethers.toUtf8Bytes("hello monad"));
      const r = ethers.ZeroHash;
      const s = ethers.ZeroHash;
      const qx = ethers.ZeroHash;
      const qy = ethers.ZeroHash;

      // 1. bytes32 signature call fails closed gracefully
      const isValid = await policyGuard["verifyP256Signature(bytes32,bytes32,bytes32,bytes32,bytes32)"](dummyHash, r, s, qx, qy);
      expect(isValid).to.be.false;

      // 2. uint256 overload signature call fails closed gracefully
      const isValidUint = await policyGuard["verifyP256Signature(bytes32,uint256,uint256,uint256,uint256)"](dummyHash, 0n, 0n, 0n, 0n);
      expect(isValidUint).to.be.false;
    });

    it("should revert PassportRevokedOrInactive when passport registry is paused and succeed once unpaused", async function () {
      const PassportFactory = await ethers.getContractFactory("GuardianPassportSBT");
      const passport = await PassportFactory.deploy();
      await passport.waitForDeployment();

      await policyGuard.setPassportRegistry(await passport.getAddress());
      await passport.mint(user.address, AGENT_A, 9000n, "ipfs://QmAgentPassport01");

      const targetAddress = await mockTarget.getAddress();
      const callData = mockTarget.interface.encodeFunctionData("doSomething", [500]);
      const calldataHash = ethers.keccak256(callData);
      const attestation = await createAttestation({ agentId: AGENT_A, targetContract: targetAddress, calldataHash, nonce: 7005n });
      const sig = await signAttestation(attestation);

      // Pause passport registry -> isPassportActive returns false -> execution reverts
      await passport.pause();
      expect(await passport.isPassportActive(AGENT_A)).to.be.false;

      await expect(
        policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)
      ).to.be.revertedWithCustomError(policyGuard, "PassportRevokedOrInactive")
        .withArgs(AGENT_A);

      // Unpause passport registry -> isPassportActive returns true -> execution succeeds
      await passport.unpause();
      expect(await passport.isPassportActive(AGENT_A)).to.be.true;

      await expect(policyGuard.executeWithAttestation(targetAddress, callData, attestation, sig)).to.not.be.reverted;
    });
  });
});