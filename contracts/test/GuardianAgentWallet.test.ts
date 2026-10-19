import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

const AGENT = ethers.keccak256(ethers.toUtf8Bytes("privy-agent:demo"));
const OTHER_AGENT = ethers.keccak256(ethers.toUtf8Bytes("some-other-agent"));

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

describe("GuardianAgentWallet", function () {
  let owner: SignerWithAddress, operator: SignerWithAddress, guardian: SignerWithAddress;
  let attacker: SignerWithAddress, payee: SignerWithAddress;
  let wallet: any, token: any, target: any, passport: any;
  let nonce = 1n;

  async function domainFor(addr: string) {
    const { chainId } = await ethers.provider.getNetwork();
    return { name: "GuardianAgentWallet", version: "1", chainId, verifyingContract: addr };
  }

  async function approve(to: string, data: string, value = 0n, o: Partial<any> = {}, signer = guardian, walletAddr?: string) {
    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    const att = {
      agentId: o.agentId ?? AGENT,
      targetContract: o.targetContract ?? to,
      calldataHash: o.calldataHash ?? ethers.keccak256(data),
      value: o.value ?? value,
      riskScore: o.riskScore ?? 10,
      nonce: o.nonce ?? nonce++,
      deadline: o.deadline ?? now + 300,
    };
    const sig = await signer.signTypedData(await domainFor(walletAddr ?? (await wallet.getAddress())), types, att);
    return { att, sig };
  }

  const transferData = (to: string, amt: bigint) => token.interface.encodeFunctionData("transfer", [to, amt]);

  beforeEach(async function () {
    [owner, operator, guardian, attacker, payee] = await ethers.getSigners();
    token = await (await ethers.getContractFactory("MockERC20")).deploy();
    target = await (await ethers.getContractFactory("MockTargetContract")).deploy();
    passport = await (await ethers.getContractFactory("MockPassportRegistry")).deploy();
    await passport.setActive(AGENT, true);
    wallet = await (await ethers.getContractFactory("GuardianAgentWallet")).deploy(
      owner.address, operator.address, guardian.address, AGENT, await passport.getAddress(),
    );
    await token.mint(await wallet.getAddress(), ethers.parseUnits("100", 18));
    await owner.sendTransaction({ to: await wallet.getAddress(), value: ethers.parseEther("1") });
  });

  describe("Deployment", function () {
    it("stores owner, operator, signer, agentId, registry and default threshold", async function () {
      expect(await wallet.owner()).to.equal(owner.address);
      expect(await wallet.operator()).to.equal(operator.address);
      expect(await wallet.guardianSigner()).to.equal(guardian.address);
      expect(await wallet.agentId()).to.equal(AGENT);
      expect(await wallet.passportRegistry()).to.equal(await passport.getAddress());
      expect(await wallet.maxAllowedRiskScore()).to.equal(25);
    });
    it("rejects a zero operator or zero signer", async function () {
      const F = await ethers.getContractFactory("GuardianAgentWallet");
      await expect(F.deploy(owner.address, ethers.ZeroAddress, guardian.address, AGENT, ethers.ZeroAddress))
        .to.be.revertedWithCustomError(wallet, "ZeroAddress");
      await expect(F.deploy(owner.address, operator.address, ethers.ZeroAddress, AGENT, ethers.ZeroAddress))
        .to.be.revertedWithCustomError(wallet, "ZeroAddress");
    });
    it("EIP-712 domain separator matches ethers (and so the Python relay's shared digest vector)", async function () {
      const d = await domainFor(await wallet.getAddress());
      expect(await wallet.domainSeparator()).to.equal(ethers.TypedDataEncoder.hashDomain(d));
    });
    it("emits Deposited when it receives MON", async function () {
      await expect(attacker.sendTransaction({ to: await wallet.getAddress(), value: 5n }))
        .to.emit(wallet, "Deposited").withArgs(attacker.address, 5n);
    });
  });

  describe("Approved actions execute", function () {
    it("ERC-20 transfer with a GuardianAI approval moves the wallet's own tokens", async function () {
      const data = transferData(payee.address, 7n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.emit(wallet, "Executed").withArgs(att.nonce, await token.getAddress(), 0, 10, ethers.keccak256(data));
      expect(await token.balanceOf(payee.address)).to.equal(7n);
    });
    it("plain MON transfer to an EOA with empty calldata", async function () {
      const amt = ethers.parseEther("0.1");
      const { att, sig } = await approve(payee.address, "0x", amt);
      await expect(wallet.connect(operator).execute(payee.address, amt, "0x", att, sig))
        .to.changeEtherBalances([wallet, payee], [-amt, amt]);
    });
    it("payable contract call spends the wallet's balance, not the operator's", async function () {
      const data = target.interface.encodeFunctionData("doSomethingPayable");
      const { att, sig } = await approve(await target.getAddress(), data, 123n);
      await expect(wallet.connect(operator).execute(await target.getAddress(), 123n, data, att, sig))
        .to.changeEtherBalances([wallet, operator], [-123n, 0n]);
      expect(await target.lastReceivedValue()).to.equal(123n);
    });
    it("bubbles up the target's revert reason", async function () {
      const data = target.interface.encodeFunctionData("alwaysReverts", ["nope"]);
      const { att, sig } = await approve(await target.getAddress(), data);
      await expect(wallet.connect(operator).execute(await target.getAddress(), 0, data, att, sig)).to.be.revertedWith("nope");
    });
  });

  describe("Bypass attempts are refused by the chain", function () {
    it("agent skips GuardianAI and self-signs an approval: InvalidAttestationSignature", async function () {
      const data = transferData(attacker.address, ethers.parseUnits("100", 18));
      const { att, sig } = await approve(await token.getAddress(), data, 0n, {}, operator);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "InvalidAttestationSignature");
      expect(await token.balanceOf(attacker.address)).to.equal(0n);
    });
    it("stolen GuardianAI signer key alone cannot move funds: NotOperator", async function () {
      const data = transferData(attacker.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(attacker).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "NotOperator");
      await expect(wallet.connect(guardian).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "NotOperator");
    });
    it("approval for a small payment cannot be swapped for a drain: CalldataHashMismatch", async function () {
      const small = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), small);
      const drain = transferData(attacker.address, ethers.parseUnits("100", 18));
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, drain, att, sig))
        .to.be.revertedWithCustomError(wallet, "CalldataHashMismatch");
    });
    it("approval for another wallet (EIP-712 domain) is useless here", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data, 0n, {}, guardian, attacker.address);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "InvalidAttestationSignature");
    });
    it("approval issued under a different agent's rules: AgentMismatch", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data, 0n, { agentId: OTHER_AGENT });
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "AgentMismatch");
    });
    it("target and value must match the approval", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await target.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "TargetMismatch");
      await expect(wallet.connect(operator).execute(await token.getAddress(), 1, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "ValueMismatch");
    });
    it("replayed approval: NonceAlreadyUsed", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "NonceAlreadyUsed");
    });
    it("expired approval: AttestationExpired", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await time.increase(301);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "AttestationExpired");
    });
    it("high-risk approval: RiskScoreExceedsThreshold", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data, 0n, { riskScore: 26 });
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "RiskScoreExceedsThreshold");
    });
    it("revoked ID card freezes the wallet: PassportRevokedOrInactive", async function () {
      await passport.setActive(AGENT, false);
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "PassportRevokedOrInactive");
    });
    it("calldata to an address with no code, or to the wallet itself: InvalidTarget", async function () {
      const data = transferData(payee.address, 1n);
      const a1 = await approve(payee.address, data);
      await expect(wallet.connect(operator).execute(payee.address, 0, data, a1.att, a1.sig))
        .to.be.revertedWithCustomError(wallet, "InvalidTarget");
      const self = wallet.interface.encodeFunctionData("setOperator", [attacker.address]);
      const a2 = await approve(await wallet.getAddress(), self);
      await expect(wallet.connect(operator).execute(await wallet.getAddress(), 0, self, a2.att, a2.sig))
        .to.be.revertedWithCustomError(wallet, "InvalidTarget");
    });
    it("cancelled nonce can never be used", async function () {
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).cancelNonce(att.nonce)).to.emit(wallet, "NonceCancelled");
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "NonceAlreadyUsed");
      await expect(wallet.connect(attacker).cancelNonce(999)).to.be.revertedWithCustomError(wallet, "NotOperatorOrOwner");
    });
  });

  describe("Kill switch and human controls", function () {
    it("operator can pause, cannot unpause; owner unpauses", async function () {
      await wallet.connect(operator).pause();
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "EnforcedPause");
      await expect(wallet.connect(operator).unpause()).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
      await expect(wallet.connect(attacker).pause()).to.be.revertedWithCustomError(wallet, "NotOperatorOrOwner");
      await wallet.connect(owner).unpause();
      await wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig);
      expect(await token.balanceOf(payee.address)).to.equal(1n);
    });
    it("owner can recover funds with ownerExecute, even while paused; others cannot", async function () {
      await wallet.connect(operator).pause();
      const data = transferData(owner.address, 5n);
      await expect(wallet.connect(owner).ownerExecute(await token.getAddress(), 0, data)).to.emit(wallet, "OwnerExecuted");
      expect(await token.balanceOf(owner.address)).to.equal(5n);
      await expect(wallet.connect(operator).ownerExecute(await token.getAddress(), 0, data))
        .to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
    });
    it("admin setters are owner-only and validated", async function () {
      for (const [fn, arg] of [["setOperator", attacker.address], ["setGuardianSigner", attacker.address], ["setPassportRegistry", ethers.ZeroAddress], ["setMaxAllowedRiskScore", 50]] as const) {
        await expect((wallet.connect(operator) as any)[fn](arg)).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
      }
      await expect(wallet.setOperator(ethers.ZeroAddress)).to.be.revertedWithCustomError(wallet, "ZeroAddress");
      await expect(wallet.setGuardianSigner(ethers.ZeroAddress)).to.be.revertedWithCustomError(wallet, "ZeroAddress");
      await expect(wallet.setMaxAllowedRiskScore(101)).to.be.revertedWithCustomError(wallet, "InvalidRiskThreshold");
    });
    it("rotating the GuardianAI signer invalidates approvals from the old key", async function () {
      await wallet.setGuardianSigner(payee.address);
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "InvalidAttestationSignature");
    });
    it("rotating the operator locks out the old agent key", async function () {
      await wallet.setOperator(payee.address);
      const data = transferData(payee.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "NotOperator");
      await wallet.connect(payee).execute(await token.getAddress(), 0, data, att, sig);
    });
  });

  describe("Chainlink CRE threat oracle check (on-chain scam list)", function () {
    let oracle: any;
    const abi = ethers.AbiCoder.defaultAbiCoder();
    const flag = async (addr: string, on: boolean, asOf: number) =>
      oracle.connect(owner).onReport("0x", abi.encode(
        ["uint64", "uint256", "uint256", "uint256", "bytes32", "address[]", "bool[]"],
        [asOf, 0, 0, 0, ethers.ZeroHash, [addr], [on]]));
    beforeEach(async function () {
      // owner doubles as the "forwarder" here; the oracle's own tests cover forwarder auth
      oracle = await (await ethers.getContractFactory("GuardianThreatOracle")).deploy(owner.address);
      await expect(wallet.setThreatOracle(await oracle.getAddress())).to.emit(wallet, "ThreatOracleUpdated");
    });
    it("refuses a GuardianAI-approved transfer to a recipient the DON flagged", async function () {
      await flag(attacker.address, true, 1);
      const data = transferData(attacker.address, 1n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "FlaggedDestination").withArgs(attacker.address);
    });
    it("refuses approve() to a flagged spender and calls to a flagged target", async function () {
      await flag(attacker.address, true, 1);
      const ap = token.interface.encodeFunctionData("approve", [attacker.address, 1n]);
      const a1 = await approve(await token.getAddress(), ap);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, ap, a1.att, a1.sig))
        .to.be.revertedWithCustomError(wallet, "FlaggedDestination");
      await flag(await target.getAddress(), true, 2);
      const call = target.interface.encodeFunctionData("doSomething", [1]);
      const a2 = await approve(await target.getAddress(), call);
      await expect(wallet.connect(operator).execute(await target.getAddress(), 0, call, a2.att, a2.sig))
        .to.be.revertedWithCustomError(wallet, "FlaggedDestination").withArgs(await target.getAddress());
    });
    it("refuses transferFrom to a flagged recipient (second argument)", async function () {
      await flag(attacker.address, true, 1);
      const data = token.interface.encodeFunctionData("transferFrom", [payee.address, attacker.address, 1n]);
      const { att, sig } = await approve(await token.getAddress(), data);
      await expect(wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "FlaggedDestination").withArgs(attacker.address);
    });
    it("unflagged recipients still go through; unflagging restores access", async function () {
      await flag(payee.address, true, 1);
      await flag(payee.address, false, 2);
      const data = transferData(payee.address, 2n);
      const { att, sig } = await approve(await token.getAddress(), data);
      await wallet.connect(operator).execute(await token.getAddress(), 0, data, att, sig);
      expect(await token.balanceOf(payee.address)).to.equal(2n);
    });
    it("setThreatOracle is owner-only", async function () {
      await expect(wallet.connect(operator).setThreatOracle(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
    });
  });

  describe("On-chain spend policy (caps and allowlist)", function () {
    let tokenAddr: string, targetAddr: string;
    const E = (x: string) => ethers.parseEther(x);

    beforeEach(async function () {
      tokenAddr = await token.getAddress();
      targetAddr = await target.getAddress();
      await owner.sendTransaction({ to: await wallet.getAddress(), value: E("5") });
    });

    async function sendMon(amt: bigint) {
      const { att, sig } = await approve(payee.address, "0x", amt);
      return wallet.connect(operator).execute(payee.address, amt, "0x", att, sig);
    }
    async function runToken(data: string) {
      const { att, sig } = await approve(tokenAddr, data);
      return wallet.connect(operator).execute(tokenAddr, 0, data, att, sig);
    }

    it("defaults are off: no limits, no allowlist", async function () {
      expect(await wallet.dailyOutflowLimit()).to.equal(0);
      expect(await wallet.enforceTargetAllowlist()).to.equal(false);
      await sendMon(E("2"));
      await sendMon(E("2"));
    });

    it("native cap: second 0.6 MON in the window is refused, with the remaining amount", async function () {
      await wallet.setDailyOutflowLimit(E("1"));
      await sendMon(E("0.6"));
      await expect(sendMon(E("0.6")))
        .to.be.revertedWithCustomError(wallet, "DailyOutflowLimitExceeded").withArgs(E("0.6"), E("0.4"));
    });

    it("native cap resets after 24h", async function () {
      await wallet.setDailyOutflowLimit(E("1"));
      await sendMon(E("0.6"));
      await time.increase(86400);
      await sendMon(E("0.6"));
      expect(await wallet.outflowInWindow()).to.equal(E("0.6"));
    });

    it("limit 0 means unlimited, and zero-value calls are not counted", async function () {
      await wallet.setDailyOutflowLimit(E("1"));
      await wallet.setDailyOutflowLimit(0);
      await sendMon(E("3"));
      await wallet.setDailyOutflowLimit(E("1"));
      const data = target.interface.encodeFunctionData("doSomething", [1]);
      const { att, sig } = await approve(targetAddr, data);
      await wallet.connect(operator).execute(targetAddr, 0, data, att, sig);
      expect(await wallet.outflowInWindow()).to.equal(0);
    });

    it("lowering the limit below current usage gives remaining 0, not a panic", async function () {
      await wallet.setDailyOutflowLimit(E("2"));
      await sendMon(E("1.5"));
      await wallet.setDailyOutflowLimit(E("1"));
      await expect(sendMon(1n))
        .to.be.revertedWithCustomError(wallet, "DailyOutflowLimitExceeded").withArgs(1n, 0n);
    });

    it("token cap counts transfer and approve, per token", async function () {
      await wallet.setTokenDailyLimit(tokenAddr, 10n);
      await runToken(transferData(payee.address, 6n));
      await runToken(token.interface.encodeFunctionData("approve", [payee.address, 4n]));
      await expect(runToken(transferData(payee.address, 1n)))
        .to.be.revertedWithCustomError(wallet, "TokenDailyLimitExceeded").withArgs(tokenAddr, 1n, 0n);
      // a different token has its own (unset) limit
      const token2 = await (await ethers.getContractFactory("MockERC20")).deploy();
      await token2.mint(await wallet.getAddress(), 100n);
      const t2 = await token2.getAddress();
      const d2 = token2.interface.encodeFunctionData("transfer", [payee.address, 50n]);
      const { att, sig } = await approve(t2, d2);
      await wallet.connect(operator).execute(t2, 0, d2, att, sig);
      // window resets after 24h
      await time.increase(86400);
      await runToken(transferData(payee.address, 10n));
    });

    it("token cap: a single amount above the limit is refused", async function () {
      await wallet.setTokenDailyLimit(tokenAddr, 10n);
      await expect(runToken(transferData(payee.address, 11n)))
        .to.be.revertedWithCustomError(wallet, "TokenDailyLimitExceeded").withArgs(tokenAddr, 11n, 10n);
    });

    it("allowlist: unknown target is refused", async function () {
      await wallet.setEnforceTargetAllowlist(true);
      await expect(sendMon(1n)).to.be.revertedWithCustomError(wallet, "TargetNotAllowed").withArgs(payee.address);
    });

    it("allowlist: allowed target with a disallowed selector is refused; allowing the selector permits it", async function () {
      await wallet.setEnforceTargetAllowlist(true);
      await wallet.setAllowedTarget(targetAddr, true);
      const data = target.interface.encodeFunctionData("doSomething", [1]);
      const sel = data.slice(0, 10);
      const { att, sig } = await approve(targetAddr, data);
      await expect(wallet.connect(operator).execute(targetAddr, 0, data, att, sig))
        .to.be.revertedWithCustomError(wallet, "SelectorNotAllowed").withArgs(targetAddr, sel);
      await wallet.setAllowedSelector(targetAddr, sel, true);
      const a2 = await approve(targetAddr, data);
      await wallet.connect(operator).execute(targetAddr, 0, data, a2.att, a2.sig);
      expect(await target.counter()).to.equal(1n);
    });

    it("allowlist: allowlisted EOA with empty data succeeds", async function () {
      await wallet.setEnforceTargetAllowlist(true);
      await wallet.setAllowedTarget(payee.address, true);
      await expect(sendMon(E("0.1"))).to.changeEtherBalance(payee, E("0.1"));
    });

    it("every policy setter is owner-only", async function () {
      for (const who of [operator, attacker]) {
        const w = wallet.connect(who);
        await expect(w.setDailyOutflowLimit(1)).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
        await expect(w.setTokenDailyLimit(tokenAddr, 1)).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
        await expect(w.setEnforceTargetAllowlist(true)).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
        await expect(w.setAllowedTarget(targetAddr, true)).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
        await expect(w.setAllowedSelector(targetAddr, "0x12345678", true)).to.be.revertedWithCustomError(wallet, "OwnableUnauthorizedAccount");
      }
    });

    it("setters emit events", async function () {
      await expect(wallet.setDailyOutflowLimit(5)).to.emit(wallet, "DailyOutflowLimitUpdated").withArgs(0, 5);
      await expect(wallet.setTokenDailyLimit(tokenAddr, 7)).to.emit(wallet, "TokenDailyLimitUpdated").withArgs(tokenAddr, 0, 7);
      await expect(wallet.setEnforceTargetAllowlist(true)).to.emit(wallet, "TargetAllowlistEnforcementUpdated").withArgs(true);
      await expect(wallet.setAllowedTarget(targetAddr, true)).to.emit(wallet, "AllowedTargetUpdated").withArgs(targetAddr, true);
      await expect(wallet.setAllowedSelector(targetAddr, "0x12345678", true))
        .to.emit(wallet, "AllowedSelectorUpdated").withArgs(targetAddr, "0x12345678", true);
    });

    it("ownerExecute bypasses the caps and the allowlist", async function () {
      await wallet.setDailyOutflowLimit(1n);
      await wallet.setEnforceTargetAllowlist(true);
      await wallet.setTokenDailyLimit(tokenAddr, 1n);
      await expect(wallet.ownerExecute(payee.address, E("1"), "0x")).to.changeEtherBalance(payee, E("1"));
      await wallet.ownerExecute(tokenAddr, 0, transferData(payee.address, 50n));
      expect(await token.balanceOf(payee.address)).to.equal(50n);
    });
  });

  describe("Factory", function () {
    let factory: any;
    beforeEach(async function () {
      factory = await (await ethers.getContractFactory("GuardianAgentWalletFactory")).deploy(guardian.address, await passport.getAddress());
    });
    it("deploys at the predicted address with the caller as owner and emits WalletCreated", async function () {
      const predicted = await factory.predictAddress(owner.address, operator.address, AGENT);
      await expect(factory.connect(owner).createWallet(operator.address, AGENT))
        .to.emit(factory, "WalletCreated").withArgs(AGENT, predicted, owner.address, operator.address);
      const w = await ethers.getContractAt("GuardianAgentWallet", predicted);
      expect(await w.owner()).to.equal(owner.address);
      expect(await w.guardianSigner()).to.equal(guardian.address);
      expect(await factory.walletOf(owner.address, AGENT)).to.equal(predicted);
    });
    it("same owner + agent twice reverts; another owner cannot squat the address", async function () {
      await factory.connect(owner).createWallet(operator.address, AGENT);
      await expect(factory.connect(owner).createWallet(operator.address, AGENT)).to.be.revertedWithCustomError(factory, "WalletExists");
      await factory.connect(attacker).createWallet(attacker.address, AGENT);
      expect(await factory.walletOf(attacker.address, AGENT)).to.not.equal(await factory.walletOf(owner.address, AGENT));
    });
  });
});
