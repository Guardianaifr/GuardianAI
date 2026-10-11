import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

// Same agent_id format as the console: keccak256("console:<owner lowercase>")
const agentIdOf = (addr: string) => ethers.keccak256(ethers.toUtf8Bytes(`console:${addr.toLowerCase()}`));

const attTypes = {
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

describe("GuardianPassportIssuer", function () {
  let deployer: SignerWithAddress, guardian: SignerWithAddress, judge: SignerWithAddress;
  let other: SignerWithAddress, agentKey: SignerWithAddress, payee: SignerWithAddress;
  let sbt: any, factory: any, issuer: any;

  beforeEach(async function () {
    [deployer, guardian, judge, other, agentKey, payee] = await ethers.getSigners();
    sbt = await (await ethers.getContractFactory("GuardianPassportSBT")).deploy();
    factory = await (await ethers.getContractFactory("GuardianAgentWalletFactory")).deploy(guardian.address, await sbt.getAddress());
    issuer = await (await ethers.getContractFactory("GuardianPassportIssuer")).deploy(
      await sbt.getAddress(), await factory.getAddress(), deployer.address,
    );
    // The handoff the deployer runs once on Monad (Ownable2Step).
    await sbt.connect(deployer).transferOwnership(await issuer.getAddress());
    await issuer.connect(deployer).acceptPassportOwnership();
  });

  async function createWallet(owner: SignerWithAddress) {
    const id = agentIdOf(owner.address);
    await factory.connect(owner).createWallet(agentKey.address, id);
    return { id, wallet: await factory.walletOf(owner.address, id) };
  }

  describe("Handoff", function () {
    it("issuer owns the SBT; deployer owns the issuer", async function () {
      expect(await sbt.owner()).to.equal(await issuer.getAddress());
      expect(await issuer.owner()).to.equal(deployer.address);
    });
    it("rejects zero addresses", async function () {
      const F = await ethers.getContractFactory("GuardianPassportIssuer");
      await expect(F.deploy(ethers.ZeroAddress, await factory.getAddress(), deployer.address)).to.be.revertedWithCustomError(issuer, "ZeroAddress");
      await expect(F.deploy(await sbt.getAddress(), ethers.ZeroAddress, deployer.address)).to.be.revertedWithCustomError(issuer, "ZeroAddress");
    });
    it("deployer can take the SBT back (two-step)", async function () {
      await issuer.connect(deployer).transferPassportOwnership(deployer.address);
      expect(await sbt.owner()).to.equal(await issuer.getAddress()); // not until accepted
      await sbt.connect(deployer).acceptOwnership();
      expect(await sbt.owner()).to.equal(deployer.address);
    });
  });

  describe("Self-serve claim", function () {
    it("mints one lowest-tier card to the wallet owner", async function () {
      const { id, wallet } = await createWallet(judge);
      await expect(issuer.connect(judge).claim(id))
        .to.emit(issuer, "Claimed").withArgs(judge.address, id, wallet, 1n);
      expect(await sbt.isPassportActive(id)).to.equal(true);
      expect(await sbt.ownerOf(1)).to.equal(judge.address);
      const p = await sbt.getPassport(1);
      expect(p.trustScore).to.equal(1000n);
      expect(p.tier).to.equal(0n); // UNVERIFIED
      expect(p.metadataURI).to.equal("");
      expect(await issuer.claimedTokenOf(judge.address)).to.equal(1n);
      expect(await issuer.claimCount()).to.equal(1n);
    });

    it("refuses an agent without a guarded wallet", async function () {
      const id = agentIdOf(judge.address);
      await expect(issuer.connect(judge).claim(id))
        .to.be.revertedWithCustomError(issuer, "NoGuardedWallet").withArgs(judge.address, id);
    });

    it("refuses claiming someone else's agent", async function () {
      const { id } = await createWallet(judge);
      await expect(issuer.connect(other).claim(id))
        .to.be.revertedWithCustomError(issuer, "NoGuardedWallet").withArgs(other.address, id);
    });

    it("one self-serve card per address, even for a second agent", async function () {
      const { id } = await createWallet(judge);
      await issuer.connect(judge).claim(id);
      await expect(issuer.connect(judge).claim(id)).to.be.revertedWithCustomError(issuer, "AlreadyClaimed").withArgs(1n);
      const second = ethers.keccak256(ethers.toUtf8Bytes("second-agent"));
      await factory.connect(judge).createWallet(agentKey.address, second);
      await expect(issuer.connect(judge).claim(second)).to.be.revertedWithCustomError(issuer, "AlreadyClaimed");
    });

    it("an agent that already has a card (issued by the team) can't get a second", async function () {
      const { id } = await createWallet(judge);
      await issuer.connect(deployer).mint(deployer.address, id, 5000, "team");
      await expect(issuer.connect(judge).claim(id)).to.be.revertedWithCustomError(sbt, "AgentAlreadyHasPassport");
      expect(await issuer.claimCount()).to.equal(0n); // reverted claim leaves no trace
    });

    it("a revoked agent can't come back through self-serve", async function () {
      const { id } = await createWallet(judge);
      await issuer.connect(judge).claim(id);
      await issuer.connect(deployer).revoke(1);
      expect(await sbt.isPassportActive(id)).to.equal(false);
      await expect(issuer.connect(judge).claim(id)).to.be.revertedWithCustomError(issuer, "AlreadyClaimed");
    });

    it("owner can close claims and set a cap", async function () {
      const a = await createWallet(judge);
      const b = await createWallet(other);
      await issuer.connect(deployer).setClaims(false, 0);
      await expect(issuer.connect(judge).claim(a.id)).to.be.revertedWithCustomError(issuer, "ClaimsClosed");
      await expect(issuer.connect(deployer).setClaims(true, 1)).to.emit(issuer, "ClaimsConfigured").withArgs(true, 1n);
      await issuer.connect(judge).claim(a.id);
      await expect(issuer.connect(other).claim(b.id)).to.be.revertedWithCustomError(issuer, "ClaimCapReached").withArgs(1n);
    });

    it("paused SBT means claims fail and cards read inactive", async function () {
      const { id } = await createWallet(judge);
      await issuer.connect(deployer).pausePassports();
      await expect(issuer.connect(judge).claim(id)).to.be.revertedWithCustomError(sbt, "EnforcedPause");
      await issuer.connect(deployer).unpausePassports();
      await issuer.connect(judge).claim(id);
      expect(await sbt.isPassportActive(id)).to.equal(true);
    });
  });

  describe("Admin is owner-only", function () {
    it("strangers can't mint, rescore, revoke, pause, configure or move the SBT", async function () {
      const id = agentIdOf(other.address);
      const E = "OwnableUnauthorizedAccount";
      await expect(issuer.connect(other).mint(other.address, id, 9999, "")).to.be.revertedWithCustomError(issuer, E);
      await expect(issuer.connect(other).updateScore(1, 9999)).to.be.revertedWithCustomError(issuer, E);
      await expect(issuer.connect(other).revoke(1)).to.be.revertedWithCustomError(issuer, E);
      await expect(issuer.connect(other).pausePassports()).to.be.revertedWithCustomError(issuer, E);
      await expect(issuer.connect(other).setClaims(true, 0)).to.be.revertedWithCustomError(issuer, E);
      await expect(issuer.connect(other).transferPassportOwnership(other.address)).to.be.revertedWithCustomError(issuer, E);
      await expect(issuer.connect(other).acceptPassportOwnership()).to.be.revertedWithCustomError(issuer, E);
    });
    it("the deployer can no longer call the SBT directly", async function () {
      await expect(sbt.connect(deployer).mint(deployer.address, agentIdOf(deployer.address), 5000, ""))
        .to.be.revertedWithCustomError(sbt, "OwnableUnauthorizedAccount");
    });
    it("owner can still issue and rescore higher tiers through the issuer", async function () {
      const id = ethers.keccak256(ethers.toUtf8Bytes("privy-agent:demo"));
      await issuer.connect(deployer).mint(deployer.address, id, 9400, "ipfs://x");
      await issuer.connect(deployer).updateScore(1, 7500);
      const p = await sbt.getPassport(1);
      expect(p.trustScore).to.equal(7500n);
      expect(p.tier).to.equal(2n); // GOLD
    });
  });

  describe("End to end with a guarded wallet", function () {
    it("payment reverts without a card, succeeds after the owner claims one", async function () {
      const { id, wallet: walletAddr } = await createWallet(judge);
      await judge.sendTransaction({ to: walletAddr, value: ethers.parseEther("1") });
      const wallet = await ethers.getContractAt("GuardianAgentWallet", walletAddr);
      const value = ethers.parseEther("0.1");
      const { chainId } = await ethers.provider.getNetwork();
      const sign = async (n: bigint) => {
        const now = (await ethers.provider.getBlock("latest"))!.timestamp;
        const att = { agentId: id, targetContract: payee.address, calldataHash: ethers.keccak256("0x"), value, riskScore: 0, nonce: n, deadline: now + 300 };
        const sig = await guardian.signTypedData({ name: "GuardianAgentWallet", version: "1", chainId, verifyingContract: walletAddr }, attTypes, att);
        return { att, sig };
      };

      const a = await sign(1n);
      await expect(wallet.connect(agentKey).execute(payee.address, value, "0x", a.att, a.sig))
        .to.be.revertedWithCustomError(wallet, "PassportRevokedOrInactive");

      await issuer.connect(judge).claim(id);
      const before = await ethers.provider.getBalance(payee.address);
      const b = await sign(2n);
      await wallet.connect(agentKey).execute(payee.address, value, "0x", b.att, b.sig);
      expect(await ethers.provider.getBalance(payee.address)).to.equal(before + value);

      // Revoking the card freezes the agent again.
      await issuer.connect(deployer).revoke(1);
      const c = await sign(3n);
      await expect(wallet.connect(agentKey).execute(payee.address, value, "0x", c.att, c.sig))
        .to.be.revertedWithCustomError(wallet, "PassportRevokedOrInactive");
    });
  });
});
