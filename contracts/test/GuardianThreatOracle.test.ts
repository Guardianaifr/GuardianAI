import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

const abi = ethers.AbiCoder.defaultAbiCoder();
const REPORT = ["uint64", "uint256", "uint256", "uint256", "bytes32", "address[]", "bool[]"];
const enc = (asOf: number, addrs: string[], flags: boolean[], b = 3, i = 10, p = 7) =>
  abi.encode(REPORT, [asOf, b, i, p, ethers.id("feed-" + asOf), addrs, flags]);
// CRE metadata: workflowId(32) | workflowName(10) | workflowOwner(20)
const meta = (owner: string) => ethers.concat([ethers.id("wf"), "0x" + "61".repeat(10), owner]);

describe("GuardianThreatOracle (Chainlink CRE receiver)", function () {
  let owner: SignerWithAddress, forwarder: SignerWithAddress, stranger: SignerWithAddress, scam: SignerWithAddress, wfOwner: SignerWithAddress;
  let oracle: any;

  beforeEach(async function () {
    [owner, forwarder, stranger, scam, wfOwner] = await ethers.getSigners();
    oracle = await (await ethers.getContractFactory("GuardianThreatOracle")).deploy(forwarder.address);
  });

  it("supports IReceiver and IERC165 via ERC-165", async function () {
    const iface = new ethers.Interface(["function onReport(bytes,bytes)"]);
    const receiverId = iface.getFunction("onReport")!.selector;
    expect(await oracle.supportsInterface(receiverId)).to.equal(true);
    expect(await oracle.supportsInterface("0x01ffc9a7")).to.equal(true);
    expect(await oracle.supportsInterface("0xdeadbeef")).to.equal(false);
  });

  it("rejects zero forwarder at deploy", async function () {
    const F = await ethers.getContractFactory("GuardianThreatOracle");
    await expect(F.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(oracle, "ZeroAddress");
  });

  it("accepts a report from the forwarder: stores stats and flags", async function () {
    await expect(oracle.connect(forwarder).onReport("0x", enc(100, [scam.address], [true])))
      .to.emit(oracle, "AddressFlagUpdated").withArgs(scam.address, true)
      .and.to.emit(oracle, "ThreatReportAccepted");
    expect(await oracle.isFlagged(scam.address)).to.equal(true);
    expect(await oracle.flaggedCount()).to.equal(1);
    expect(await oracle.blocked()).to.equal(3);
    expect(await oracle.intercepted()).to.equal(10);
    expect(await oracle.blockRateBps()).to.equal(3000);
    expect(await oracle.reportCount()).to.equal(1);
    expect(await oracle.lastAsOf()).to.equal(100);
  });

  it("anyone but the forwarder is refused, including the owner (no GuardianAI hot key can write)", async function () {
    await expect(oracle.connect(stranger).onReport("0x", enc(1, [scam.address], [true])))
      .to.be.revertedWithCustomError(oracle, "InvalidSender");
    await expect(oracle.connect(owner).onReport("0x", enc(1, [scam.address], [true])))
      .to.be.revertedWithCustomError(oracle, "InvalidSender");
  });

  it("stale or replayed reports cannot undo newer ones", async function () {
    await oracle.connect(forwarder).onReport("0x", enc(200, [scam.address], [true]));
    await expect(oracle.connect(forwarder).onReport("0x", enc(150, [scam.address], [false])))
      .to.be.revertedWithCustomError(oracle, "StaleReport");
    await expect(oracle.connect(forwarder).onReport("0x", enc(200, [scam.address], [false])))
      .to.be.revertedWithCustomError(oracle, "StaleReport");
    expect(await oracle.isFlagged(scam.address)).to.equal(true);
  });

  it("unflags, keeps the count right, and ignores no-op / zero entries", async function () {
    await oracle.connect(forwarder).onReport("0x", enc(1, [scam.address, stranger.address], [true, true]));
    await oracle.connect(forwarder).onReport("0x", enc(2, [scam.address, scam.address, ethers.ZeroAddress], [false, false, true]));
    expect(await oracle.isFlagged(scam.address)).to.equal(false);
    expect(await oracle.isFlagged(ethers.ZeroAddress)).to.equal(false);
    expect(await oracle.flaggedCount()).to.equal(1);
  });

  it("rejects malformed reports", async function () {
    await expect(oracle.connect(forwarder).onReport("0x", enc(1, [scam.address], [])))
      .to.be.revertedWithCustomError(oracle, "LengthMismatch");
    const many = Array.from({ length: 101 }, (_, k) => ethers.getAddress("0x" + (k + 1).toString(16).padStart(40, "0")));
    await expect(oracle.connect(forwarder).onReport("0x", enc(1, many, many.map(() => true))))
      .to.be.revertedWithCustomError(oracle, "TooManyAddresses");
  });

  it("optional workflow-owner pinning reads the CRE metadata", async function () {
    await oracle.setExpectedWorkflowOwner(wfOwner.address);
    await expect(oracle.connect(forwarder).onReport(meta(stranger.address), enc(1, [], [])))
      .to.be.revertedWithCustomError(oracle, "InvalidWorkflowOwner");
    await oracle.connect(forwarder).onReport(meta(wfOwner.address), enc(1, [scam.address], [true]));
    expect(await oracle.isFlagged(scam.address)).to.equal(true);
  });

  it("admin is owner-only", async function () {
    await expect(oracle.connect(stranger).setForwarder(stranger.address)).to.be.revertedWithCustomError(oracle, "OwnableUnauthorizedAccount");
    await expect(oracle.connect(stranger).setExpectedWorkflowOwner(stranger.address)).to.be.revertedWithCustomError(oracle, "OwnableUnauthorizedAccount");
    await expect(oracle.setForwarder(ethers.ZeroAddress)).to.be.revertedWithCustomError(oracle, "ZeroAddress");
    await oracle.setForwarder(stranger.address);
    await oracle.connect(stranger).onReport("0x", enc(1, [], []));
  });
});
