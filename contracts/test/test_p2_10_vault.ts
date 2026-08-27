import { expect } from "chai";
import { ethers } from "hardhat";
import { GuardianProtectedVault, MaliciousToken } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("P2-10: GuardianProtectedVault CEI Reentrancy Fix", function () {
  let vault: GuardianProtectedVault;
  let token: MaliciousToken;
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  beforeEach(async function () {
    [owner, attacker] = await ethers.getSigners();
    const Mock = await ethers.getContractFactory("MockDependencies");
    const mock = await Mock.deploy();
    const Token = await ethers.getContractFactory("MaliciousToken");
    token = await Token.deploy();
    const Vault = await ethers.getContractFactory("GuardianProtectedVault");
    vault = await Vault.deploy(await token.getAddress(), await mock.getAddress(), await mock.getAddress(), "monad");
    
    await token.mint(attacker.address, 1000);
    // Give the malicious token itself some balance so its re-entrant deposit succeeds
    await token.mint(await token.getAddress(), 1000);
    await token.setVault(await vault.getAddress());
  });

  it("Should prevent malicious token from exploiting deposit ordering", async function () {
    await token.connect(attacker).approve(await vault.getAddress(), 1000);
    
    let err = "";
    try {
        await vault.connect(attacker).deposit(10);
    } catch (e: any) {
        err = e.message;
    }
    
    console.log("\n\t[+] Received Error:", err.split('\n')[0]);
    
    // We expect the ReentrancyGuard to block the nested call entirely, reverting the entire transaction.
    expect(err).to.include("ReentrancyGuardReentrantCall()");
    
    // Attack failed outright, no balances were modified at all
    expect(await vault.balances(attacker.address)).to.equal(0);
    expect(await vault.balances(await token.getAddress())).to.equal(0);
    expect(await token.balanceOf(await vault.getAddress())).to.equal(0);
    
    console.log("\t[+] ReentrancyGuard successfully reverted the transaction outright!\n");
  });
});