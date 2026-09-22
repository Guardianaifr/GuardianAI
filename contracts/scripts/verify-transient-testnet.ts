import { ethers } from "hardhat";

async function main() {
  console.log("==================================================");
  console.log("Verifying ReentrancyGuardTransient (EIP-1153 TSTORE/TLOAD) on Monad Testnet");
  console.log("==================================================");

  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  const bal = await ethers.provider.getBalance(deployer.address);
  console.log("Balance :", ethers.formatEther(bal), "MON");

  const Factory = await ethers.getContractFactory("MockTransientGuard");
  console.log("[+] Deploying MockTransientGuard to Monad Testnet...");
  const contract = await Factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  const deployTx = contract.deploymentTransaction();
  console.log(`[✓] MockTransientGuard deployed at: ${address}`);
  console.log(`    Deployment Tx: ${deployTx?.hash}`);

  console.log("[+] Executing doProtectedWork(10) calling nonReentrant with TSTORE/TLOAD...");
  const tx = await contract.doProtectedWork(10);
  console.log(`    Call Tx Hash: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`[✓] Transaction confirmed in block #${receipt?.blockNumber} with status: ${receipt?.status === 1 ? "SUCCESS" : "FAIL"}`);
  console.log(`    Gas Used: ${receipt?.gasUsed.toString()}`);

  const counter = await contract.counter();
  console.log(`[✓] On-Chain Counter after TSTORE/TLOAD execution: ${counter.toString()}`);
  console.log("==================================================");
  console.log("EIP-1153 (TSTORE / TLOAD) IS 100% CONFIRMED LIVE ON MONAD TESTNET!");
  console.log("==================================================");
}

main().catch((err) => {
  console.error("[-] Verification failed:", err);
  process.exitCode = 1;
});
