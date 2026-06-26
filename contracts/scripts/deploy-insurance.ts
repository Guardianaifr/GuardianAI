import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianInsuranceLedger with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  const InsuranceLedger = await ethers.getContractFactory("GuardianInsuranceLedger");
  const ledger = await InsuranceLedger.deploy();
  await ledger.waitForDeployment();

  const address = await ledger.getAddress();
  console.log("GuardianInsuranceLedger deployed to:", address);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_INSURANCE_CONTRACT_MONAD=${address}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
