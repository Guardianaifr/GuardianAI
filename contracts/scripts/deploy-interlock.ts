import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianInterlockRegistry with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  const InterlockRegistry = await ethers.getContractFactory("GuardianInterlockRegistry");
  const registry = await InterlockRegistry.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log("GuardianInterlockRegistry deployed to:", address);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_INTERLOCK_CONTRACT_MONAD=${address}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
