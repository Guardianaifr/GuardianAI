import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianCortexAnchor with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  const CortexAnchor = await ethers.getContractFactory("GuardianCortexAnchor");
  const anchor = await CortexAnchor.deploy();
  await anchor.waitForDeployment();

  const address = await anchor.getAddress();
  console.log("GuardianCortexAnchor deployed to:", address);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_CORTEX_CONTRACT_MONAD=${address}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
