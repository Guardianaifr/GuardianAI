import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianPassportSBT with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  const PassportSBT = await ethers.getContractFactory("GuardianPassportSBT");
  const passport = await PassportSBT.deploy();
  await passport.waitForDeployment();

  const address = await passport.getAddress();
  console.log("GuardianPassportSBT deployed to:", address);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_SBT_CONTRACT_MONAD=${address}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
