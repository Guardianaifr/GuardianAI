import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianRiskAttestation with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  const RiskAttestation = await ethers.getContractFactory("GuardianRiskAttestation");
  const attestation = await RiskAttestation.deploy();
  await attestation.waitForDeployment();

  const address = await attestation.getAddress();
  console.log("GuardianRiskAttestation deployed to:", address);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_RISK_CONTRACT_MONAD=${address}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
