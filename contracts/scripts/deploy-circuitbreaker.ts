import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianProtectedVault with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  const riskAttestationAddress = process.env.GUARDIAN_RISK_ATTESTATION_CONTRACT;
  const threatFeedAddress = process.env.GUARDIAN_THREATFEED_CONTRACT;

  if (!riskAttestationAddress || !threatFeedAddress) {
    throw new Error("Missing GUARDIAN_RISK_ATTESTATION_CONTRACT or GUARDIAN_THREATFEED_CONTRACT in env");
  }

  // Deploy MockERC20 token for vault
  console.log("Deploying MockERC20 token for vault...");
  const MockERC20 = await ethers.getContractFactory("MockERC20");
  const token = await MockERC20.deploy();
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();
  console.log("MockERC20 deployed to:", tokenAddress);

  // Deploy Vault
  console.log("Deploying GuardianProtectedVault...");
  const Vault = await ethers.getContractFactory("GuardianProtectedVault");
  const vault = await Vault.deploy(tokenAddress, riskAttestationAddress, threatFeedAddress);
  await vault.waitForDeployment();

  const vaultAddress = await vault.getAddress();
  console.log("GuardianProtectedVault deployed to:", vaultAddress);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_CIRCUIT_BREAKER_CONTRACT=${vaultAddress}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${vaultAddress} ${tokenAddress} ${riskAttestationAddress} ${threatFeedAddress}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
