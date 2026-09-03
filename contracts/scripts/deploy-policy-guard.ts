import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianPolicyGuard with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  // Use configured relayer address or fall back to deployer
  const signerAddress = process.env.GUARDIAN_ATTESTATION_SIGNER || deployer.address;
  console.log("Authorized Attestation Signer:", signerAddress);

  const PolicyGuardFactory = await ethers.getContractFactory("GuardianPolicyGuard");
  const policyGuard = await PolicyGuardFactory.deploy(signerAddress);
  await policyGuard.waitForDeployment();

  const address = await policyGuard.getAddress();
  console.log("GuardianPolicyGuard deployed to:", address);
  console.log("");
  console.log("Add to your .env:");
  console.log(`GUARDIAN_POLICY_GUARD_CONTRACT_MONAD=${address}`);
  console.log("");
  console.log("Verify with:");
  console.log(`npx hardhat verify --network monad_testnet ${address} "${signerAddress}"`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});