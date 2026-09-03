import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  console.log("================================================================");
  console.log("Deploying GuardianAI Core Smart Contract Trio to Monad Testnet");
  console.log("================================================================");

  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);
  const network = await ethers.provider.getNetwork();

  console.log(`[+] Deployer Account : ${deployer.address}`);
  console.log(`[+] Monad Balance    : ${ethers.formatEther(balance)} MON`);
  console.log(`[+] Target Chain ID  : ${network.chainId}`);

  if (balance === 0n) {
    throw new Error("[-] Deployer account has 0 MON balance. Cannot proceed with deployment.");
  }

  const signerAddress = process.env.GUARDIAN_ATTESTATION_SIGNER || deployer.address;
  console.log(`[+] Authorized Attestation Signer : ${signerAddress}`);
  console.log("----------------------------------------------------------------");

  // 1. Deploy GuardianThreatFeedRegistry
  console.log("[1/3] Deploying GuardianThreatFeedRegistry...");
  const ThreatFeedFactory = await ethers.getContractFactory("GuardianThreatFeedRegistry");
  const threatFeed = await ThreatFeedFactory.deploy();
  await threatFeed.waitForDeployment();
  const threatFeedAddress = await threatFeed.getAddress();
  console.log(`  [✓] GuardianThreatFeedRegistry deployed at: ${threatFeedAddress}`);

  // 2. Deploy GuardianPassportSBT
  console.log("[2/3] Deploying GuardianPassportSBT...");
  const PassportFactory = await ethers.getContractFactory("GuardianPassportSBT");
  const passportSBT = await PassportFactory.deploy();
  await passportSBT.waitForDeployment();
  const passportSBTAddress = await passportSBT.getAddress();
  console.log(`  [✓] GuardianPassportSBT deployed at: ${passportSBTAddress}`);

  // 3. Deploy GuardianPolicyGuard
  console.log("[3/3] Deploying GuardianPolicyGuard...");
  const PolicyGuardFactory = await ethers.getContractFactory("GuardianPolicyGuard");
  const policyGuard = await PolicyGuardFactory.deploy(signerAddress);
  await policyGuard.waitForDeployment();
  const policyGuardAddress = await policyGuard.getAddress();
  console.log(`  [✓] GuardianPolicyGuard deployed at: ${policyGuardAddress}`);

  console.log("================================================================");
  console.log("DEPLOYMENT COMPLETE — SUMMARY OF MONAD TESTNET ADDRESSES:");
  console.log("================================================================");
  console.log(`GUARDIAN_POLICY_GUARD_CONTRACT_MONAD=${policyGuardAddress}`);
  console.log(`GUARDIAN_THREATFEED_CONTRACT_MONAD=${threatFeedAddress}`);
  console.log(`GUARDIAN_SBT_CONTRACT_MONAD=${passportSBTAddress}`);

  // Save deployment artifact
  const deploymentSummary = {
    network: "monad_testnet",
    chainId: Number(network.chainId),
    deployer: deployer.address,
    attestationSigner: signerAddress,
    timestamp: new Date().toISOString(),
    contracts: {
      GuardianPolicyGuard: policyGuardAddress,
      GuardianThreatFeedRegistry: threatFeedAddress,
      GuardianPassportSBT: passportSBTAddress,
    },
  };

  const outputPath = path.resolve(__dirname, "../../metropolis/deployments-monad.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentSummary, null, 2), "utf8");
  console.log(`[+] Saved deployment record to: ${outputPath}`);

  // Append/update .env
  const envPath = path.resolve(__dirname, "../../.env");
  if (fs.existsSync(envPath)) {
    let envContent = fs.readFileSync(envPath, "utf8");
    const appendLines = [
      `\n# Monad Testnet Deployed Contracts (${new Date().toISOString()})`,
      `GUARDIAN_POLICY_GUARD_CONTRACT_MONAD=${policyGuardAddress}`,
      `GUARDIAN_THREATFEED_CONTRACT_MONAD=${threatFeedAddress}`,
      `GUARDIAN_SBT_CONTRACT_MONAD=${passportSBTAddress}`,
    ].join("\n");
    fs.appendFileSync(envPath, appendLines, "utf8");
    console.log(`[+] Appended deployed contract addresses to .env`);
  }
}

main().catch((error) => {
  console.error("[-] Deployment failed:", error);
  process.exitCode = 1;
});