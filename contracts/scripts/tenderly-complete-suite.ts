import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("===============================================================");
  console.log("Executing Tenderly Complete Suite with account:", deployer.address);
  console.log("Account Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");
  console.log("===============================================================\n");

  const signerAddress = process.env.GUARDIAN_ATTESTATION_SIGNER || deployer.address;

  // 1. Deploy GuardianPolicyGuard
  console.log("[1/5] Deploying GuardianPolicyGuard...");
  const PolicyGuardFactory = await ethers.getContractFactory("GuardianPolicyGuard");
  const policyGuard = await PolicyGuardFactory.deploy(signerAddress);
  await policyGuard.waitForDeployment();
  const policyGuardAddr = await policyGuard.getAddress();
  console.log("      -> GuardianPolicyGuard:", policyGuardAddr);

  // 2. Deploy GuardianThreatFeedRegistry
  console.log("[2/5] Deploying GuardianThreatFeedRegistry...");
  const ThreatFeedFactory = await ethers.getContractFactory("GuardianThreatFeedRegistry");
  const threatFeed = await ThreatFeedFactory.deploy();
  await threatFeed.waitForDeployment();
  const threatFeedAddr = await threatFeed.getAddress();
  console.log("      -> GuardianThreatFeedRegistry:", threatFeedAddr);

  // 3. Deploy GuardianInterlockRegistry
  console.log("[3/5] Deploying GuardianInterlockRegistry...");
  const InterlockFactory = await ethers.getContractFactory("GuardianInterlockRegistry");
  const interlock = await InterlockFactory.deploy();
  await interlock.waitForDeployment();
  const interlockAddr = await interlock.getAddress();
  console.log("      -> GuardianInterlockRegistry:", interlockAddr);

  // 4. Deploy GuardianRiskAttestation
  console.log("[4/5] Deploying GuardianRiskAttestation...");
  const RiskFactory = await ethers.getContractFactory("GuardianRiskAttestation");
  const risk = await RiskFactory.deploy();
  await risk.waitForDeployment();
  const riskAddr = await risk.getAddress();
  console.log("      -> GuardianRiskAttestation:", riskAddr);

  // 5. Deploy GuardianTimelock
  console.log("[5/5] Deploying GuardianTimelock...");
  const TimelockFactory = await ethers.getContractFactory("GuardianTimelock");
  const timelock = await TimelockFactory.deploy(
    [deployer.address],
    [ethers.ZeroAddress],
    deployer.address
  );
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();
  console.log("      -> GuardianTimelock:", timelockAddr);

  console.log("\n===============================================================");
  console.log("Executing Live Transactions for Tenderly Visual Debugger Traces");
  console.log("===============================================================\n");

  // Interaction A: Issue Insurance Certificate on GuardianInsuranceLedger
  const insuranceAddr = "0xB98644392B035a4bA7207a6EcBfF0Ba82a57AfcE";
  console.log("Interacting with GuardianInsuranceLedger at:", insuranceAddr);
  const insuranceContract = await ethers.getContractAt("GuardianInsuranceLedger", insuranceAddr);
  
  const certId = ethers.hexlify(ethers.randomBytes(32));
  const agentHash = ethers.id("agent-007-production");
  const certHash = ethers.id("cert-metadata-hash-v1");
  const now = Math.floor(Date.now() / 1000);
  
  const txCert = await insuranceContract.issueCertificate(
    certId,
    agentHash,
    now,
    now + 86400 * 30,
    certHash,
    "LOW"
  );
  const receiptCert = await txCert.wait();
  console.log(" -> [Tx 1/3] issueCertificate confirmed! Hash:", receiptCert.hash);

  // Interaction B: Commit Cortex Anchor Merkle Root
  const cortexAddr = "0x133fC02Ccf1c7D0f1E9D5C00e5625a13983A293c";
  console.log("Interacting with GuardianCortexAnchor at:", cortexAddr);
  const cortexContract = await ethers.getContractAt("GuardianCortexAnchor", cortexAddr);
  
  const merkleRoot = ethers.hexlify(ethers.randomBytes(32));
  const txAnchor = await cortexContract.commitRoot(
    merkleRoot,
    42,
    agentHash,
    now - 3600,
    now
  );
  const receiptAnchor = await txAnchor.wait();
  console.log(" -> [Tx 2/3] commitRoot confirmed! Hash:", receiptAnchor.hash);

  // Interaction C: Add Malicious Address to Threat Feed
  console.log("Interacting with GuardianThreatFeedRegistry at:", threatFeedAddr);
  const threatContract = await ethers.getContractAt("GuardianThreatFeedRegistry", threatFeedAddr);
  const maliciousWallet = ethers.Wallet.createRandom().address;
  const txThreat = await threatContract.addAddress(maliciousWallet, "Phishing drainer detected by GuardianAI Cortex");
  const receiptThreat = await txThreat.wait();
  console.log(" -> [Tx 3/3] addAddress threat confirmed! Hash:", receiptThreat.hash);

  console.log("\n===============================================================");
  console.log("ALL DEPLOYMENTS AND LIVE TRANSACTIONS COMPLETED ON TENDERLY!");
  console.log("===============================================================");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
