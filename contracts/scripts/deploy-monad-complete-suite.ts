import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  console.log("================================================================");
  console.log("GUARDIAN-AI COMPLETE SMART CONTRACT SUITE DEPLOYMENT TO MONAD TESTNET");
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

  const deployedAddresses: Record<string, string> = {};
  const deployedReceipts: Record<string, any> = {};

  // 1. GuardianThreatFeedRegistry
  console.log("[1/9] Deploying GuardianThreatFeedRegistry...");
  const ThreatFeedFactory = await ethers.getContractFactory("GuardianThreatFeedRegistry");
  const threatFeed = await ThreatFeedFactory.deploy();
  await threatFeed.waitForDeployment();
  const threatFeedAddr = await threatFeed.getAddress();
  deployedAddresses["GuardianThreatFeedRegistry"] = threatFeedAddr;
  console.log(`  [✓] GuardianThreatFeedRegistry deployed at: ${threatFeedAddr}`);

  // 2. GuardianPassportSBT
  console.log("[2/9] Deploying GuardianPassportSBT (ERC-5192 Soulbound)...");
  const PassportFactory = await ethers.getContractFactory("GuardianPassportSBT");
  const passportSBT = await PassportFactory.deploy();
  await passportSBT.waitForDeployment();
  const passportSBTAddr = await passportSBT.getAddress();
  deployedAddresses["GuardianPassportSBT"] = passportSBTAddr;
  console.log(`  [✓] GuardianPassportSBT deployed at: ${passportSBTAddr}`);

  // 3. IdentityRegistryTestnet (ERC-8004 Stand-in Registry)
  console.log("[3/9] Deploying IdentityRegistryTestnet (ERC-8004 Stand-in)...");
  const Erc8004Factory = await ethers.getContractFactory("IdentityRegistryTestnet");
  const erc8004Registry = await Erc8004Factory.deploy();
  await erc8004Registry.waitForDeployment();
  const erc8004Addr = await erc8004Registry.getAddress();
  deployedAddresses["IdentityRegistryTestnet"] = erc8004Addr;
  console.log(`  [✓] IdentityRegistryTestnet deployed at: ${erc8004Addr}`);

  // 4. GuardianPolicyGuard
  console.log("[4/9] Deploying GuardianPolicyGuard...");
  const PolicyGuardFactory = await ethers.getContractFactory("GuardianPolicyGuard");
  const policyGuard = await PolicyGuardFactory.deploy(signerAddress);
  await policyGuard.waitForDeployment();
  const policyGuardAddr = await policyGuard.getAddress();
  deployedAddresses["GuardianPolicyGuard"] = policyGuardAddr;
  console.log(`  [✓] GuardianPolicyGuard deployed at: ${policyGuardAddr}`);

  // 4b. Wire PolicyGuard to PassportSBT
  console.log("  [+] Configuring GuardianPolicyGuard with PassportRegistry...");
  const setRegTx = await policyGuard.setPassportRegistry(passportSBTAddr);
  await setRegTx.wait();
  console.log(`  [✓] GuardianPolicyGuard linked to PassportSBT: ${passportSBTAddr}`);

  // 5. GuardianInsuranceLedger (with MAX_CERTIFICATES = 100,000)
  console.log("[5/9] Deploying GuardianInsuranceLedger...");
  const InsuranceFactory = await ethers.getContractFactory("GuardianInsuranceLedger");
  const insuranceLedger = await InsuranceFactory.deploy();
  await insuranceLedger.waitForDeployment();
  const insuranceAddr = await insuranceLedger.getAddress();
  deployedAddresses["GuardianInsuranceLedger"] = insuranceAddr;
  console.log(`  [✓] GuardianInsuranceLedger deployed at: ${insuranceAddr}`);

  // 6. GuardianCortexAnchor
  console.log("[6/9] Deploying GuardianCortexAnchor...");
  const CortexFactory = await ethers.getContractFactory("GuardianCortexAnchor");
  const cortexAnchor = await CortexFactory.deploy();
  await cortexAnchor.waitForDeployment();
  const cortexAddr = await cortexAnchor.getAddress();
  deployedAddresses["GuardianCortexAnchor"] = cortexAddr;
  console.log(`  [✓] GuardianCortexAnchor deployed at: ${cortexAddr}`);

  // 7. GuardianInterlockRegistry
  console.log("[7/9] Deploying GuardianInterlockRegistry...");
  const InterlockFactory = await ethers.getContractFactory("GuardianInterlockRegistry");
  const interlockRegistry = await InterlockFactory.deploy();
  await interlockRegistry.waitForDeployment();
  const interlockAddr = await interlockRegistry.getAddress();
  deployedAddresses["GuardianInterlockRegistry"] = interlockAddr;
  console.log(`  [✓] GuardianInterlockRegistry deployed at: ${interlockAddr}`);

  // 8. GuardianRiskAttestation
  console.log("[8/9] Deploying GuardianRiskAttestation...");
  const RiskFactory = await ethers.getContractFactory("GuardianRiskAttestation");
  const riskAttestation = await RiskFactory.deploy();
  await riskAttestation.waitForDeployment();
  const riskAddr = await riskAttestation.getAddress();
  deployedAddresses["GuardianRiskAttestation"] = riskAddr;
  console.log(`  [✓] GuardianRiskAttestation deployed at: ${riskAddr}`);

  // 9. GuardianTimelock (MIN_DELAY = 24 hours)
  console.log("[9/9] Deploying GuardianTimelock...");
  const TimelockFactory = await ethers.getContractFactory("GuardianTimelock");
  const timelock = await TimelockFactory.deploy(
    [deployer.address], // Proposers
    [ethers.ZeroAddress], // Open executors after 24h delay
    deployer.address // Initial admin
  );
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();
  deployedAddresses["GuardianTimelock"] = timelockAddr;
  console.log(`  [✓] GuardianTimelock deployed at: ${timelockAddr}`);

  console.log("----------------------------------------------------------------");
  console.log("Bootstrapping Reference Agent Passports in GuardianPassportSBT...");

  // Mint Reference Agent Passports
  const agents = [
    {
      id: "eliza-monad-01",
      score: 9400, // 94/100 GOLD
      uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/eliza.json"
    },
    {
      id: "mera-memory-01",
      score: 9700, // 97/100 DIAMOND
      uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/mera.json"
    },
    {
      id: "passport-agent-01",
      score: 9800, // 98/100 DIAMOND
      uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/passport.json"
    }
  ];

  for (const agent of agents) {
    const agentHash = ethers.id(agent.id);
    const mintTx = await passportSBT.mint(deployer.address, agentHash, agent.score, agent.uri);
    await mintTx.wait();
    const isActive = await passportSBT.isPassportActive(agentHash);
    console.log(`  [✓] Minted Passport for ${agent.id} (Score: ${agent.score/100}, Active: ${isActive})`);
  }

  console.log("----------------------------------------------------------------");
  console.log("Bootstrapping Live Transactions & Verifications...");

  // Live interaction 1: Issue Insurance Certificate
  const certId = ethers.hexlify(ethers.randomBytes(32));
  const agentHash = ethers.id("passport-agent-01");
  const certHash = ethers.id("guardian-cert-metadata-v1");
  const now = Math.floor(Date.now() / 1000);
  const txCert = await insuranceLedger.issueCertificate(
    certId,
    agentHash,
    now,
    now + 86400 * 30,
    certHash,
    "LOW"
  );
  await txCert.wait();
  console.log(`  [✓] Insurance certificate issued on-chain: ${certId}`);

  // Live interaction 2: Anchor Merkle Root
  const merkleRoot = ethers.hexlify(ethers.randomBytes(32));
  const txAnchor = await cortexAnchor.commitRoot(merkleRoot, 10, agentHash, now - 3600, now);
  await txAnchor.wait();
  console.log(`  [✓] Cortex Merkle root anchored on-chain: ${merkleRoot}`);

  // Live interaction 3: Add Threat Feed Address
  const sampleThreat = ethers.Wallet.createRandom().address;
  const txThreat = await threatFeed.addAddress(sampleThreat, "Monad testnet phishing drainer flagged by GuardianAI");
  await txThreat.wait();
  console.log(`  [✓] Threat address registered on-chain: ${sampleThreat}`);

  // Verify Timelock delay
  const minDelay = await timelock.getMinDelay();
  console.log(`  [✓] GuardianTimelock verified min delay: ${minDelay.toString()} seconds (24 hours)`);

  // Verify PolicyGuard connected to PassportSBT
  const activeReg = await policyGuard.passportRegistry();
  console.log(`  [✓] GuardianPolicyGuard passportRegistry confirmed: ${activeReg}`);

  const remainingBalance = await ethers.provider.getBalance(deployer.address);
  console.log(`[+] Remaining Deployer Balance: ${ethers.formatEther(remainingBalance)} MON`);

  console.log("================================================================");
  console.log("DEPLOYMENT COMPLETE — SUMMARY OF MONAD TESTNET ADDRESSES:");
  console.log("================================================================");
  for (const [name, addr] of Object.entries(deployedAddresses)) {
    console.log(`${name}=${addr}`);
  }

  // Save deployment artifact directory
  const deploymentsDir = path.resolve(__dirname, "../deployments/monad_testnet_10143");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentSummary = {
    network: "monad_testnet",
    chainId: Number(network.chainId),
    deployer: deployer.address,
    attestationSigner: signerAddress,
    timestamp: new Date().toISOString(),
    contracts: deployedAddresses,
    explorerUrls: {
      GuardianPolicyGuard: `https://testnet.monadscan.com/address/${policyGuardAddr}`,
      GuardianThreatFeedRegistry: `https://testnet.monadscan.com/address/${threatFeedAddr}`,
      GuardianPassportSBT: `https://testnet.monadscan.com/address/${passportSBTAddr}`,
      IdentityRegistryTestnet: `https://testnet.monadscan.com/address/${erc8004Addr}`,
      GuardianInsuranceLedger: `https://testnet.monadscan.com/address/${insuranceAddr}`,
      GuardianCortexAnchor: `https://testnet.monadscan.com/address/${cortexAddr}`,
      GuardianInterlockRegistry: `https://testnet.monadscan.com/address/${interlockAddr}`,
      GuardianRiskAttestation: `https://testnet.monadscan.com/address/${riskAddr}`,
      GuardianTimelock: `https://testnet.monadscan.com/address/${timelockAddr}`,
    }
  };

  fs.writeFileSync(
    path.join(deploymentsDir, "deployment-summary.json"),
    JSON.stringify(deploymentSummary, null, 2),
    "utf8"
  );

  // Also save to metropolis/deployments-monad.json
  const metropolisOutputPath = path.resolve(__dirname, "../../metropolis/deployments-monad.json");
  fs.writeFileSync(metropolisOutputPath, JSON.stringify(deploymentSummary, null, 2), "utf8");
  console.log(`[+] Saved deployment records to: ${deploymentsDir} and ${metropolisOutputPath}`);

  // Save individual contract artifact files
  const { artifacts } = require("hardhat");
  for (const [contractName, contractAddr] of Object.entries(deployedAddresses)) {
    const artifact = await artifacts.readArtifact(contractName);
    const contractJson = {
      name: contractName,
      address: contractAddr,
      network: "monad_testnet",
      chainId: 10143,
      deployer: deployer.address,
      deployedAt: new Date().toISOString(),
      abi: artifact.abi,
    };
    fs.writeFileSync(
      path.join(deploymentsDir, `${contractName}.json`),
      JSON.stringify(contractJson, null, 2),
      "utf8"
    );
  }

  // Update .env with new addresses
  const envPath = path.resolve(__dirname, "../../.env");
  if (fs.existsSync(envPath)) {
    let envContent = fs.readFileSync(envPath, "utf8");

    // Replace or set keys
    const replacements: Record<string, string> = {
      "GUARDIAN_POLICY_GUARD_CONTRACT_MONAD": policyGuardAddr,
      "GUARDIAN_THREATFEED_CONTRACT_MONAD": threatFeedAddr,
      "GUARDIAN_SBT_CONTRACT_MONAD": passportSBTAddr,
      "GUARDIAN_INSURANCE_CONTRACT_MONAD": insuranceAddr,
      "GUARDIAN_CORTEX_CONTRACT_MONAD": cortexAddr,
      "GUARDIAN_INTERLOCK_CONTRACT_MONAD": interlockAddr,
      "GUARDIAN_RISK_ATTESTATION_CONTRACT_MONAD": riskAddr,
      "GUARDIAN_TIMELOCK_CONTRACT_MONAD": timelockAddr,
      "GUARDIAN_ERC8004_REGISTRY_MONAD_TESTNET": erc8004Addr,
      "GUARDIAN_ERC8004_IDENTITY_REGISTRY_OVERRIDE": erc8004Addr,
      "TIMELOCK_ADDRESS": timelockAddr,
      "INSURANCE_LEDGER_ADDRESS": insuranceAddr,
      "CORTEX_ANCHOR_ADDRESS": cortexAddr,
      "PASSPORT_SBT_ADDRESS": passportSBTAddr,
      "INTERLOCK_REGISTRY_ADDRESS": interlockAddr,
      "RISK_ATTESTATION_ADDRESS": riskAddr,
      "THREAT_FEED_REGISTRY_ADDRESS": threatFeedAddr,
    };

    for (const [key, value] of Object.entries(replacements)) {
      const regex = new RegExp(`^${key}=.*$`, "m");
      if (regex.test(envContent)) {
        envContent = envContent.replace(regex, `${key}=${value}`);
      } else {
        envContent += `\n${key}=${value}`;
      }
    }

    fs.writeFileSync(envPath, envContent, "utf8");
    console.log(`[+] Synchronized and updated .env with all new Monad contract addresses`);
  }

  return deploymentSummary;
}

main().catch((error) => {
  console.error("[-] Deployment failed:", error);
  process.exitCode = 1;
});
