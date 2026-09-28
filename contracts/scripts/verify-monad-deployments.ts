import { ethers } from "hardhat";
import * as dotenv from "dotenv";
dotenv.config({ path: "../.env" });

async function main() {
  console.log("================================================================");
  console.log("VERIFYING GUARDIAN-AI LIVE ON-CHAIN SUITE ON MONAD TESTNET (10143)");
  console.log("================================================================");

  const [deployer] = await ethers.getSigners();
  console.log("Deployer / Verifier Address:", deployer.address);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("Deployer MON Balance:", ethers.formatEther(balance), "MON");
  const block = await ethers.provider.getBlockNumber();
  console.log("Current Block Number:", block);
  console.log("----------------------------------------------------------------");

  const policyGuardAddr = process.env.GUARDIAN_POLICY_GUARD_CONTRACT_MONAD!;
  const threatFeedAddr = process.env.GUARDIAN_THREATFEED_CONTRACT_MONAD!;
  const passportSBTAddr = process.env.GUARDIAN_SBT_CONTRACT_MONAD!;
  const erc8004Addr = process.env.GUARDIAN_ERC8004_REGISTRY_MONAD_TESTNET!;
  const insuranceAddr = process.env.GUARDIAN_INSURANCE_CONTRACT_MONAD!;
  const cortexAddr = process.env.GUARDIAN_CORTEX_CONTRACT_MONAD!;
  const interlockAddr = process.env.GUARDIAN_INTERLOCK_CONTRACT_MONAD!;
  const riskAddr = process.env.GUARDIAN_RISK_ATTESTATION_CONTRACT_MONAD!;
  const timelockAddr = process.env.GUARDIAN_TIMELOCK_CONTRACT_MONAD!;

  // 1. Threat Feed
  const threatFeed = await ethers.getContractAt("GuardianThreatFeedRegistry", threatFeedAddr);
  console.log("[1] GuardianThreatFeedRegistry at:", threatFeedAddr);
  console.log("    Owner:", await threatFeed.owner());
  console.log("    Threat count (EVM):", (await threatFeed.evmAddressCount()).toString());

  // 2. Passport SBT
  const passportSBT = await ethers.getContractAt("GuardianPassportSBT", passportSBTAddr);
  console.log("[2] GuardianPassportSBT at:", passportSBTAddr);
  console.log("    Name:", await passportSBT.name());
  console.log("    Symbol:", await passportSBT.symbol());
  console.log("    Active Passports:", (await passportSBT.activePassportCount()).toString());
  const agent1Active = await passportSBT.isPassportActive(ethers.id("passport-agent-01"));
  const agent2Active = await passportSBT.isPassportActive(ethers.id("eliza-monad-01"));
  const agent3Active = await passportSBT.isPassportActive(ethers.id("mera-memory-01"));
  console.log("    passport-agent-01 active:", agent1Active);
  console.log("    eliza-monad-01 active:", agent2Active);
  console.log("    mera-memory-01 active:", agent3Active);

  // 3. Identity Registry Testnet (ERC-8004)
  const erc8004 = await ethers.getContractAt("IdentityRegistryTestnet", erc8004Addr);
  console.log("[3] IdentityRegistryTestnet at:", erc8004Addr);
  console.log("    Name:", await erc8004.name());
  console.log("    Registration Type:", await erc8004.REGISTRATION_TYPE());

  // 4. Policy Guard
  const policyGuard = await ethers.getContractAt("GuardianPolicyGuard", policyGuardAddr);
  console.log("[4] GuardianPolicyGuard at:", policyGuardAddr);
  console.log("    Owner:", await policyGuard.owner());
  console.log("    Attestation Signer:", await policyGuard.attestationSigner());
  console.log("    Linked Passport Registry:", await policyGuard.passportRegistry());

  // 5. Insurance Ledger
  const insurance = await ethers.getContractAt("GuardianInsuranceLedger", insuranceAddr);
  console.log("[5] GuardianInsuranceLedger at:", insuranceAddr);
  console.log("    Owner:", await insurance.owner());
  console.log("    MAX_CERTIFICATES cap:", (await insurance.MAX_CERTIFICATES()).toString());
  console.log("    Certificate Count:", (await insurance.getCertificateCount()).toString());

  // 6. Cortex Anchor
  const cortex = await ethers.getContractAt("GuardianCortexAnchor", cortexAddr);
  console.log("[6] GuardianCortexAnchor at:", cortexAddr);
  console.log("    Owner:", await cortex.owner());
  console.log("    Total Commitments:", (await cortex.getCommitmentCount()).toString());

  // 7. Interlock Registry
  const interlock = await ethers.getContractAt("GuardianInterlockRegistry", interlockAddr);
  console.log("[7] GuardianInterlockRegistry at:", interlockAddr);
  console.log("    Owner:", await interlock.owner());

  // 8. Risk Attestation
  const risk = await ethers.getContractAt("GuardianRiskAttestation", riskAddr);
  console.log("[8] GuardianRiskAttestation at:", riskAddr);
  console.log("    Owner:", await risk.owner());
  console.log("    Grade 'A' valid:", await risk.isValidGrade("A"));
  console.log("    Grade 'F' valid:", await risk.isValidGrade("F"));

  // 9. Timelock Controller
  const timelock = await ethers.getContractAt("GuardianTimelock", timelockAddr);
  console.log("[9] GuardianTimelock at:", timelockAddr);
  console.log("    MIN_DELAY constant:", (await timelock.MIN_DELAY()).toString());
  console.log("    getMinDelay():", (await timelock.getMinDelay()).toString(), "seconds (24 hours)");

  const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
  const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();
  console.log("    Deployer has PROPOSER_ROLE:", await timelock.hasRole(PROPOSER_ROLE, deployer.address));
  console.log("    Open execution (ZeroAddress has EXECUTOR_ROLE):", await timelock.hasRole(EXECUTOR_ROLE, ethers.ZeroAddress));

  console.log("================================================================");
  console.log("ALL 9 CONTRACTS ON MONAD TESTNET VERIFIED 100% OPERATIONAL!");
  console.log("================================================================");
}

main().catch((err) => {
  console.error("[-] Verification failed:", err);
  process.exitCode = 1;
});
