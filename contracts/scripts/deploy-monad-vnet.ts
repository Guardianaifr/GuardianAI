import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("===============================================================");
  console.log("Executing Transactions on Tenderly MONAD Virtual TestNet");
  console.log("Account:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "MON");
  console.log("===============================================================\n");

  const insuranceAddr = "0x2D77aDf9135949d6c59ba7A54FedA34Bd3C9c1aB";
  const cortexAddr = "0x242CdE982122ae2e723EA4E0CbA1eb563B2A32Fb";
  const threatAddr = "0xfCE78ABE17dE01A3fAdC55Bf38AFFDE95792C418";

  const insurance = await ethers.getContractAt("GuardianInsuranceLedger", insuranceAddr);
  const cortex = await ethers.getContractAt("GuardianCortexAnchor", cortexAddr);
  const threat = await ethers.getContractAt("GuardianThreatFeedRegistry", threatAddr);

  const now = Math.floor(Date.now() / 1000);
  const agentHash = ethers.id("agent-monad-production");

  // Tx 1: Issue Insurance Certificate
  console.log("Calling issueCertificate on InsuranceLedger at:", insuranceAddr);
  const certId = ethers.hexlify(ethers.randomBytes(32));
  const certHash = ethers.id("monad-cert-metadata-v1");
  const tx1 = await insurance.issueCertificate(certId, agentHash, now, now + 86400 * 30, certHash, "LOW");
  const r1 = await tx1.wait();
  console.log(" -> [Tx 1/3] issueCertificate confirmed! Hash:", r1?.hash);

  // Tx 2: Commit Merkle Root on Cortex Anchor
  console.log("Calling commitRoot on CortexAnchor at:", cortexAddr);
  const root = ethers.hexlify(ethers.randomBytes(32));
  const tx2 = await cortex.commitRoot(root, 100, agentHash, now - 3600, now);
  const r2 = await tx2.wait();
  console.log(" -> [Tx 2/3] commitRoot confirmed! Hash:", r2?.hash);

  // Tx 3: Add Threat on Threat Feed Registry
  console.log("Calling addAddress on ThreatFeedRegistry at:", threatAddr);
  const badActor = ethers.Wallet.createRandom().address;
  const tx3 = await threat.addAddress(badActor, "Malicious flashloan attacker on Monad");
  const r3 = await tx3.wait();
  console.log(" -> [Tx 3/3] addAddress confirmed! Hash:", r3?.hash);

  console.log("\n===============================================================");
  console.log("ALL TRANSACTIONS CONFIRMED ON TENDERLY MONAD VIRTUAL TESTNET!");
  console.log("===============================================================");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
