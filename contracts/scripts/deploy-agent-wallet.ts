/**
 * Deploy the on-chain enforcement layer for the hackathon demo on Monad testnet:
 *   1. GuardianThreatOracle  (Chainlink CRE receiver; forwarder = CRE_FORWARDER or the simulation MockKeystoneForwarder)
 *   2. GuardianAgentWalletFactory (guardianSigner = GUARDIAN_ATTESTATION_SIGNER, passport = PassportSBT)
 *   3. a GuardianAgentWallet for the Privy agent (operator = Privy wallet, owner = deployer), wired to the oracle
 *   4. funds the wallet with AGENT_WALLET_FUND_MON (default 0.2) MON
 * Results are merged into metropolis/deployments-monad.json.
 *
 *   node node_modules/hardhat/internal/cli/bootstrap.js run scripts/deploy-agent-wallet.ts --network monad_testnet
 */
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const SIM_FORWARDER_MONAD = "0xB9F79d863261869B234c481D1f9A7af84AeAd192"; // CRE MockKeystoneForwarder (simulation)
const ROOT = path.resolve(__dirname, "..", "..");
const DEPLOYMENTS = path.join(ROOT, "metropolis", "deployments-monad.json");
const PRIVY_STATE = path.join(ROOT, "tools", "privy-agent", ".state.json");

async function main() {
  const [deployer] = await ethers.getSigners();
  const dep = JSON.parse(fs.readFileSync(DEPLOYMENTS, "utf8"));
  const signer = process.env.GUARDIAN_ATTESTATION_SIGNER;
  if (!signer) throw new Error("GUARDIAN_ATTESTATION_SIGNER not set");
  if (ethers.getAddress(signer) === deployer.address) throw new Error("Attestation signer must not be the deployer key");
  const passport = dep.contracts.GuardianPassportSBT;
  const operator = process.env.AGENT_OPERATOR || JSON.parse(fs.readFileSync(PRIVY_STATE, "utf8")).address;
  const agentIdStr = `privy-agent:${operator.toLowerCase()}`;
  const agentId = ethers.keccak256(ethers.toUtf8Bytes(agentIdStr));
  const forwarder = process.env.CRE_FORWARDER || SIM_FORWARDER_MONAD;

  console.log(`deployer ${deployer.address}  balance ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} MON`);
  console.log(`signer ${signer}  operator ${operator}  agent_id ${agentIdStr}`);

  let oracleAddr = dep.contracts.GuardianThreatOracle;
  if (!oracleAddr) {
    const oracle = await (await ethers.getContractFactory("GuardianThreatOracle")).deploy(forwarder);
    await oracle.waitForDeployment();
    oracleAddr = await oracle.getAddress();
    console.log(`GuardianThreatOracle ${oracleAddr} (forwarder ${forwarder})`);
  }

  let factoryAddr = dep.contracts.GuardianAgentWalletFactory;
  if (!factoryAddr) {
    const f = await (await ethers.getContractFactory("GuardianAgentWalletFactory")).deploy(signer, passport);
    await f.waitForDeployment();
    factoryAddr = await f.getAddress();
    console.log(`GuardianAgentWalletFactory ${factoryAddr}`);
  }
  const factory = await ethers.getContractAt("GuardianAgentWalletFactory", factoryAddr);

  let walletAddr = await factory.walletOf(deployer.address, agentId);
  if (walletAddr === ethers.ZeroAddress) {
    const tx = await factory.createWallet(operator, agentId);
    const r = await tx.wait();
    walletAddr = await factory.walletOf(deployer.address, agentId);
    console.log(`GuardianAgentWallet ${walletAddr}  tx ${r!.hash}`);
  }
  const wallet = await ethers.getContractAt("GuardianAgentWallet", walletAddr);
  if ((await wallet.threatOracle()) !== oracleAddr) {
    await (await wallet.setThreatOracle(oracleAddr)).wait();
    console.log(`wallet.setThreatOracle(${oracleAddr})`);
  }
  const fund = ethers.parseEther(process.env.AGENT_WALLET_FUND_MON || "0.2");
  if ((await ethers.provider.getBalance(walletAddr)) < fund) {
    await (await deployer.sendTransaction({ to: walletAddr, value: fund })).wait();
    console.log(`funded wallet with ${ethers.formatEther(fund)} MON`);
  }

  dep.contracts.GuardianThreatOracle = oracleAddr;
  dep.contracts.GuardianAgentWalletFactory = factoryAddr;
  dep.agentWallets = dep.agentWallets || {};
  dep.agentWallets[agentIdStr] = { wallet: walletAddr, owner: deployer.address, operator, agentId };
  dep.creForwarder = forwarder;
  for (const [k, v] of Object.entries({ GuardianThreatOracle: oracleAddr, GuardianAgentWalletFactory: factoryAddr, GuardianAgentWallet: walletAddr })) {
    dep.explorerUrls[k] = `https://testnet.monadscan.com/address/${v}`;
  }
  fs.writeFileSync(DEPLOYMENTS, JSON.stringify(dep, null, 2) + "\n");
  console.log("\nSummary:", JSON.stringify({ oracleAddr, factoryAddr, walletAddr, operator, agentIdStr }, null, 2));
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
