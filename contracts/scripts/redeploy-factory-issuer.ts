/**
 * Redeploy GuardianAgentWalletFactory (its signer is immutable) and GuardianPassportIssuer (its factory is
 * immutable) so new console wallets trust the rotated attestation signer.
 *
 * 1. Deploy (any funded key; the deployer key in ../.env is used). Nothing it deploys is owned by it:
 *    the factory has no owner, and the issuer is owned by the Safe from its constructor.
 *      npx hardhat run scripts/redeploy-factory-issuer.ts --network monad_testnet              (dry run)
 *      set "CONFIRM=1" & npx hardhat run scripts/redeploy-factory-issuer.ts --network monad_testnet
 *    Writes deployments/monad_testnet_10143/factory-issuer-v2.json and the Safe batch
 *    deployments/monad_testnet_10143/move-passport-to-issuer-v2.safe-batch.json.
 * 2. The Safe executes the batch: old issuer hands the passport SBT to the new issuer, the new issuer
 *    accepts, and the claim settings are copied.
 *
 * Rehearse everything on a fork first, including a real payment from a new wallet (nothing is broadcast):
 *      set "FORK_MONAD=1" & set "REHEARSE=1" & npx hardhat run scripts/redeploy-factory-issuer.ts
 *
 * Wallets created by the OLD factory keep trusting the old signer; their owners must call
 * setGuardianSigner themselves. They also cannot claim through the new issuer.
 */
import * as fs from "fs";
import * as path from "path";
import { ethers, network } from "hardhat";

const SAFE = "0x402b0Dad9098942c9fF34c8Be1da037C72BFd81a";
const DEPLOYER = "0x1D4549B95dccAC8203393543187b25B3137D0bf6";
const SBT = "0xb2a8FeF3591efbd385778906207A054af0Ca3566";
const OLD_FACTORY = "0xAb3aE67587D946e63b3cfFb32C9e32d701B8Ef03";
const OLD_ISSUER = "0x9c4acFb906EBF32c2C5115F3D84ab6Db809f2Dd1";
const DIR = path.join(__dirname, "..", "deployments", "monad_testnet_10143");
const OUT = path.join(DIR, "factory-issuer-v2.json");
const BATCH = path.join(DIR, "move-passport-to-issuer-v2.safe-batch.json");

type Signer = Awaited<ReturnType<typeof ethers.getSigner>>;

function newSigner() {
  const key = process.env.GUARDIAN_ATTESTATION_SIGNER_KEY || "";
  const wallet = new ethers.Wallet(key);
  if (wallet.address !== ethers.getAddress(process.env.GUARDIAN_ATTESTATION_SIGNER || "0x" + "0".repeat(40)))
    throw new Error("GUARDIAN_ATTESTATION_SIGNER does not match GUARDIAN_ATTESTATION_SIGNER_KEY in .env");
  return wallet;
}

async function safeBatch(newIssuer: string) {
  const old = await ethers.getContractAt("GuardianPassportIssuer", OLD_ISSUER);
  const open = await old.claimsOpen();
  const cap = await old.claimCap();
  const used = await old.claimCount();
  // Carry over what is left of the old cap (0 means "no cap", so a used-up cap closes claims instead).
  const left = cap === 0n ? 0n : cap - used;
  const issuer = await ethers.getContractAt("GuardianPassportIssuer", newIssuer);
  return [
    { to: OLD_ISSUER, data: old.interface.encodeFunctionData("transferPassportOwnership", [newIssuer]) },
    { to: newIssuer, data: issuer.interface.encodeFunctionData("acceptPassportOwnership") },
    { to: newIssuer, data: issuer.interface.encodeFunctionData("setClaims", [open && (cap === 0n || left > 0n), left]) },
  ];
}

async function deploy(deployer: Signer, signer: string) {
  const Factory = await ethers.getContractFactory("GuardianAgentWalletFactory", deployer);
  const factory = await Factory.deploy(signer, SBT);
  await factory.waitForDeployment();
  const Issuer = await ethers.getContractFactory("GuardianPassportIssuer", deployer);
  const issuer = await Issuer.deploy(SBT, await factory.getAddress(), SAFE);
  await issuer.waitForDeployment();
  return { factory: await factory.getAddress(), issuer: await issuer.getAddress(),
    factoryTx: factory.deploymentTransaction()!.hash, issuerTx: issuer.deploymentTransaction()!.hash };
}

async function check(addrs: { factory: string; issuer: string }, signer: string) {
  const f = await ethers.getContractAt("GuardianAgentWalletFactory", addrs.factory);
  const i = await ethers.getContractAt("GuardianPassportIssuer", addrs.issuer);
  const ok = (await f.guardianSigner()) === signer && (await f.passportRegistry()) === SBT
    && (await i.owner()) === SAFE && (await i.factory()) === addrs.factory && (await i.passport()) === SBT;
  if (!ok) throw new Error("deployed contracts are not configured as expected");
  console.log(`  factory ${addrs.factory}: signer ${signer}, passport registry ${SBT}`);
  console.log(`  issuer  ${addrs.issuer}: owner ${SAFE} (Safe), factory and passport as above`);
}

async function rehearse() {
  await network.provider.send("evm_mine", []);
  const signer = newSigner();
  for (const a of [DEPLOYER, SAFE]) {
    await network.provider.request({ method: "hardhat_impersonateAccount", params: [a] });
    await network.provider.send("hardhat_setBalance", [a, "0x56BC75E2D63100000"]);
  }
  console.log("--- fork rehearsal ---\n1. deploy");
  const addrs = await deploy(await ethers.getSigner(DEPLOYER), signer.address);
  await check(addrs, signer.address);

  console.log("2. Safe executes the batch");
  const safe = await ethers.getSigner(SAFE);
  for (const tx of await safeBatch(addrs.issuer)) await (await safe.sendTransaction(tx)).wait();
  const sbt = await ethers.getContractAt("GuardianPassportSBT", SBT);
  const issuer = await ethers.getContractAt("GuardianPassportIssuer", addrs.issuer);
  console.log(`  SBT owner now ${await sbt.owner()} (new issuer: ${(await sbt.owner()) === addrs.issuer})`);
  console.log(`  claims open ${await issuer.claimsOpen()}, cap ${await issuer.claimCap()}`);

  console.log("3. a new user: wallet from the new factory, ID card, then a payment approved by the new signer");
  const user = ethers.Wallet.createRandom().connect(ethers.provider);
  const operator = ethers.Wallet.createRandom().connect(ethers.provider);
  for (const a of [user.address, operator.address]) await network.provider.send("hardhat_setBalance", [a, "0x8AC7230489E80000"]);
  const factory = await ethers.getContractAt("GuardianAgentWalletFactory", addrs.factory, user);
  const agentId = ethers.id(`console:${user.address.toLowerCase()}`);
  await (await factory.createWallet(operator.address, agentId)).wait();
  const walletAddr = await factory.walletOf(user.address, agentId);
  await (await issuer.connect(user).claim(agentId)).wait();
  await (await user.sendTransaction({ to: walletAddr, value: ethers.parseEther("1") })).wait();

  const wallet = await ethers.getContractAt("GuardianAgentWallet", walletAddr, operator);
  const to = ethers.Wallet.createRandom().address;
  const now = (await ethers.provider.getBlock("latest"))!.timestamp;
  const att = { agentId, targetContract: to, calldataHash: ethers.keccak256("0x"), value: ethers.parseEther("0.01"),
    riskScore: 0, nonce: BigInt(ethers.hexlify(ethers.randomBytes(16))), deadline: BigInt(now + 600) };
  const domain = { name: "GuardianAgentWallet", version: "1", chainId: 10143, verifyingContract: walletAddr };
  const types = { SafetyAttestation: [
    { name: "agentId", type: "bytes32" }, { name: "targetContract", type: "address" }, { name: "calldataHash", type: "bytes32" },
    { name: "value", type: "uint256" }, { name: "riskScore", type: "uint8" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] };

  let forgedRefused = false;
  try {
    const forged = await ethers.Wallet.createRandom().signTypedData(domain, types, att);
    await wallet.execute.staticCall(to, att.value, "0x", att, forged);
  } catch (e: any) {
    forgedRefused = e?.revert?.name === "InvalidAttestationSignature" || /InvalidAttestationSignature/.test(String(e?.message ?? e));
    if (!forgedRefused) console.log(`  forged approval failed for another reason: ${e?.shortMessage ?? e?.message}`);
  }
  await (await wallet.execute(to, att.value, "0x", att, await signer.signTypedData(domain, types, att))).wait();
  const received = await ethers.provider.getBalance(to);
  console.log(`  payment with the new signer's approval: recipient got ${ethers.formatEther(received)} MON`);
  console.log(`  approval from any other key refused: ${forgedRefused}`);
  if (received !== att.value || !forgedRefused) throw new Error("rehearsal failed");
  console.log("\nrehearsal passed");
}

async function main() {
  if (process.env.REHEARSE === "1") {
    if (network.name !== "hardhat" || process.env.FORK_MONAD !== "1") throw new Error("REHEARSE=1 needs FORK_MONAD=1");
    return rehearse();
  }
  if (network.name !== "monad_testnet") throw new Error("use --network monad_testnet, or REHEARSE=1 with FORK_MONAD=1");
  const signer = newSigner().address;
  const [deployer] = await ethers.getSigners();

  let addrs: { factory: string; issuer: string };
  if (fs.existsSync(OUT)) {
    addrs = JSON.parse(fs.readFileSync(OUT, "utf8"));
    console.log(`already deployed (${path.relative(process.cwd(), OUT)}); checking and rewriting the Safe batch`);
  } else {
    console.log(`deployer ${deployer.address}, balance ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} MON`);
    console.log(`will deploy GuardianAgentWalletFactory(signer ${signer}, registry ${SBT}) and GuardianPassportIssuer(owner ${SAFE})`);
    if (process.env.CONFIRM !== "1") return console.log("dry run: add CONFIRM=1 to deploy");
    const d = await deploy(deployer, signer);
    addrs = { factory: d.factory, issuer: d.issuer };
    fs.writeFileSync(OUT, JSON.stringify({ network: "monad_testnet", chainId: 10143, deployedAt: new Date().toISOString(),
      guardianSigner: signer, passportSBT: SBT, safe: SAFE, replaces: { factory: OLD_FACTORY, issuer: OLD_ISSUER },
      GuardianAgentWalletFactory: d.factory, GuardianPassportIssuer: d.issuer, txs: { factory: d.factoryTx, issuer: d.issuerTx } }, null, 2) + "\n");
  }
  await check(addrs, signer);
  const txs = await safeBatch(addrs.issuer);
  fs.writeFileSync(BATCH, JSON.stringify({ version: "1.0", chainId: "10143", createdAt: Date.now(),
    meta: { name: "GuardianAI: move passport SBT to issuer v2", description: `Old issuer hands the SBT to ${addrs.issuer}; it accepts and copies the claim settings` },
    transactions: txs.map((t) => ({ to: t.to, value: "0", data: t.data, contractMethod: null, contractInputsValues: null })) }, null, 2) + "\n");
  console.log(`\nSafe batch written (3 transactions): ${path.relative(process.cwd(), BATCH)}`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
