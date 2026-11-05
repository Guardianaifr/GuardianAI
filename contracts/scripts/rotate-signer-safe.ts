/**
 * Point the Safe-owned contracts at a new GuardianAI attestation signer.
 *
 * The new signer address comes from GUARDIAN_ATTESTATION_SIGNER in ../.env. This script only writes a
 * Safe Transaction Builder batch; the Safe signers approve and execute it. Nothing is sent from here.
 *
 *   npx hardhat run scripts/rotate-signer-safe.ts --network monad_testnet                 (writes the batch)
 *   set "FORK_MONAD=1" & set "REHEARSE=1" & npx hardhat run scripts/rotate-signer-safe.ts  (fork rehearsal)
 *
 * Not covered: GuardianAgentWalletFactory stores the signer as immutable, so wallets it creates from now on
 * still trust the old signer until the factory (and GuardianPassportIssuer, which pins the factory) is
 * redeployed. Wallets owned by other people must be updated by their owners (setGuardianSigner).
 */
import * as fs from "fs";
import * as path from "path";
import { ethers, network } from "hardhat";

const SAFE = "0x402b0Dad9098942c9fF34c8Be1da037C72BFd81a";
const TARGETS = [
  { name: "GuardianPolicyGuard", addr: "0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d", getter: "attestationSigner", setter: "setAttestationSigner" },
  { name: "GuardianAgentWallet (demo)", addr: "0x356EfbC397B104F90795E89F0b755aa5AE4967DD", getter: "guardianSigner", setter: "setGuardianSigner" },
];
const BATCH_FILE = path.join(__dirname, "..", "deployments", "monad_testnet_10143", "rotate-signer.safe-batch.json");

const iface = (t: (typeof TARGETS)[number]) => new ethers.Interface([
  `function ${t.getter}() view returns (address)`, "function owner() view returns (address)", `function ${t.setter}(address)`,
]);

async function show(label: string) {
  console.log(`\n${label}`);
  for (const t of TARGETS) {
    const c = new ethers.Contract(t.addr, iface(t), ethers.provider);
    console.log(`  ${t.name.padEnd(28)} signer ${await c[t.getter]()}  owner ${await c.owner()}`);
  }
}

async function main() {
  if (process.env.FORK_MONAD === "1") await network.provider.send("evm_mine", []); // Monad fork: read on a fresh local block
  const newSigner = ethers.getAddress(process.env.GUARDIAN_ATTESTATION_SIGNER || "");
  const key = process.env.GUARDIAN_ATTESTATION_SIGNER_KEY || "";
  if (new ethers.Wallet(key).address !== newSigner) throw new Error("GUARDIAN_ATTESTATION_SIGNER does not match GUARDIAN_ATTESTATION_SIGNER_KEY in .env");
  if ((await ethers.provider.getCode(newSigner)) !== "0x") throw new Error("new signer must be an EOA");
  console.log(`new signer: ${newSigner}`);

  const txs = [];
  for (const t of TARGETS) {
    const c = new ethers.Contract(t.addr, iface(t), ethers.provider);
    if ((await c.owner()).toLowerCase() !== SAFE.toLowerCase()) throw new Error(`${t.name} is not owned by the Safe`);
    if ((await c[t.getter]()).toLowerCase() === newSigner.toLowerCase()) { console.log(`  ${t.name}: already on the new signer`); continue; }
    txs.push({ to: t.addr, value: "0", data: iface(t).encodeFunctionData(t.setter, [newSigner]), contractMethod: null, contractInputsValues: null });
  }
  await show("before");

  if (process.env.REHEARSE === "1") {
    if (network.name !== "hardhat" || process.env.FORK_MONAD !== "1") throw new Error("REHEARSE=1 needs FORK_MONAD=1");
    await network.provider.request({ method: "hardhat_impersonateAccount", params: [SAFE] });
    await network.provider.send("hardhat_setBalance", [SAFE, "0x56BC75E2D63100000"]);
    const safe = await ethers.getSigner(SAFE); // stands in for the 2-of-3 execution
    for (const tx of txs) await (await safe.sendTransaction({ to: tx.to, data: tx.data })).wait();
    await show("after (fork)");
    for (const t of TARGETS) {
      const c = new ethers.Contract(t.addr, iface(t), ethers.provider);
      if ((await c[t.getter]()).toLowerCase() !== newSigner.toLowerCase()) throw new Error(`${t.name} not rotated`);
    }
    return console.log("\nrehearsal passed: both contracts trust only the new signer");
  }

  if (network.name !== "monad_testnet") throw new Error("use --network monad_testnet, or REHEARSE=1 with FORK_MONAD=1");
  if (txs.length === 0) return console.log("nothing to do");
  fs.writeFileSync(BATCH_FILE, JSON.stringify({
    version: "1.0", chainId: "10143", createdAt: Date.now(),
    meta: { name: "GuardianAI: rotate attestation signer", description: `Point PolicyGuard and the demo wallet at ${newSigner}` },
    transactions: txs,
  }, null, 2) + "\n");
  console.log(`\nSafe batch written (${txs.length} transactions): ${path.relative(process.cwd(), BATCH_FILE)}`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
