/**
 * Hand admin control of the deployed GuardianAI contracts from the deployer EOA to NEW_OWNER:
 * a Safe multisig (recommended) or GuardianTimelock.
 *
 * Every contract here is Ownable2Step: transferOwnership() only NOMINATES the new owner, and nothing
 * changes until the new owner calls acceptOwnership(). (The older transfer_ownership_to_timelock.js
 * stopped after the nomination, so ownership never actually moved.)
 *
 * 0. Rehearse on a local fork first (nothing is broadcast):
 *      FORK_MONAD=1 REHEARSE=1 NEW_OWNER=0xYourSafe npx hardhat run scripts/handover-ownership.ts
 *
 * 1. Nominate (signed by the deployer key, GUARDIAN_DEPLOYER_PRIVATE_KEY in ../.env):
 *      NEW_OWNER=0xYourSafe npx hardhat run scripts/handover-ownership.ts --network monad_testnet             (dry run)
 *      NEW_OWNER=0xYourSafe CONFIRM=1 npx hardhat run scripts/handover-ownership.ts --network monad_testnet   (sends)
 *    Also writes deployments/monad_testnet_10143/accept-ownership.safe-batch.json.
 *
 * 2. Accept (signed by the new owner):
 *    Safe:     Safe{Wallet} > Apps > Transaction Builder > drag in accept-ownership.safe-batch.json, sign, execute.
 *    Timelock: STEP=timelock-schedule CONFIRM=1 ... --network monad_testnet   (deployer is still the proposer)
 *              then 24h later:
 *              STEP=timelock-execute CONFIRM=1 ... --network monad_testnet
 *
 * Windows cmd:  set NEW_OWNER=0x... && set CONFIRM=1 && npx hardhat run ...
 * PowerShell:   $env:NEW_OWNER="0x..."; $env:CONFIRM="1"; npx hardhat run ...
 */
import * as fs from "fs";
import * as path from "path";
import { ethers, network } from "hardhat";

export const DEPLOYER = "0x1D4549B95dccAC8203393543187b25B3137D0bf6";
export const TIMELOCK = "0xBBcBd965DB982d4A1aC01CADb1C98d4e86a2b1dc";

// Current Monad testnet deployment (README, 2026-10-19). GuardianPassportSBT is owned by
// GuardianPassportIssuer, so it moves with the issuer and is not listed.
export const CONTRACTS: Record<string, string> = {
  GuardianPolicyGuard: "0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d",
  GuardianThreatFeedRegistry: "0x576CC248D8c406ac302b74e7BFd571E9F989f467",
  GuardianInsuranceLedger: "0x671F73068BF55a30299719D76db0d3031A64Bb22",
  GuardianCortexAnchor: "0x78aFC34a9653c762cA9827370A94a02f7412dBfa",
  GuardianInterlockRegistry: "0x03bd6268f886DE88670B66FAC71cBd3CcC35D67d",
  GuardianRiskAttestation: "0x7e0631bB10ABAE7dd6D8b7A0762e9f9Ab81d6c87",
  GuardianThreatOracle: "0x26144375c4f846174A386C464aC5F2e671EbdA95",
  GuardianPassportIssuer: "0x9c4acFb906EBF32c2C5115F3D84ab6Db809f2Dd1",
  GuardianAgentWallet: "0x356EfbC397B104F90795E89F0b755aa5AE4967DD", // demo wallet: owner gets ownerExecute
};

const ABI = [
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function transferOwnership(address)",
  "function acceptOwnership()",
];
const OWNABLE = new ethers.Interface(ABI);
const ACCEPT_DATA = OWNABLE.encodeFunctionData("acceptOwnership");
const SALT = ethers.id("guardianai-ownership-handover-v1");
const BATCH_FILE = path.join(__dirname, "..", "deployments", "monad_testnet_10143", "accept-ownership.safe-batch.json");

type Signer = Awaited<ReturnType<typeof ethers.getSigner>>;

async function status(newOwner: string) {
  const rows: { name: string; addr: string; owner: string; pending: string }[] = [];
  for (const [name, addr] of Object.entries(CONTRACTS)) {
    const c = new ethers.Contract(addr, ABI, ethers.provider);
    rows.push({ name, addr, owner: await c.owner(), pending: await c.pendingOwner() });
  }
  for (const r of rows) {
    const tag = r.owner.toLowerCase() === newOwner.toLowerCase() ? "DONE"
      : r.pending.toLowerCase() === newOwner.toLowerCase() ? "nominated, awaiting accept"
      : r.owner.toLowerCase() === DEPLOYER.toLowerCase() ? "deployer-owned" : "OTHER OWNER (skipped)";
    console.log(`  ${r.name.padEnd(28)} owner ${r.owner}  ${tag}`);
  }
  return rows;
}

/** Step 1: deployer nominates NEW_OWNER on every contract it still owns. */
export async function nominate(deployer: Signer, newOwner: string, confirm: boolean, writeBatch = true) {
  const rows = await status(newOwner);
  const todo = rows.filter((r) => r.owner.toLowerCase() === DEPLOYER.toLowerCase()
    && r.pending.toLowerCase() !== newOwner.toLowerCase());
  console.log(`\n${todo.length} contract(s) to nominate ${newOwner} on${confirm ? "" : " (dry run: add CONFIRM=1 to send)"}`);
  for (const r of todo) {
    if (!confirm) { console.log(`  would call transferOwnership on ${r.name}`); continue; }
    const tx = await new ethers.Contract(r.addr, ABI, deployer).transferOwnership(newOwner);
    await tx.wait();
    console.log(`  nominated on ${r.name}: ${tx.hash}`);
  }
  if (writeBatch) writeSafeBatch(newOwner);
}

// acceptOwnership reverts unless the caller is the pending owner, so run the batch only after nominating.
const ACCEPT_TARGETS = Object.values(CONTRACTS);

function writeSafeBatch(newOwner: string) {
  const batch = {
    version: "1.0",
    chainId: "10143",
    createdAt: Date.now(),
    meta: {
      name: "GuardianAI: accept contract ownership",
      description: `acceptOwnership() on every GuardianAI contract nominated to ${newOwner}`,
    },
    transactions: ACCEPT_TARGETS.map((to) => ({
      to, value: "0", data: ACCEPT_DATA, contractMethod: null, contractInputsValues: null,
    })),
  };
  fs.writeFileSync(BATCH_FILE, JSON.stringify(batch, null, 2) + "\n");
  console.log(`\nSafe Transaction Builder batch written: ${path.relative(process.cwd(), BATCH_FILE)}`);
}

function timelockBatch() {
  const targets = ACCEPT_TARGETS;
  return { targets, values: targets.map(() => 0n), payloads: targets.map(() => ACCEPT_DATA) };
}

/** Step 2 (timelock only): the timelock must call acceptOwnership itself, via schedule + 24h + execute. */
export async function timelockSchedule(proposer: Signer, confirm: boolean) {
  const tl = await ethers.getContractAt("GuardianTimelock", TIMELOCK, proposer);
  const { targets, values, payloads } = timelockBatch();
  const delay = await tl.getMinDelay();
  console.log(`scheduleBatch: acceptOwnership on ${targets.length} contracts, executable after ${delay}s`);
  if (!confirm) return console.log("  dry run: add CONFIRM=1 to send");
  const tx = await tl.scheduleBatch(targets, values, payloads, ethers.ZeroHash, SALT, delay);
  await tx.wait();
  console.log(`  scheduled: ${tx.hash}`);
}

export async function timelockExecute(executor: Signer, confirm: boolean) {
  const tl = await ethers.getContractAt("GuardianTimelock", TIMELOCK, executor);
  const { targets, values, payloads } = timelockBatch();
  const id = await tl.hashOperationBatch(targets, values, payloads, ethers.ZeroHash, SALT);
  if (!(await tl.isOperationReady(id))) {
    const ts = await tl.getTimestamp(id);
    return console.log(ts === 0n ? "not scheduled yet: run STEP=timelock-schedule first"
      : `not ready until ${new Date(Number(ts) * 1000).toISOString()}`);
  }
  if (!confirm) return console.log("ready. dry run: add CONFIRM=1 to send");
  const tx = await tl.executeBatch(targets, values, payloads, ethers.ZeroHash, SALT);
  await tx.wait();
  console.log(`  executed: ${tx.hash}`);
}

async function rehearse(newOwner: string) {
  await network.provider.send("evm_mine", []); // Monad fork: run on a fresh local block
  for (const a of [DEPLOYER, newOwner]) {
    await network.provider.request({ method: "hardhat_impersonateAccount", params: [a] });
    await network.provider.send("hardhat_setBalance", [a, "0x56BC75E2D63100000"]); // 100 MON, fork only
  }
  const deployer = await ethers.getSigner(DEPLOYER);
  console.log(`--- rehearsal on a fork, new owner ${newOwner} ---`);
  await nominate(deployer, newOwner, true, false);

  if (newOwner.toLowerCase() === TIMELOCK.toLowerCase()) {
    await timelockSchedule(deployer, true);
    await timelockExecute(deployer, true); // too early: must refuse
    await network.provider.send("evm_increaseTime", [24 * 3600 + 1]);
    await network.provider.send("evm_mine", []);
    await timelockExecute(deployer, true);
  } else {
    const owner = await ethers.getSigner(newOwner); // stands in for the Safe executing the batch
    for (const addr of ACCEPT_TARGETS) {
      await (await owner.sendTransaction({ to: addr, data: ACCEPT_DATA })).wait();
    }
  }

  console.log("\n--- after ---");
  const rows = await status(newOwner);
  const allMoved = rows.every((r) => r.owner.toLowerCase() === newOwner.toLowerCase());
  let deployerLocked = false;
  try {
    await (await ethers.getContractAt("GuardianPolicyGuard", CONTRACTS.GuardianPolicyGuard, deployer)).pause.staticCall();
  } catch { deployerLocked = true; }
  console.log(`\nall contracts owned by new owner: ${allMoved}`);
  console.log(`deployer can no longer pause PolicyGuard: ${deployerLocked}`);
  if (!allMoved || !deployerLocked) throw new Error("rehearsal failed");
}

async function main() {
  const confirm = process.env.CONFIRM === "1";
  const step = process.env.STEP || "nominate";
  const newOwner = process.env.NEW_OWNER ? ethers.getAddress(process.env.NEW_OWNER) : "";

  if (process.env.REHEARSE === "1") {
    if (network.name !== "hardhat" || process.env.FORK_MONAD !== "1") throw new Error("REHEARSE=1 needs FORK_MONAD=1 on the hardhat network");
    return rehearse(newOwner || ethers.Wallet.createRandom().address);
  }
  if (network.name !== "monad_testnet") throw new Error("use --network monad_testnet (or REHEARSE=1 with FORK_MONAD=1)");
  const [signer] = await ethers.getSigners();

  if (step === "nominate") {
    if (!newOwner) throw new Error("set NEW_OWNER to the Safe (or timelock) address");
    if (newOwner.toLowerCase() === DEPLOYER.toLowerCase()) throw new Error("NEW_OWNER is the deployer");
    if ((await ethers.provider.getCode(newOwner)) === "0x") throw new Error(`${newOwner} has no code: expected a Safe or the timelock, not an EOA`);
    if (signer.address.toLowerCase() !== DEPLOYER.toLowerCase()) throw new Error(`signer ${signer.address} is not the deployer`);
    return nominate(signer, newOwner, confirm);
  }
  if (step === "timelock-schedule") return timelockSchedule(signer, confirm);
  if (step === "timelock-execute") return timelockExecute(signer, confirm);
  throw new Error(`unknown STEP ${step}`);
}

if (require.main === module) {
  main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
}
