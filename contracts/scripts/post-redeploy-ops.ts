// One-off follow-up after the audited redeploy (see docs/operations/RELEASE_NOTES.md v1.3.1):
//   1. re-mint the reference demo passports on the new SBT through GuardianPassportIssuer
//   2. move the old GuardianAgentWallet's MON into the new wallet, then pause the old wallet
//   3. pause the old GuardianPolicyGuard
// Dry run by default; CONFIRM=yes sends the transactions.
//   npx hardhat run scripts/post-redeploy-ops.ts --network monad_testnet
import { ethers } from "hardhat";

const ISSUER = "0x9c4acFb906EBF32c2C5115F3D84ab6Db809f2Dd1";
const NEW_SBT = "0xb2a8FeF3591efbd385778906207A054af0Ca3566";
const NEW_WALLET = "0x356EfbC397B104F90795E89F0b755aa5AE4967DD";
const OLD_WALLET = "0xCCb137694f2910c8Ec4883d108c989648019D335";
const OLD_GUARD = "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60";
const USDC = "0x534b2f3A21130d7a60830c2Df862319e593943A3";

const AGENTS = [
  { id: "eliza-monad-01", score: 9400, uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/eliza.json" },
  { id: "mera-memory-01", score: 9700, uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/mera.json" },
  { id: "passport-agent-01", score: 9800, uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/passport.json" },
];

async function main() {
  const live = process.env.CONFIRM === "yes";
  const [deployer] = await ethers.getSigners();
  console.log(`deployer ${deployer.address}  mode ${live ? "LIVE" : "dry run"}`);

  const issuer = await ethers.getContractAt(
    ["function mint(address,bytes32,uint256,string) returns (uint256)", "function owner() view returns (address)"], ISSUER);
  const sbt = await ethers.getContractAt(["function isPassportActive(bytes32) view returns (bool)"], NEW_SBT);
  const wallet = await ethers.getContractAt(
    ["function ownerExecute(address,uint256,bytes) returns (bytes)", "function pause()", "function paused() view returns (bool)", "function owner() view returns (address)"], OLD_WALLET);
  const guard = await ethers.getContractAt(
    ["function pause()", "function paused() view returns (bool)", "function owner() view returns (address)"], OLD_GUARD);
  const usdc = await ethers.getContractAt(["function balanceOf(address) view returns (uint256)", "function transfer(address,uint256) returns (bool)"], USDC);

  console.log(`issuer owner ${await issuer.owner()}, old wallet owner ${await wallet.owner()}, old guard owner ${await guard.owner()}`);

  // 1. passports
  for (const a of AGENTS) {
    const hash = ethers.id(a.id);
    if (await sbt.isPassportActive(hash)) { console.log(`passport ${a.id}: already active`); continue; }
    console.log(`passport ${a.id}: mint score ${a.score}`);
    if (live) { const tx = await issuer.mint(deployer.address, hash, a.score, a.uri); await tx.wait(); console.log(`  tx ${tx.hash}`); }
  }

  // 2. old wallet: move MON and USDC to the new wallet, then pause
  const mon = await ethers.provider.getBalance(OLD_WALLET);
  const usdcBal = await usdc.balanceOf(OLD_WALLET);
  console.log(`old wallet holds ${ethers.formatEther(mon)} MON, ${ethers.formatUnits(usdcBal, 6)} USDC`);
  if (usdcBal > 0n) {
    const data = usdc.interface.encodeFunctionData("transfer", [NEW_WALLET, usdcBal]);
    if (live) { const tx = await wallet.ownerExecute(USDC, 0, data); await tx.wait(); console.log(`  USDC moved, tx ${tx.hash}`); }
  }
  if (mon > 0n) {
    if (live) { const tx = await wallet.ownerExecute(NEW_WALLET, mon, "0x"); await tx.wait(); console.log(`  MON moved, tx ${tx.hash}`); }
  }
  if (!(await wallet.paused())) {
    console.log("old wallet: pause");
    if (live) { const tx = await wallet.pause(); await tx.wait(); console.log(`  tx ${tx.hash}`); }
  }

  // 3. old guard: pause
  if (!(await guard.paused())) {
    console.log("old guard: pause");
    if (live) { const tx = await guard.pause(); await tx.wait(); console.log(`  tx ${tx.hash}`); }
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
