/**
 * Rehearse the passport handoff on a local FORK of Monad testnet (nothing is broadcast).
 *   FORK_MONAD=1 npx hardhat run scripts/rehearse-passport-issuer.ts          (PowerShell: $env:FORK_MONAD="1"; npx hardhat run ...)
 */
import { ethers, network } from "hardhat";
import { handOff, SBT, FACTORY } from "./deploy-passport-issuer";

const DEPLOYER = "0x1D4549B95dccAC8203393543187b25B3137D0bf6";

async function snapshotCards(sbt: any) {
  const out: { id: number; agent: string; owner: string; active: boolean; score: bigint }[] = [];
  for (let i = 1; i <= 50; i++) {
    let p;
    p = await sbt.passports(i); // a mapping read never reverts; issuedAt 0 = past the last card
    if (p.issuedAt === 0n) break;
    const owner = p.revoked ? "(burned)" : await sbt.ownerOf(i);
    out.push({ id: i, agent: p.agentHash, owner, active: await sbt.isPassportActive(p.agentHash), score: p.trustScore });
  }
  return out;
}

async function main() {
  if (network.name !== "hardhat" || process.env.FORK_MONAD !== "1") throw new Error("run with FORK_MONAD=1 on the in-process hardhat network");
  const block = await ethers.provider.getBlockNumber();
  // Calls on the fork block itself count as "historical" for Monad's chain id; run on a fresh local block.
  await network.provider.send("evm_mine", []);
  console.log(`forked Monad testnet at block ${block}`);

  await network.provider.request({ method: "hardhat_impersonateAccount", params: [DEPLOYER] });
  await network.provider.send("hardhat_setBalance", [DEPLOYER, "0x56BC75E2D63100000"]); // 100 MON (fork only)
  const deployer = await ethers.getSigner(DEPLOYER);
  const sbt = await ethers.getContractAt("GuardianPassportSBT", SBT);

  const before = await snapshotCards(sbt);
  console.log(`existing cards: ${before.length} (${before.filter((c) => c.active).length} active)`);

  console.log("\n--- dry run ---");
  await handOff(deployer, { cap: 200n, confirm: false });
  console.log("\n--- confirmed run (fork) ---");
  const issuerAddr = (await handOff(deployer, { cap: 200n, confirm: true }))!;
  const issuer = await ethers.getContractAt("GuardianPassportIssuer", issuerAddr);

  const after = await snapshotCards(sbt);
  const unchanged = JSON.stringify(before, (_, v) => (typeof v === "bigint" ? v.toString() : v)) ===
    JSON.stringify(after, (_, v) => (typeof v === "bigint" ? v.toString() : v));
  console.log(`\nexisting cards unchanged after handoff: ${unchanged}`);
  console.log(`claimsOpen ${await issuer.claimsOpen()}  claimCap ${await issuer.claimCap()}`);

  let directMintBlocked = false;
  try { await sbt.connect(deployer).mint.staticCall(DEPLOYER, ethers.ZeroHash, 1, ""); } catch { directMintBlocked = true; }
  console.log(`deployer can no longer mint on the SBT directly: ${directMintBlocked}`);

  // A judge: new key, guarded wallet through the real factory, then claim.
  const judge = ethers.Wallet.createRandom().connect(ethers.provider);
  const agentKey = ethers.Wallet.createRandom();
  await network.provider.send("hardhat_setBalance", [judge.address, "0x8AC7230489E80000"]); // 10 MON (fork only)
  const factory = await ethers.getContractAt("GuardianAgentWalletFactory", FACTORY, judge);
  const agentId = ethers.id(`console:${judge.address.toLowerCase()}`);
  await (await factory.createWallet(agentKey.address, agentId)).wait();
  const wallet = await factory.walletOf(judge.address, agentId);
  console.log(`\njudge ${judge.address} created guarded wallet ${wallet}`);
  console.log(`card active before claim: ${await sbt.isPassportActive(agentId)}`);
  const rc = await (await issuer.connect(judge).claim(agentId)).wait();
  const ev = rc!.logs.map((l: any) => { try { return issuer.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "Claimed");
  const tokenId = ev!.args.tokenId;
  const p = await sbt.getPassport(tokenId);
  console.log(`claimed token #${tokenId}: owner ${await sbt.ownerOf(tokenId)}, score ${p.trustScore}, tier ${p.tier}, active ${await sbt.isPassportActive(agentId)}`);
  console.log(`claim gas used: ${rc!.gasUsed}`);

  let second = "";
  try { await issuer.connect(judge).claim.staticCall(agentId); } catch (e: any) { second = e.revert?.name || e.shortMessage || "reverted"; }
  console.log(`second claim from same judge: ${second}`);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
