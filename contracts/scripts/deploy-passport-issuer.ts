/**
 * Hand GuardianPassportSBT to a GuardianPassportIssuer so wallet owners can claim their own Agent ID card.
 *
 *   npx hardhat run scripts/deploy-passport-issuer.ts --network monad_testnet                 # dry run (no tx)
 *   CONFIRM=yes npx hardhat run scripts/deploy-passport-issuer.ts --network monad_testnet     # do it
 *
 * Optional env: CLAIM_CAP (default 200, 0 = no cap), ISSUER (reuse an already-deployed issuer).
 * Signer = GUARDIAN_DEPLOYER_PRIVATE_KEY (current SBT owner). Three transactions:
 *   1. deploy GuardianPassportIssuer(sbt, factory, deployer)
 *   2. sbt.transferOwnership(issuer)
 *   3. issuer.acceptPassportOwnership()          (+ setClaims if CLAIM_CAP differs from "open, no cap")
 * Undo: issuer.transferPassportOwnership(deployer), then sbt.acceptOwnership() from the deployer.
 */
import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

export const SBT = "0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff";
export const FACTORY = "0x25A4A3cC1483F8Ca67ED6D33938974Ed0aa119c6";

export async function handOff(deployer: any, opts: { issuer?: string; cap: bigint; confirm: boolean; log?: (s: string) => void }) {
  const log = opts.log ?? console.log;
  const sbt = await ethers.getContractAt("GuardianPassportSBT", SBT, deployer);
  const owner: string = await sbt.owner();
  const pending: string = await sbt.pendingOwner();
  log(`SBT ${SBT}\n  owner ${owner}\n  pendingOwner ${pending}\n  active cards ${await sbt.activePassportCount()}`);
  log(`deployer ${deployer.address}  balance ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} MON`);

  let issuerAddr = opts.issuer;
  if (owner.toLowerCase() !== deployer.address.toLowerCase()) {
    if (issuerAddr && owner.toLowerCase() === issuerAddr.toLowerCase()) {
      log("SBT already owned by the issuer: nothing to do.");
      return issuerAddr;
    }
    throw new Error("The deployer is not the SBT owner; refusing to continue.");
  }

  if (!opts.confirm) {
    log(`\nDRY RUN. With CONFIRM=yes this would:\n  1. ${issuerAddr ? `reuse issuer ${issuerAddr}` : `deploy GuardianPassportIssuer(${SBT}, ${FACTORY}, ${deployer.address})`}\n  2. sbt.transferOwnership(issuer)\n  3. issuer.acceptPassportOwnership()\n  4. issuer.setClaims(true, ${opts.cap})`);
    return undefined;
  }

  if (!issuerAddr) {
    const F = await ethers.getContractFactory("GuardianPassportIssuer", deployer);
    const issuer = await F.deploy(SBT, FACTORY, deployer.address);
    await issuer.waitForDeployment();
    issuerAddr = await issuer.getAddress();
    log(`1. issuer deployed ${issuerAddr}  tx ${issuer.deploymentTransaction()?.hash}`);
  }
  const issuer = await ethers.getContractAt("GuardianPassportIssuer", issuerAddr!, deployer);
  if ((await issuer.owner()).toLowerCase() !== deployer.address.toLowerCase()) throw new Error("issuer owner is not the deployer");
  if ((await issuer.passport()).toLowerCase() !== SBT.toLowerCase()) throw new Error("issuer points at the wrong SBT");
  if ((await issuer.factory()).toLowerCase() !== FACTORY.toLowerCase()) throw new Error("issuer points at the wrong factory");

  if (pending.toLowerCase() !== issuerAddr!.toLowerCase()) {
    const t = await sbt.transferOwnership(issuerAddr!);
    log(`2. sbt.transferOwnership  tx ${t.hash}`);
    await t.wait();
  }
  const a = await issuer.acceptPassportOwnership();
  log(`3. issuer.acceptPassportOwnership  tx ${a.hash}`);
  await a.wait();
  if (opts.cap !== 0n) {
    const s = await issuer.setClaims(true, opts.cap);
    log(`4. issuer.setClaims(true, ${opts.cap})  tx ${s.hash}`);
    await s.wait();
  }
  const now: string = await sbt.owner();
  if (now.toLowerCase() !== issuerAddr!.toLowerCase()) throw new Error(`handoff incomplete: SBT owner is ${now}`);
  log(`done: SBT owner = issuer ${issuerAddr}`);
  return issuerAddr;
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const cap = BigInt(process.env.CLAIM_CAP ?? "200");
  const confirm = process.env.CONFIRM === "yes";
  const issuer = await handOff(deployer, { issuer: process.env.ISSUER, cap, confirm });
  if (issuer && network.name === "monad_testnet") {
    const out = path.join(__dirname, "..", "deployments", "monad_testnet_10143", "passport-issuer.json");
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, JSON.stringify({ GuardianPassportIssuer: issuer, passport: SBT, factory: FACTORY, claimCap: cap.toString(), at: new Date().toISOString() }, null, 2));
    console.log(`saved ${out}`);
  }
}

if (require.main === module) {
  main().catch((e) => { console.error(e); process.exitCode = 1; });
}
