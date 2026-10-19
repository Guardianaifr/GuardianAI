// One-time: create a guarded wallet for the Eliza agent on Monad testnet (same contracts as the console).
//   FUNDER_PRIVATE_KEY (or GUARDIAN_DEPLOYER_PRIVATE_KEY in the repo .env) pays ~0.45 MON:
//   owner gets 0.30 (createWallet ≈0.2, scam protection, ID card, 0.01 deposit), agent key gets 0.15 gas.
// Writes .env.agent (git-ignored) with the new owner + agent keys. Re-running reuses them.
import { ethers } from 'ethers'
import fs from 'fs'
import { loadEnv, AGENT_ENV } from './env.mjs'
loadEnv()
const p = new ethers.JsonRpcProvider(process.env.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz', 10143, { staticNetwork: true })
const FACTORY = '0xAb3aE67587D946e63b3cfFb32C9e32d701B8Ef03', ISSUER = '0x9c4acFb906EBF32c2C5115F3D84ab6Db809f2Dd1'
const ORACLE = '0x26144375c4f846174A386C464aC5F2e671EbdA95', SBT = '0xb2a8FeF3591efbd385778906207A054af0Ca3566'
const funderKey = process.env.FUNDER_PRIVATE_KEY || process.env.GUARDIAN_DEPLOYER_PRIVATE_KEY
if (!funderKey) throw new Error('Set FUNDER_PRIVATE_KEY (a Monad testnet key with ~0.5 MON)')
const funder = new ethers.Wallet(funderKey, p)
const ownerKey = process.env.GUARDIAN_OWNER_PRIVATE_KEY || ethers.Wallet.createRandom().privateKey
const agentKey = process.env.GUARDIAN_AGENT_PRIVATE_KEY || ethers.Wallet.createRandom().privateKey
const owner = new ethers.Wallet(ownerKey, p), agent = new ethers.Wallet(agentKey, p)
const agentId = ethers.id(`console:${owner.address.toLowerCase()}`)
const save = (wallet) => fs.writeFileSync(AGENT_ENV, `# Eliza demo agent — testnet only, git-ignored\nGUARDIAN_OWNER_PRIVATE_KEY=${ownerKey}\nGUARDIAN_AGENT_PRIVATE_KEY=${agentKey}\nGUARDIAN_OWNER=${owner.address}\nGUARDIAN_WALLET=${wallet}\n`, { mode: 0o600 })
save('')
const step = async (txp, label) => { const t = await txp; const r = await t.wait(); console.log(`${label.padEnd(22)} status ${r.status}  https://testnet.monadscan.com/tx/${t.hash}`) }
const top = async (to, amt, label) => { const b = await p.getBalance(to); if (b < amt) await step(funder.sendTransaction({ to, value: amt - b }), label) }
console.log(`owner ${owner.address}\nagent key ${agent.address}`)
await top(owner.address, ethers.parseEther('0.30'), 'fund owner')
await top(agent.address, ethers.parseEther('0.15'), 'fund agent gas')
const f = new ethers.Contract(FACTORY, ['function createWallet(address,bytes32) returns (address)', 'function walletOf(address,bytes32) view returns (address)'], owner)
let wallet = await f.walletOf(owner.address, agentId)
if (wallet === ethers.ZeroAddress) { await step(f.createWallet(agent.address, agentId), 'create guarded wallet'); wallet = await f.walletOf(owner.address, agentId) }
save(wallet)
const w = new ethers.Contract(wallet, ['function setThreatOracle(address)', 'function threatOracle() view returns (address)'], owner)
if ((await w.threatOracle()).toLowerCase() !== ORACLE.toLowerCase()) await step(w.setThreatOracle(ORACLE), 'scam protection on')
const sbt = new ethers.Contract(SBT, ['function isPassportActive(bytes32) view returns (bool)'], p)
if (!(await sbt.isPassportActive(agentId))) await step(new ethers.Contract(ISSUER, ['function claim(bytes32) returns (uint256)'], owner).claim(agentId), 'claim Agent ID card')
const bal = await p.getBalance(wallet)
if (bal < ethers.parseEther('0.01')) await step(owner.sendTransaction({ to: wallet, value: ethers.parseEther('0.01') - bal }), 'deposit 0.01 MON')
console.log(`\nguarded wallet ${wallet}  balance ${ethers.formatEther(await p.getBalance(wallet))} MON\nsaved ${AGENT_ENV}`)
