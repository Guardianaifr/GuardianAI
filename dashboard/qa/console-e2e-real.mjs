// REAL Monad testnet E2E of the console (costs testnet MON). Usage:
//   BURNER_KEY_FILE=path/to/funded.key FRESH=1 REFUND=<address> [SITE=https://aiguardian.dev/explorer/?view=console] node qa/console-e2e-real.mjs
// FRESH=1 funds a new owner from the burner each run (one guarded wallet per owner); leftovers are swept to REFUND.
// REAL Monad testnet run against the deployed https://aiguardian.dev/explorer/?view=console
// Owner = burner key (signs from Node via an injected EIP-1193 shim). Agent keys are created by the page itself.
import { chromium } from 'playwright'
import { ethers, FetchRequest } from 'ethers'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'

const SITE = process.env.SITE || 'https://aiguardian.dev/explorer/?view=console'
const RPC = 'https://testnet-rpc.monad.xyz'
const REFUND = process.env.REFUND || '0x1D4549B95dccAC8203393543187b25B3137D0bf6' // team/deployer wallet
mkdirSync('qa/real', { recursive: true })

// ethers in Node does not use the proxy; route its HTTP through global fetch (which does).
FetchRequest.registerGetUrl(async (req) => {
  const res = await fetch(req.url, { method: req.method, headers: Object.fromEntries(Object.entries(req.headers)), body: req.body ? Buffer.from(req.body) : undefined })
  return { statusCode: res.status, statusMessage: res.statusText, headers: Object.fromEntries(res.headers.entries()), body: new Uint8Array(await res.arrayBuffer()) }
})
const provider = new ethers.JsonRpcProvider(RPC, 10143, { staticNetwork: true })
const burner = new ethers.Wallet(readFileSync(process.env.BURNER_KEY_FILE || 'qa/real/burner.key', 'utf8').trim(), provider)
// Each run needs a fresh owner (the factory allows one guarded wallet per owner). Fund it from the burner.
const owner = process.env.FRESH === '1' ? ethers.Wallet.createRandom().connect(provider) : burner
if (owner !== burner) {
  writeFileSync(`qa/real/owner-${owner.address}.key`, owner.privateKey, { mode: 0o600 })
  const t = await burner.sendTransaction({ to: owner.address, value: ethers.parseEther(process.env.FUND || '0.8'), gasLimit: 21000n })
  await t.wait()
  console.log(`fresh owner ${owner.address} funded from burner: ${t.hash}`)
}
const txs = []
const log = (...a) => console.log(...a)
const fmt = (w) => ethers.formatEther(w)

log(`owner (burner) ${owner.address}  balance ${fmt(await provider.getBalance(owner.address))} MON`)

async function ownerRpc(method, params) {
  for (let i = 0; i < 6; i++) {
    try {
      if (method === 'eth_sendTransaction') {
        const t = params[0]
        const sent = await owner.sendTransaction({ to: t.to, data: t.data || '0x', value: t.value ? BigInt(t.value) : 0n, gasLimit: t.gas ? BigInt(t.gas) : undefined })
        txs.push({ by: 'owner', hash: sent.hash, to: t.to })
        return sent.hash
      }
      return await provider.send(method, params || [])
    } catch (e) {
      if (/429|rate|too many/i.test(String(e?.message)) && i < 5) { await new Promise((r) => setTimeout(r, 600 * 2 ** i)); continue }
      const err = { message: e?.shortMessage || e?.message, code: e?.code === 'ACTION_REJECTED' ? 4001 : e?.info?.error?.code, data: e?.data || e?.info?.error?.data }
      throw new Error(JSON.stringify(err))
    }
  }
}

const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`, '--proxy-bypass-list=localhost;127.0.0.1'] : []
const browser = await chromium.launch({ args: ['--headless=new', ...proxyArgs] })
const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 }, ignoreHTTPSErrors: true })
const page = await ctx.newPage()
const errors = []
page.on('pageerror', (e) => errors.push(e.message))
page.on('console', (m) => { if (m.type() === 'error' && !/429/.test(m.text())) errors.push(m.text()) })
await page.exposeFunction('ownerRpc', ownerRpc)
await page.addInitScript((addr) => {
  const provider = {
    request: async ({ method, params }) => {
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr]
      if (method === 'eth_chainId') return '0x279f'
      if (method.startsWith('wallet_')) return null
      try { return await window.ownerRpc(method, params) } catch (e) {
        let d = {}; try { d = JSON.parse(e.message) } catch { d = { message: e.message } }
        const err = new Error(d.message); err.code = d.code; err.data = d.data; throw err
      }
    },
    on() {}, removeListener() {},
  }
  window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'burner', name: 'Test Wallet', icon: '', rdns: 'dev.burner' }, provider }) })))
  try { localStorage.setItem('gx-wallet', 'dev.burner') } catch { /* */ }
}, owner.address)

const panel = () => page.locator('section[aria-labelledby="guarded-agent-title"]')
const click = async (name) => { await panel().getByRole('button', { name }).first().click() }
const lastLine = () => panel().locator('p[role="alert"], p.gx-good-t').last()
async function act(name, okText, timeout = 120000) {
  await click(name)
  await Promise.race([
    panel().getByText(okText).first().waitFor({ timeout }),
    panel().locator('p[role="alert"]').first().waitFor({ timeout }).then(async () => { throw new Error(`${name}: ${await panel().locator('p[role="alert"]').first().innerText()}`) }),
  ])
}
const step = (s) => log(`\n== ${s}`)
async function tryAgent(title) {
  const before = await panel().locator('li[aria-live]').count()
  await click(new RegExp(title))
  await page.waitForFunction((n) => document.querySelectorAll('section[aria-labelledby="guarded-agent-title"] li[aria-live]').length > n, before, { timeout: 180000 })
  const row = panel().locator('li[aria-live]').first()
  const text = (await row.innerText()).replace(/\s+/g, ' ')
  const link = await row.locator('a').first().getAttribute('href').catch(() => null)
  if (link) txs.push({ by: 'agent', hash: link.split('/tx/')[1], to: 'agent wallet' })
  log(`${title}\n   -> ${text}`)
  return { text, link }
}
const res = {}
const agentKeys = []
const readAgentKey = () => page.evaluate((o) => localStorage.getItem(`gx-agent-key:${o.toLowerCase()}`), owner.address)

try {
  await page.goto(SITE)
  step('create guarded wallet (real deploy, ~0.2 MON)')
  await act('Create guarded wallet', 'Guarded wallet created.', 240000)
  agentKeys.push(await readAgentKey())
  await panel().getByText('Agent wallet').first().waitFor({ timeout: 60000 })
  const walletAddr = (await panel().locator('a[href*="/address/"]').first().getAttribute('href')).split('/address/')[1]
  log('guarded wallet', walletAddr)

  step('turn on scam protection'); await act('Turn on scam protection', 'Scam protection on.')
  step('add 0.03 MON'); await panel().locator('#gx-fund-amount').fill('0.03'); await act('Send to agent wallet', 'Added 0.03 MON.')
  step('get Agent ID card'); await act('Get Agent ID card', 'Agent ID card issued to your agent.')
  step('give agent gas'); await act(/Give your agent/, /Sent 0\.1 MON to your agent for gas/)
  await panel().getByText('Agent ID card active (entry level)').first().waitFor({ timeout: 60000 })
  await panel().screenshot({ path: 'qa/real/1-ready.png' })

  step('let the agent try (real chain)')
  res.pay = await tryAgent('Pay you back')
  res.scam = await tryAgent('scam list')
  res.inj = await tryAgent('prompt-injected')
  res.forged = await tryAgent('approve itself')
  res.cre = await tryAgent('flagged by Chainlink')

  step('freeze, pay (dry run refuses), unfreeze')
  await act('Freeze agent', 'Wallet frozen.')
  res.frozen = await tryAgent('Pay you back')
  await act('Unfreeze agent', 'Wallet unfrozen.')

  step('risk limit Strict (10), pay again')
  await act(/Strict · 10/, 'Risk limit set to 10.')
  res.strict = await tryAgent('Pay you back')
  res.third = await tryAgent('Pay you back')

  step('replace agent key, old key locked out')
  const opIface = new ethers.Interface(['function operator() view returns (address)'])
  const w = new ethers.Contract(walletAddr, opIface, provider)
  const oldOp = await w.operator()
  await act('Replace agent key', 'Agent key replaced. The old key can no longer request anything.')
  agentKeys.push(await readAgentKey())
  const newOp = await w.operator()
  const ap = await (await fetch('https://guardian-relay-production.up.railway.app/api/v1/attest', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agent_id: `console:${owner.address.toLowerCase()}`, target: owner.address, value: '1000000000000000', wallet: walletAddr, data: '0x' }) })).text()
  const wrapped = ap.match(/"wrapped_calldata"\s*:\s*"(0x[0-9a-fA-F]*)"/)[1]
  try { await provider.call({ from: oldOp, to: walletAddr, data: wrapped }); res.oldKey = 'NOT refused' } catch (e) {
    res.oldKey = new ethers.Interface(['error NotOperator(address)']).parseError(e.data)?.name || e.shortMessage
  }
  log(`old operator ${oldOp} -> new ${newOp}; old key with a valid approval -> ${res.oldKey}`)
  res.rotated = oldOp !== newOp
  res.noGas = await tryAgent('Pay you back')

  step('withdraw'); await act(/^Withdraw \d/, /Withdrew/)
  await panel().getByRole('button', { name: 'Withdraw 0 MON' }).waitFor({ timeout: 60000 })
  res.walletAfter = await provider.getBalance(walletAddr)
  await page.screenshot({ path: 'qa/real/2-full.png', fullPage: true })
} catch (e) {
  log('\nSTOPPED:', e.message)
  await page.screenshot({ path: 'qa/real/error.png', fullPage: true }).catch(() => {})
} finally {
  await browser.close()
}

step('sweep agent keys and leftovers back to ' + REFUND)
if (owner !== burner) agentKeys.push(owner.privateKey) // sweep the fresh owner too (back to REFUND below)
for (const pk of agentKeys.filter(Boolean)) {
  const a = new ethers.Wallet(pk, provider)
  const bal = await provider.getBalance(a.address)
  const fee = (await provider.getFeeData()).maxFeePerGas * 21000n
  if (bal > fee * 2n) { const t = await a.sendTransaction({ to: REFUND, value: bal - fee * 2n, gasLimit: 21000n }); await t.wait(); log(`agent key ${a.address}: returned ${fmt(bal - fee * 2n)} MON  ${t.hash}`) }
  else log(`agent key ${a.address}: ${fmt(bal)} MON (too little to sweep)`)
}
writeFileSync('qa/real/agent-keys.txt', agentKeys.filter(Boolean).join('\n'))

const ok = (c, l) => log(`${c ? 'PASS' : 'FAIL'}  ${l}`)
step('summary (real Monad testnet)')
const T = (r) => r?.text || ''
ok(/Paid/.test(T(res.pay)), 'pay back: approved and paid on Monad')
ok(/Blocked by GuardianAI/.test(T(res.scam)) && /risk score 100/i.test(T(res.scam)), 'scam list: blocked by relay')
ok(/Blocked by GuardianAI/.test(T(res.inj)) && /risk score 50/i.test(T(res.inj)), 'prompt injection: blocked by relay')
ok(/InvalidAttestationSignature/.test(T(res.forged)), 'forged approval: refused by Monad')
ok(/FlaggedDestination/.test(T(res.cre)), 'Chainlink-flagged: relay approved, Monad refused')
ok(/EnforcedPause/.test(T(res.frozen)), 'frozen: refused by Monad')
ok(/Paid/.test(T(res.strict)), 'risk limit Strict: still paid')
ok(res.rotated && res.oldKey === 'NotOperator', 'replace key: old key refused on Monad')
ok(res.walletAfter === 0n, 'withdraw: wallet empty')
ok(/Paid/.test(T(res.third)), 'third payment on one 0.1 MON top-up: paid')
ok(/Didn’t run/.test(T(res.noGas)) && /needs about 0\.0\d+ MON for gas/.test(T(res.noGas)), 'rotated key without gas: clear real-gas message, nothing sent')
log('page errors:', errors.length ? errors : 'none')
log('\ntransactions:'); for (const t of txs) log(`  ${t.by.padEnd(5)} https://testnet.monadscan.com/tx/${t.hash}`)
