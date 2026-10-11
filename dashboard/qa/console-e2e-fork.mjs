// E2E: console "guarded agent" journey on a local Monad fork with the live relay.
// Run: (contracts) FORK_MONAD=1 npx hardhat node  ->  evm_mine once  ->  (dashboard) VITE_MONAD_RPC_URL=http://127.0.0.1:8545 npm run build && npx vite preview --port 5173 --host localhost  ->  node qa/console-e2e-fork.mjs
// Needs: npm i -D playwright (and a Chromium). No real MON is spent.
// Full console run on a local fork of Monad (chain 10143) with the LIVE Railway relay. No real MON.
import { chromium } from 'playwright'
import { ethers } from 'ethers'
import { mkdirSync } from 'node:fs'
mkdirSync('qa/e2e-out', { recursive: true })

const FORK = 'http://127.0.0.1:8545'
const rpc = async (method, params = []) => {
  const r = await (await fetch(FORK, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })).json()
  if (r.error) throw new Error(`${method}: ${r.error.message}`)
  return r.result
}
const judge = ethers.Wallet.createRandom().address
await rpc('hardhat_impersonateAccount', [judge])
await rpc('hardhat_setBalance', [judge, '0x8AC7230489E80000']) // 10 MON on the fork only
console.log('judge (fork-funded):', judge)

const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`, '--proxy-bypass-list=localhost;127.0.0.1'] : []
const browser = await chromium.launch({ args: ['--headless=new', ...proxyArgs] })
const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 }, ignoreHTTPSErrors: true })
const page = await ctx.newPage()
const errors = []
page.on('pageerror', (e) => errors.push(e.message))
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })

await page.addInitScript(({ judge, FORK }) => {
  const forward = async (method, params) => {
    const r = await (await fetch(FORK, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params: params || [] }) })).json()
    if (r.error) { const e = new Error(r.error.message); e.code = r.error.code; e.data = r.error.data; throw e }
    return r.result
  }
  const provider = {
    request: async ({ method, params }) => {
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [judge]
      if (method === 'eth_chainId') return '0x279f'
      if (method.startsWith('wallet_')) return null
      return forward(method, params)
    },
    on() {}, removeListener() {},
  }
  const announce = () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'fork-wallet', name: 'Fork Wallet', icon: '', rdns: 'dev.fork' }, provider }) }))
  window.addEventListener('eip6963:requestProvider', announce)
  try { localStorage.setItem('gx-wallet', 'dev.fork') } catch { /* */ }
}, { judge, FORK })

const panel = () => page.locator('section[aria-labelledby="guarded-agent-title"]')
const shot = async (name) => { await panel().screenshot({ path: `qa/e2e-out/${name}.png` }) }
const click = async (name) => { await panel().getByRole('button', { name }).first().click() }
const waitText = async (text, timeout = 60000) => { await panel().getByText(text).first().waitFor({ timeout }) }
const step = (s) => console.log(`\n== ${s}`)

await page.goto('http://localhost:5173/?view=console')
step('create guarded wallet')
await click('Create guarded wallet')
await waitText('Agent wallet')
await shot('1-created')

step('turn on scam protection')
await click('Turn on scam protection')
await waitText('Scam protection on.')

step('add 0.05 MON')
await panel().locator('#gx-fund-amount').fill('0.05')
await click('Send to agent wallet')
await waitText('Added 0.05 MON.')

step('get Agent ID card')
await click('Get Agent ID card')
await waitText('Agent ID card active (entry level)')

step('give agent gas')
await click(/Give your agent/)
await waitText(/Agent key has 0\.05 MON for gas/)
await shot('2-ready')

const runScenario = async (title) => {
  const rows = panel().locator('ul[aria-live], li[aria-live]')
  const before = await rows.count()
  await click(new RegExp(title))
  await page.waitForFunction((n) => document.querySelectorAll('section[aria-labelledby="guarded-agent-title"] li[aria-live]').length > n, before, { timeout: 90000 })
  const row = panel().locator('li[aria-live]').first()
  const text = (await row.innerText()).replace(/\s+/g, ' ')
  const link = await row.locator('a').first().getAttribute('href').catch(() => null)
  console.log(`${title}\n   -> ${text}`)
  return { text, link }
}

step('let the agent try')
const pay = await runScenario('Pay you back')
const scam = await runScenario('scam list')
const inj = await runScenario('prompt-injected')
const forged = await runScenario('approve itself')
const cre = await runScenario('flagged by Chainlink')
await shot('3-tries')

step('freeze, then pay again')
await click('Freeze agent')
await waitText('Wallet frozen.')
const frozen = await runScenario('Pay you back')
await click('Unfreeze agent')
await waitText('Wallet unfrozen.')

step('verify the paid transaction on the fork')
const hash = pay.link?.split('/tx/')[1]
const rc = hash ? await rpc('eth_getTransactionReceipt', [hash]) : null
console.log('payBack tx', hash, 'status', rc?.status, 'to', rc?.to)

step('Agents panel label')
const card = page.getByText('Console agent · entry-level card').first()
const labelShown = await card.waitFor({ timeout: 30000 }).then(() => true).catch(() => false)

await page.screenshot({ path: 'qa/e2e-out/4-full.png', fullPage: true })
await page.setViewportSize({ width: 390, height: 900 })
await page.waitForTimeout(500)
const overflow390 = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
const wide = await page.evaluate(() => [...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().right > window.innerWidth + 1).slice(0, 8).map((e) => `${e.tagName.toLowerCase()}.${String(e.className).slice(0, 50)} w=${Math.round(e.getBoundingClientRect().width)} :: ${(e.innerText || '').slice(0, 60).replace(/\s+/g, ' ')}`))
console.log('elements wider than 390px:', wide)
console.log('widths:', await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth, innerWidth: window.innerWidth, bodyScroll: document.body.scrollWidth })))
console.log('text past edge:', await page.evaluate(() => { const out = []; const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n; while ((n = w.nextNode()) && out.length < 6) { const r = document.createRange(); r.selectNodeContents(n); const b = r.getBoundingClientRect(); if (b.right > document.documentElement.clientWidth + 0.5 && n.textContent.trim()) out.push(`right=${Math.round(b.right)} in <${n.parentElement.tagName.toLowerCase()} class="${String(n.parentElement.className).slice(0, 70)}"> :: ${n.textContent.trim().slice(0, 70)}`) } return out }))
console.log('past clientWidth:', await page.evaluate(() => [...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().right > document.documentElement.clientWidth + 0.5).slice(0, 8).map((e) => `${e.tagName.toLowerCase()}.${String(e.className).slice(0, 60)} right=${Math.round(e.getBoundingClientRect().right)} :: ${(e.innerText || '').slice(0, 50).replace(/\s+/g, ' ')}`)))
await panel().screenshot({ path: 'qa/e2e-out/5-mobile.png' })
const ok = (cond, label) => console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`)
step('summary')
ok(/Paid/.test(pay.text) && rc?.status === '0x1', 'pay back: approved, sent, receipt status 1')
ok(/Blocked by GuardianAI/.test(scam.text) && /risk score 100\/100/i.test(scam.text), 'scam list: blocked by relay, risk 100')
ok(/Blocked by GuardianAI/.test(inj.text) && /risk score 50\/100/i.test(inj.text), 'prompt injection: blocked by relay, risk 50')
ok(/Refused by Monad/.test(forged.text) && /InvalidAttestationSignature/.test(forged.text), 'forged approval: refused on-chain')
ok(/Refused by Monad/.test(cre.text) && /FlaggedDestination/.test(cre.text) && /Chainlink-fed/.test(cre.text), 'Chainlink-flagged: relay approved (risk 0), chain refused')
ok(/Refused by Monad/.test(frozen.text) && /EnforcedPause/.test(frozen.text), 'frozen wallet: refused on-chain')
ok(labelShown, 'Agents panel shows the new card as "Console agent · entry-level card" without reload')
ok(!overflow390, 'no horizontal scroll at 390px')
console.log('page errors:', errors.length ? errors : 'none')
await browser.close()
