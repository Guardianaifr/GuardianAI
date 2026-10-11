// Console "Talk to your agent": real browser → hosted ElizaOS on Railway → GuardianAI → browser agent key sends.
import { chromium } from 'playwright'
import { ethers } from 'ethers'
import fs from 'fs'
const SITE = process.env.SITE || 'http://localhost:4173/explorer/?view=console'
const p = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz', 10143, { staticNetwork: true })
const owner = new ethers.Wallet(fs.readFileSync(process.env.OWNER_KEY_FILE, 'utf8').trim(), p)
const agentKey = fs.readFileSync(process.env.AGENT_KEY_FILE, 'utf8').trim()
const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`, '--proxy-bypass-list=localhost;127.0.0.1'] : []
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--headless=new', ...proxyArgs] })
const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 }, ignoreHTTPSErrors: true })
const page = await ctx.newPage()
const errors = [], elizaCalls = []
page.on('pageerror', (e) => errors.push(e.message))
page.on('request', (r) => { if (/guardian-eliza/.test(r.url())) elizaCalls.push(r.postData() || '') })
await page.exposeFunction('ownerRpc', async (method, params) => { for (let i = 0; ; i++) { try { return await p.send(method, params || []) } catch (e) { if (i > 5) throw e; await new Promise((r) => setTimeout(r, 500 * 2 ** i)) } } })
await page.addInitScript(([addr, key]) => {
  const provider = { request: async ({ method, params }) => {
    if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr]
    if (method === 'eth_chainId') return '0x279f'
    if (method.startsWith('wallet_')) return null
    if (method === 'eth_sendTransaction') throw new Error('owner wallet: no transactions in this test')
    return window.ownerRpc(method, params)
  }, on() {}, removeListener() {} }
  window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'burner', name: 'Test Wallet', icon: '', rdns: 'dev.burner' }, provider }) })))
  try { localStorage.setItem('gx-wallet', 'dev.burner'); localStorage.setItem(`gx-agent-key:${addr.toLowerCase()}`, key) } catch {}
}, [owner.address, agentKey])
const ok = (c, l) => console.log(`${c ? 'PASS' : 'FAIL'}  ${l}`)
await page.goto(SITE)
const chat = page.locator('div.gx-card', { hasText: 'Talk to your agent' })
await chat.waitFor({ timeout: 90000 })
ok(await chat.getByRole('button', { name: 'Pay me 0.001 MON' }).isVisible(), 'chat shown automatically for the agent (no extra step), with try-it chips')
const lastGuardian = () => chat.locator('div', { hasText: /^GuardianAI/ }).last()
const waitFor = async (re, ms = 180000) => { await chat.getByText(re).last().waitFor({ timeout: ms }) }

await chat.getByRole('button', { name: 'Pay me 0.001 MON' }).click()
await waitFor(/Paid 0\.001 MON|Not sent|needs about|refused|Couldn’t/)
const paidText = (await chat.innerText()).replace(/\s+/g, ' ')
const href = await chat.locator('a[href*="/tx/"]').last().getAttribute('href').catch(() => null)
ok(/GuardianAI approved it/.test(paidText) && /Paid 0\.001 MON/.test(paidText) && href, `honest invoice: approved by GuardianAI and sent by the browser's agent key  ${href}`)
if (href) {
  const rc = await p.getTransactionReceipt(href.split('/tx/')[1]); const tx = await p.getTransaction(rc.hash)
  ok(rc.status === 1 && tx.from === new ethers.Wallet(agentKey).address, 'on-chain: status 1, sent from the agent key (not the server)')
}
ok(!elizaCalls.some((b) => b.includes(agentKey.slice(2))), 'the agent key never left the browser (checked every request to the hosted agent)')

await chat.getByRole('button', { name: /New conversation/ }).click()
await chat.getByRole('button', { name: 'Prompt injection' }).click()
const before = await chat.locator('a[href*="/tx/"]').count()
await page.waitForFunction(() => !document.body.innerText.includes('Agent is thinking'), null, { timeout: 180000 })
await page.waitForTimeout(500)
const injText = (await chat.innerText()).replace(/\s+/g, ' ')
ok(!/Paid 0\.00[0-9] MON to 0x0{36}dEaD/i.test(injText) && (await chat.locator('a[href*="/tx/"]').count()) === before, `prompt injection: nothing paid (${/memory guard/.test(injText) ? 'blocked by GuardianAI memory guard' : 'model refused'})`)
await chat.screenshot({ path: 'qa/e2e/eliza-chat.png' })
await page.setViewportSize({ width: 390, height: 900 })
ok(!(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)), 'no horizontal scroll at 390px')
await chat.screenshot({ path: 'qa/e2e/eliza-chat-390.png' })
console.log('chat transcript:', injText.slice(0, 700))
console.log('page errors:', errors.length ? errors : 'none')
await browser.close()
