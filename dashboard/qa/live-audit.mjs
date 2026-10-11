// Read-only audit of the live explorer: every view, no wallet + connected wallet, desktop + phone.
import { chromium } from 'playwright'
import { ethers } from 'ethers'
import fs from 'fs'
const BASE = process.env.BASE || 'https://aiguardian.dev/explorer/'
const p = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz', 10143, { staticNetwork: true })
const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`] : []
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--headless=new', ...proxyArgs] })
const out = 'qa/e2e/audit'; fs.mkdirSync(out, { recursive: true })
const report = []
async function visit(name, url, { width = 1280, wallet } = {}) {
  const ctx = await browser.newContext({ viewport: { width, height: 900 }, ignoreHTTPSErrors: true })
  const page = await ctx.newPage()
  const errs = [], bad = []
  page.on('pageerror', (e) => errs.push('pageerror: ' + e.message))
  page.on('console', (m) => { if (m.type() === 'error' && !/429|Too Many/.test(m.text())) errs.push('console: ' + m.text().slice(0, 160)) })
  page.on('response', (r) => { if (r.status() >= 400 && !/testnet-rpc|429/.test(r.url()) && r.status() !== 429) bad.push(`${r.status()} ${r.url().slice(0, 110)}`) })
  if (wallet) {
    await page.exposeFunction('ownerRpc', async (method, params) => { for (let i = 0; ; i++) { try { return await p.send(method, params || []) } catch (e) { if (i > 5) throw e; await new Promise((r) => setTimeout(r, 500 * 2 ** i)) } } })
    await page.addInitScript(([addr, key]) => {
      const provider = { request: async ({ method, params }) => {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr]
        if (method === 'eth_chainId') return '0x279f'
        if (method.startsWith('wallet_')) return null
        if (method === 'eth_sendTransaction') throw new Error('audit: read-only')
        return window.ownerRpc(method, params)
      }, on() {}, removeListener() {} }
      window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'audit', name: 'Audit Wallet', icon: '', rdns: 'dev.audit' }, provider }) })))
      try { localStorage.setItem('gx-wallet', 'dev.audit'); if (key) localStorage.setItem(`gx-agent-key:${addr.toLowerCase()}`, key) } catch {}
    }, [wallet.address, wallet.key])
  }
  await page.goto(url, { waitUntil: 'networkidle', timeout: 90000 }).catch(() => {})
  await page.waitForTimeout(wallet ? 12000 : 6000)
  const text = await page.evaluate(() => document.body.innerText)
  const weird = [...new Set((text.match(/[^\n]{0,40}\b(undefined|NaN|null|\[object Object\]|Infinity)\b[^\n]{0,40}/g) || []))].slice(0, 6)
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)
  const errorsShown = [...new Set((text.match(/[^\n]*(Couldn’t|Could not|failed|Error|error:)[^\n]*/g) || []))].slice(0, 6)
  const links = await page.evaluate(() => [...document.querySelectorAll('a[href]')].map((a) => a.href).filter((h) => h.startsWith('http')))
  await page.screenshot({ path: `${out}/${name}.png`, fullPage: true })
  report.push({ name, url, width, errs: [...new Set(errs)].slice(0, 6), badResponses: [...new Set(bad)].slice(0, 8), weird, overflow, errorsShown, links: [...new Set(links)] })
  await ctx.close()
}
const views = ['', '?view=console', '?view=proof', '?view=agents', '?view=threats', '?view=sponsors']
for (const v of views) await visit(`home${v.replace(/[?=]/g, '_') || ''}`, BASE + v)
await visit('console-phone', BASE + '?view=console', { width: 390 })
const owner = new ethers.Wallet(fs.readFileSync(process.env.OWNER_KEY_FILE, 'utf8').trim())
await visit('console-wallet', BASE + '?view=console', { wallet: { address: owner.address, key: fs.readFileSync(process.env.AGENT_KEY_FILE, 'utf8').trim() } })
await visit('console-wallet-phone', BASE + '?view=console', { width: 390, wallet: { address: owner.address, key: fs.readFileSync(process.env.AGENT_KEY_FILE, 'utf8').trim() } })
const fresh = ethers.Wallet.createRandom()
await visit('console-new-user', BASE + '?view=console', { wallet: { address: fresh.address } })
fs.writeFileSync(`${out}/report.json`, JSON.stringify(report, null, 2))
for (const r of report) console.log(`\n== ${r.name} (${r.width}px)\n  page errors: ${r.errs.length ? r.errs.join(' | ') : 'none'}\n  HTTP ≥400: ${r.badResponses.length ? r.badResponses.join(' | ') : 'none'}\n  odd text: ${r.weird.length ? r.weird.join(' | ') : 'none'}\n  error text on page: ${r.errorsShown.length ? r.errorsShown.join(' | ') : 'none'}\n  horizontal scroll: ${r.overflow}`)
await browser.close()
