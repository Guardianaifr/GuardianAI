// Console "Run this agent in ElizaOS": click Copy command, decode the clipboard with the CLI's own decoder.
import { chromium } from 'playwright'
import { ethers } from 'ethers'
import fs from 'fs'
import { decodeConnectCode } from '../../packages/guardianai-eliza/dist/index.js'
const SITE = process.env.SITE || 'http://localhost:4173/explorer/?view=console'
const p = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz', 10143, { staticNetwork: true })
const owner = new ethers.Wallet(fs.readFileSync(process.env.OWNER_KEY_FILE, 'utf8').trim(), p)
const agentKey = fs.readFileSync(process.env.AGENT_KEY_FILE, 'utf8').trim()
const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`, '--proxy-bypass-list=localhost;127.0.0.1'] : []
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--headless=new', ...proxyArgs] })
const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 }, ignoreHTTPSErrors: true })
await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(SITE).origin })
const page = await ctx.newPage()
const errors = []
page.on('pageerror', (e) => errors.push(e.message))
await page.exposeFunction('ownerRpc', async (method, params) => {
  for (let i = 0; ; i++) { try { return await p.send(method, params || []) } catch (e) { if (i > 5) throw e; await new Promise((r) => setTimeout(r, 500 * 2 ** i)) } }
})
await page.addInitScript(([addr, key]) => {
  const provider = { request: async ({ method, params }) => {
    if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [addr]
    if (method === 'eth_chainId') return '0x279f'
    if (method.startsWith('wallet_')) return null
    if (method === 'eth_sendTransaction') throw new Error('test wallet: no transactions in this test')
    return window.ownerRpc(method, params)
  }, on() {}, removeListener() {} }
  window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'burner', name: 'Test Wallet', icon: '', rdns: 'dev.burner' }, provider }) })))
  try { localStorage.setItem('gx-wallet', 'dev.burner'); localStorage.setItem(`gx-agent-key:${addr.toLowerCase()}`, key) } catch {}
}, [owner.address, agentKey])
const ok = (c, l) => console.log(`${c ? 'PASS' : 'FAIL'}  ${l}`)
await page.goto(SITE)
const panel = page.locator('section[aria-labelledby="guarded-agent-title"]')
const btn = panel.getByRole('button', { name: /Copy command/ })
await btn.waitFor({ timeout: 60000 }).catch(async (e) => { await page.screenshot({ path: 'qa/e2e/eliza-debug.png', fullPage: false }); console.log('PANEL TEXT:', (await panel.innerText().catch(() => 'no panel')).slice(0, 600).replace(/\s+/g, ' ')); throw e })
ok(await btn.isEnabled(), 'button shown and enabled for an agent whose key is in this browser')
await btn.click()
await panel.getByRole('button', { name: /Copied/ }).waitFor({ timeout: 5000 })
const clip = await page.evaluate(() => navigator.clipboard.readText())
const shown = (await panel.locator('code.gx-code').innerText()).trim()
console.log('clipboard:', clip.replace(/gx1_\S+/, (m) => m.slice(0, 18) + '…'))
const code = clip.split(' ').at(-1)
const info = decodeConnectCode(code)
const w = new ethers.Contract(info.wallet, ['function owner() view returns (address)', 'function operator() view returns (address)'], p)
ok(clip.startsWith('npx -y guardianai-eliza@latest gx1_') && clip === shown, 'clipboard = shown command = npx -y guardianai-eliza@latest <code>')
ok(info.owner === owner.address && (await w.owner()) === owner.address, 'code carries this owner, and the chain agrees it owns that wallet')
ok(new ethers.Wallet(info.agentKey).address === (await w.operator()), "code's agent key is the wallet's on-chain operator")
await panel.locator('div.gx-card', { hasText: 'Run this agent in ElizaOS' }).screenshot({ path: 'qa/e2e/eliza-button.png' })
await page.setViewportSize({ width: 390, height: 900 })
ok(!(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)), 'no horizontal scroll at 390px with the command shown')
await panel.locator('div.gx-card', { hasText: 'Run this agent in ElizaOS' }).screenshot({ path: 'qa/e2e/eliza-button-390.png' })
console.log('page errors:', errors.length ? errors : 'none')
await browser.close()
