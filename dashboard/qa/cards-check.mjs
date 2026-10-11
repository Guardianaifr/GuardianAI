import { chromium } from 'playwright'
import { ethers } from 'ethers'
const SITE = process.env.SITE || 'http://localhost:4173/explorer/?view=console'
const p = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz', 10143, { staticNetwork: true })
const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`, '--proxy-bypass-list=localhost;127.0.0.1'] : []
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--headless=new', ...proxyArgs] })
const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 }, ignoreHTTPSErrors: true })).newPage()
const errors = []; page.on('pageerror', (e) => errors.push(e.message))
const user = ethers.Wallet.createRandom().address
await page.exposeFunction('ownerRpc', async (m, a) => { for (let i = 0; ; i++) { try { return await p.send(m, a || []) } catch (e) { if (i > 5) throw e; await new Promise((r) => setTimeout(r, 500 * 2 ** i)) } } })
await page.addInitScript((addr) => {
  const provider = { request: async ({ method, params }) => method === 'eth_requestAccounts' || method === 'eth_accounts' ? [addr] : method === 'eth_chainId' ? '0x279f' : method.startsWith('wallet_') ? null : window.ownerRpc(method, params), on() {}, removeListener() {} }
  window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'a', name: 'Audit Wallet', icon: '', rdns: 'dev.audit' }, provider }) })))
  try { localStorage.setItem('gx-wallet', 'dev.audit') } catch {}
}, user)
await page.goto(SITE)
const cards = page.locator('section, div').filter({ hasText: /^Agent ID cards/ }).first()
await page.getByText(/active cards?:/).waitFor({ timeout: 90000 })
const panel = page.locator('li.gx-surface-2')
const titles = await panel.locator('p.gx-t1.font-bold').allInnerTexts()
console.log('cards shown:', titles.map((t) => t.replace(/\s+/g, ' ')))
console.log('footer:', (await page.getByText(/active cards?:/).innerText()).replace(/\s+/g, ' '))
await page.getByText('Agent ID cards').first().scrollIntoViewIfNeeded()
const box = page.locator('div', { has: page.getByText(/active cards?:/) }).last()
await page.screenshot({ path: 'qa/e2e/cards-after.png', fullPage: true })
console.log('page errors:', errors.length ? errors : 'none')
await browser.close()
