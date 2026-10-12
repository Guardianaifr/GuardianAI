import { chromium } from 'playwright'
import { ethers } from 'ethers'
import fs from 'fs'
const SITE = process.env.SITE || 'http://localhost:4173/explorer/?view=console'
const p = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz', 10143, { staticNetwork: true })
const owner = new ethers.Wallet(fs.readFileSync(process.env.OWNER_KEY_FILE, 'utf8').trim())
const agentKey = fs.readFileSync(process.env.AGENT_KEY_FILE, 'utf8').trim()
const proxyArgs = process.env.HTTPS_PROXY ? [`--proxy-server=${process.env.HTTPS_PROXY}`, '--proxy-bypass-list=localhost;127.0.0.1'] : []
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--headless=new', ...proxyArgs] })
const page = await (await browser.newContext({ viewport: { width: 1280, height: 1000 }, ignoreHTTPSErrors: true })).newPage()
const errors = []; page.on('pageerror', (e) => errors.push(e.message))
const sent = []; page.on('request', (r) => { if (r.postData()?.includes('eth_sendRawTransaction')) sent.push(r.url()) })
await page.exposeFunction('ownerRpc', async (m, a) => { for (let i = 0; ; i++) { try { return await p.send(m, a || []) } catch (e) { if (i > 5) throw e; await new Promise((r) => setTimeout(r, 500 * 2 ** i)) } } })
await page.addInitScript(([addr, key]) => {
  const provider = { request: async ({ method, params }) => method === 'eth_requestAccounts' || method === 'eth_accounts' ? [addr] : method === 'eth_chainId' ? '0x279f' : method.startsWith('wallet_') ? null : method === 'eth_sendTransaction' ? Promise.reject(new Error('read-only')) : window.ownerRpc(method, params), on() {}, removeListener() {} }
  window.addEventListener('eip6963:requestProvider', () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail: Object.freeze({ info: { uuid: 'a', name: 'Audit Wallet', icon: '', rdns: 'dev.audit' }, provider }) })))
  try { localStorage.setItem('gx-wallet', 'dev.audit'); localStorage.setItem(`gx-agent-key:${addr.toLowerCase()}`, key) } catch {}
}, [owner.address, agentKey])
const ok = (c, l) => console.log(`${c ? 'PASS' : 'FAIL'}  ${l}`)
await page.goto(SITE)
const chat = page.locator('div.gx-card', { hasText: 'Talk to your agent' })
await chat.waitFor({ timeout: 90000 })
ok(!(await page.getByText('Let your agent try').count()), '"Let your agent try" card is gone')
const chips = await chat.locator('button.\\!rounded-full').allInnerTexts()
ok(chips.join('|') === 'Pay me 0.001 MON|Prompt injection|Scam-list address|Chainlink-flagged address|Agent skips GuardianAI', `chat has the 5 buttons: ${chips.join(' · ')}`)
await chat.getByRole('button', { name: 'Agent skips GuardianAI' }).click()
await chat.getByText(/Refused on-chain by the agent wallet|Didn’t|Couldn’t/).waitFor({ timeout: 60000 })
const t = (await chat.innerText()).replace(/\s+/g, ' ')
console.log('chat:', t.slice(t.indexOf('YOU'), t.indexOf('YOU') + 400))
ok(/Refused on-chain by the agent wallet/.test(t) && /Why: (PassportRevokedOrInactive|InvalidAttestationSignature)/.test(t), 'forged approval → refused on-chain, reason shown')
ok(sent.length === 0, 'no transaction was sent (dry run against Monad only)')
await chat.screenshot({ path: 'qa/e2e/skip-chip.png' })
console.log('page errors:', errors.length ? errors : 'none')
await browser.close()
