import { encodeConnectCode, decodeConnectCode } from '../dist/index.js'
let n = 0; const ok = (c, l) => { if (!c) { console.error('FAIL', l); process.exit(1) } n++; console.log('  [+]', l) }
const info = { wallet: '0xc928C9743c466Ea9f491eCff9B0EDB8Dbf2F2Faa', owner: '0x2d21D39E67126e8D3ab2FD806fDc74827B2EAb41', agentKey: '0x' + 'ab'.repeat(32), chainId: 10143 }
const code = encodeConnectCode(info)
ok(code.startsWith('gx1_') && !/[+/=]/.test(code), 'code is gx1_ + url-safe base64 (pastes in any shell)')
ok(JSON.stringify(decodeConnectCode(code)) === JSON.stringify(info), 'round trip')
ok(JSON.stringify(decodeConnectCode('  ' + code + '\n')) === JSON.stringify(info), 'tolerates spaces/newline from copy-paste')
const bad = (s) => { try { decodeConnectCode(s); return false } catch { return true } }
ok(bad('hello') && bad('gx1_!!!') && bad(code.slice(0, 30)), 'rejects junk / truncated codes')
const { guardianPlugin, default: dflt } = await import('../dist/index.js')
ok(guardianPlugin.name === 'guardianai' && dflt === guardianPlugin && guardianPlugin.actions[0].name === 'GUARDED_PAYMENT', 'exports the ElizaOS plugin (named + default)')
console.log(`${n}/${n} passed`)
