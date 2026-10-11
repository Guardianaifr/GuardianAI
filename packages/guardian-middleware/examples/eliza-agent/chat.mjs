// Talk to the agent yourself. Try: "pay 0.001 MON to 0x…", or an injection. Ctrl+C to quit.
//   npm run eliza:chat
import './quiet.mjs'
import readline from 'readline/promises'
import { startAgent } from './agent.mjs'
let last
const { say } = await startAgent({ onPayment: (d) => { last = d } })
const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
console.log(`Treasurer is ready. Guarded wallet ${process.env.GUARDIAN_WALLET} on Monad testnet.`)
for (;;) {
  const text = await rl.question('\nyou> ')
  if (!text.trim()) continue
  last = undefined
  const reply = await say('chat', text)
  if (reply.text) console.log(`agent> ${reply.text}`)
  if (last) console.log(`guardian> ${last.message}${last.reasons?.length ? `\n          why: ${String(last.reasons[0]).slice(0, 160)}` : ''}`)
}
