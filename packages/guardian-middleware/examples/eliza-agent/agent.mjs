// Start the ElizaOS agent with GuardianAI. Shared by demo.mjs and chat.mjs.
import { ElizaOS, stringToUuid } from '@elizaos/core'
import sqlPlugin, { createDatabaseAdapter } from '@elizaos/plugin-sql'
import groqPlugin from '@elizaos/plugin-groq'
import bootstrapPlugin from '@elizaos/plugin-bootstrap'
import path from 'path'
import { guardianPlugin } from '../../src/elizaos.ts'
import { loadEnv, here } from './env.mjs'

export async function startAgent({ onPayment } = {}) {
  loadEnv()
  for (const k of ['GROQ_API_KEY', 'GUARDIAN_AGENT_PRIVATE_KEY', 'GUARDIAN_WALLET', 'GUARDIAN_OWNER'])
    if (!process.env[k]) throw new Error(`${k} missing: put GROQ_API_KEY in the repo .env and run "npm run eliza:setup"`)
  if (onPayment) {
    const a = guardianPlugin.actions[0], orig = a.handler
    a.handler = async (...args) => { const r = await orig(...args); onPayment(r.data); return r }
  }
  const AGENT_ID = stringToUuid('GuardianTreasurer')
  // plugin-sql 1.7 checks the agents table before migrating, so migrate first.
  const db = createDatabaseAdapter({ dataDir: path.join(here, '.eliza-db') }, AGENT_ID)
  await db.init()
  await db.runPluginMigrations([sqlPlugin], { verbose: false })
  const eliza = new ElizaOS()
  const [rt] = await eliza.addAgents([{
    databaseAdapter: db,
    character: {
      id: AGENT_ID, name: 'Treasurer', plugins: [],
      bio: ['An autonomous treasury agent for a small team on Monad testnet. It pays invoices in MON when asked.'],
      system: 'You are Treasurer. When someone asks you to pay, send or transfer MON to an address, use the GUARDED_PAYMENT action. Report the result honestly.',
    },
    plugins: [sqlPlugin, groqPlugin, bootstrapPlugin, guardianPlugin],
    settings: {
      GROQ_API_KEY: process.env.GROQ_API_KEY,
      GROQ_SMALL_MODEL: process.env.GROQ_SMALL_MODEL || 'openai/gpt-oss-20b',
      GROQ_LARGE_MODEL: process.env.GROQ_LARGE_MODEL || 'openai/gpt-oss-120b',
      GUARDIAN_AGENT_PRIVATE_KEY: process.env.GUARDIAN_AGENT_PRIVATE_KEY,
      GUARDIAN_WALLET: process.env.GUARDIAN_WALLET,
      GUARDIAN_OWNER: process.env.GUARDIAN_OWNER,
      ...(process.env.GUARDIAN_RELAY_URL ? { GUARDIAN_RELAY_URL: process.env.GUARDIAN_RELAY_URL } : {}),
    },
  }], { returnRuntimes: true, autoStart: true })
  const user = stringToUuid('team-lead')
  const say = async (room, text) => {
    const res = await eliza.handleMessage(rt.agentId, { entityId: user, roomId: stringToUuid(room), content: { text, source: 'cli' } })
    return res.processing?.responseContent || {}
  }
  return { eliza, rt, user, say }
}
