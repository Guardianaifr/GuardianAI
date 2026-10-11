# ElizaOS agent with a GuardianAI-guarded wallet

A real ElizaOS 1.7 agent ("Treasurer") that pays invoices in MON on Monad testnet. Its money sits in a
**GuardianAgentWallet** (the same contract the [GuardianAI console](https://aiguardian.dev/explorer/?view=console)
creates). The agent key only pays gas; every payment needs a GuardianAI approval, and the wallet re-checks
it on-chain.

Three layers stop a tricked agent, even when the LLM itself obeys the attacker:

| Layer | Where | Stops |
|---|---|---|
| Memory guard | in the agent (`detectInjection`) | injected instructions in the request **or in earlier messages** (memory poisoning) |
| GuardianAI relay | `POST /api/v1/attest` | scam-list destinations, prompt injection, policy violations |
| GuardianAgentWallet | Monad contract | forged / replayed approvals, old agent keys, frozen wallet, Chainlink-flagged destinations (`FlaggedDestination`) |

## Run it

Needs Node 22.18+ (runs the `.ts` source directly) and a free Groq key.

```bash
cd packages/guardian-middleware
npm install
# repo-root .env: GROQ_API_KEY=...  and a funded key (FUNDER_PRIVATE_KEY, or GUARDIAN_DEPLOYER_PRIVATE_KEY)
npm run eliza:setup   # one time, ~0.45 MON: new owner + agent key, guarded wallet, scam protection, ID card, 0.01 MON
npm run eliza:demo    # honest invoice + 4 attacks, real transactions
npm run eliza:chat    # talk to it yourself
# add DEBUG=1 to see ElizaOS internal logs
```

## Use it in your own agent

```ts
import { guardianPlugin } from "@guardianai/middleware/elizaos";

plugins: [sqlPlugin, groqPlugin, bootstrapPlugin, guardianPlugin]
settings: { GUARDIAN_AGENT_PRIVATE_KEY, GUARDIAN_WALLET, GUARDIAN_OWNER }
```

Create the wallet in the console, then use "Replace agent key" there to set the operator to your agent's key.
