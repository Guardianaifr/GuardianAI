# guardianai-eliza-host

Hosted ElizaOS agents for the GuardianAI console. Every agent created at
https://aiguardian.dev/explorer/?view=console gets a "Talk to your agent" chat backed by this service.

**Non-custodial.** The server never receives an agent key:
1. The browser signs a session message with the agent key → `POST /api/eliza/session`. The server checks the
   signature and, on Monad, that the factory made this wallet for this owner and that the key is its operator.
2. `POST /api/eliza/message` runs the user's text through a real ElizaOS 1.7 agent (Groq LLM) with the
   GuardianAI plugin in external-signer mode: memory guard → GuardianAI relay approval → on-chain dry run.
3. If approved, the server returns the signed `execute(...)` call. The browser checks it is for this wallet and
   exactly the payment shown, then sends it from its own agent key.

Live: https://guardian-eliza-production.up.railway.app/health (Railway project `guardian-relay`, service `guardian-eliza`).

**LLM failover** (`src/llm.ts`): Groq first; on a 429 / 5xx / timeout the same message goes straight to OpenRouter, and Groq
is skipped until its retry-after passes. OpenRouter defaults to free models (`nvidia/nemotron-3-super-120b-a12b:free`, then
Nemotron Ultra, then Gemma via OpenRouter's `models` routing). **OpenRouter is free-models-only:** any model
without `:free` in the settings is ignored. `/health` shows `served` per provider
and `failovers`.

Variables: `GROQ_API_KEY`, `OPENROUTER_API_KEY` (an inference key with a spend limit, not a management key), `SESSION_SECRET`, `CORS_ORIGINS`, optional `ELIZA_DATA_DIR`, `MAX_AGENTS` (25), `MAX_QUEUE` (8),
`GUARDIAN_RELAY_URL`. One LLM call at a time (free Groq tier: 8k tokens/min ≈ 2–3 messages/min overall);
10 messages/min per wallet.

## Build, test, deploy

```bash
npm install && npm run build
PORT=8099 GROQ_API_KEY=... node dist/server.js
npm test                                                                           # failover unit tests
HOST=http://localhost:8099 OWNER=0x… WALLET=0x… AGENT_KEY_FILE=agent.key npm run test:live   # live: sends one 0.001 MON payment
```

Deploy: put `Dockerfile`, `package.json`, `dist/` and a `railway.json` (builder DOCKERFILE, healthcheck `/health`)
in a folder, then `RAILWAY_TOKEN=<project token> railway up --service guardian-eliza --detach`.
