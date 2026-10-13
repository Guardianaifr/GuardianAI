# GuardianAI Explorer (Attack Lab + Console)

Vite + React source of the public explorer at **https://aiguardian.dev/explorer/**. The production build is
copied into `website/explorer/` and deployed with the website (see [`website/README.md`](../website/README.md)).

`src/main.jsx` renders one of two pages:

| URL | Page | Source |
|---|---|---|
| `/explorer/` | **Attack Lab**: the public walkthrough (try an attack, see the firewall and the chain refuse it, live proof ledger, sponsor integrations) | `src/explorer/SimpleExplorer.jsx` |
| `/explorer/?view=console` (also `?view=developer`) | **Console**: create a guarded agent wallet on Monad testnet, claim an Agent ID card, fund it, and chat with a hosted ElizaOS agent that pays through GuardianAI | `src/explorer/Console.jsx` |

The console is non-custodial: the agent key is generated in the browser and kept in local storage (demo key);
the hosted agent returns the approved call and the browser checks and sends it.

## Live services it talks to

| Service | Default | Override |
|---|---|---|
| Monad testnet RPC | `https://testnet-rpc.monad.xyz` | `VITE_MONAD_RPC_URL` |
| GuardianAI relay (approvals, rules, threat feed) | `https://guardian-relay-production.up.railway.app` | `VITE_GUARDIAN_RELAY_URL` |
| Hosted ElizaOS agent (`packages/eliza-host`) | `https://guardian-eliza-production.up.railway.app` | `VITE_GUARDIAN_ELIZA_URL` |
| Envio GraphQL | `ENVIO_GRAPHQL` in `src/explorer/siteConfig.js` | edit the file |

Contract addresses come from `src/explorer/chain.js`. `src/explorer/siteConfig.js` holds the repo link, the
demo-video link and the sponsor cards.

## Develop

```bash
npm install
npm run dev        # http://localhost:5173 (the relay allows this origin by default)
npm test           # Vitest: 52 tests
npm run lint
npm run build      # dashboard/dist/, then copy into website/explorer/
```

`npm run dev` also proxies `/api` and `/ws/threats` to a local backend on `127.0.0.1:8001`, used only by the
older dashboard below.

## Real-network checks (`qa/`)

Node scripts that drive the deployed site with Playwright, for example
`qa/console-e2e-real.mjs` (a full console run on Monad testnet; costs testnet MON, needs a funded burner key)
and `qa/live-audit.mjs`. Each script documents its usage at the top. Outputs under `qa/real/` and
`qa/e2e-out/` are git-ignored.

## Older SaaS dashboard (not in the build)

`src/App.jsx`, `src/DeveloperConsole.jsx` and most of `src/components/` (all but `ErrorBoundary.jsx`) are the earlier telemetry dashboard (Privy login,
WebSocket threat feed from the backend, policy tabs). `main.jsx` no longer renders it. Its settings, if you
revive it: `VITE_PRIVY_APP_ID`, `VITE_WS_URL`, `VITE_GRAPHQL_URL`, `VITE_STANDALONE_MODE`, `VITE_AGENT_ADDRESS`,
`VITE_PRIVY_AGENT_POLICY_ID`, `VITE_RELAYER_URL`.
