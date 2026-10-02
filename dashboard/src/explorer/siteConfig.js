/**
 * siteConfig.js: the few things you will change before submitting.
 *
 * REPO_PUBLIC: set to true once github.com/Guardianaifr/GuardianAI is public.
 *              While false, the page shows no repo links (they would 404 for judges).
 * VIDEO_URL:   paste the demo video link (YouTube/Loom) to show a "Watch the demo" button.
 * SPONSORS:    update `status` when something goes live (e.g. the Chainlink consumer is deployed).
 * FOUNDER, AUDIENCE, BUSINESS, NEXT: the "Who it's for" section. Judges score Founder & Market
 *              Readiness (25%) on this, so make every line something you will stand behind.
 *              BUSINESS and NEXT are DRAFTS: edit them to your real plan before submitting.
 */
export const REPO_URL = 'https://github.com/Guardianaifr/GuardianAI'
export const REPO_PUBLIC = false
export const VIDEO_URL = ''

export const repoLink = (path = '') =>
  REPO_PUBLIC ? `${REPO_URL}${path ? `/tree/main/${path}` : ''}` : null

export const SPONSORS = [
  {
    key: 'mera',
    name: 'Category Labs Mera',
    bounty: 'Mera bounty',
    title: 'Passkey identity and sealed agent memory',
    body: 'A fingerprint or Face ID passkey creates the agent’s identity and the key that locks its memory. No private key is ever stored. If anyone changes even one byte of the agent’s memory, the check fails and the agent is frozen.',
    status: 'Built, runs locally',
    statusKind: 'local',
    howToRun: 'cd metropolis/mera && npm run demo',
    path: 'metropolis/mera',
  },
  {
    key: 'envio',
    name: 'Envio HyperIndex',
    bounty: 'Envio bounty',
    title: 'Real-time indexing of every security event',
    body: 'Indexes events from five GuardianAI contracts on Monad testnet (signed actions, scam-list changes, passport updates, risk scores, memory anchors) into one GraphQL API for dashboards.',
    status: 'Built, runs locally',
    statusKind: 'local',
    howToRun: 'cd metropolis/indexer && pnpm envio dev',
    path: 'metropolis/indexer',
  },
  {
    key: 'chainlink',
    name: 'Chainlink CRE',
    bounty: 'Chainlink CRE bounty',
    title: 'Decentralized threat oracle',
    body: 'Every 30 seconds, a Chainlink workflow fetches GuardianAI’s threat stats, nodes agree on the result, and a signed report is written to a consumer contract on Monad.',
    status: 'Tested in the CRE simulator · consumer contract not deployed yet',
    statusKind: 'simulated',
    howToRun: 'cre workflow simulate guardian-threat-sync --target staging-settings',
    path: 'metropolis/chainlink',
  },
]

export const FOUNDER = {
  name: '', // your name, if you want it shown
  role: 'Solo founder and developer',
  handle: '@noob_nad',
  url: 'https://x.com/noob_nad',
}

export const AUDIENCE = [
  { title: 'Teams shipping agents that hold wallets', body: 'Trading, payment and DeFi agents built on ElizaOS or any viem wallet. One prompt injection can empty the wallet; GuardianAI stands between the prompt and the money.' },
  { title: 'Wallets and dApps on Monad', body: 'Refuse payments to known drainers and to agents that aren’t registered, with a single read call to a public contract. No package, no API key.' },
  { title: 'Agent marketplaces and platforms', body: 'Check that an agent has an active, revocable ID card before letting it trade or pay on a user’s behalf.' },
]

// Model: free for end users, usage-based for builders (like GoPlus / Turnkey), paid in USDC on Monad via x402.
// The last line states what is live today; keep it accurate.
export const BUSINESS = [
  'Agent users never pay. Protection comes built into the agent or wallet they already use.',
  'Builders start free: the on-chain rules (scam list, agent ID cards, payment guard) are public, the code is MIT-licensed, and the first approvals each month cost nothing.',
  'After that, agents pay per signed approval in USDC on Monad, through x402. No account and no API key: the agent pays as it goes.',
  'Teams that want a fixed bill get monthly bundles; wallets and platforms get custom contracts. Later, people who report scam wallets earn a share of fees.',
  'Today: pay-per-approval with x402 works on Monad testnet: $0.01 in USDC per approved action, settled on-chain, and blocked actions are never charged.',
]

// DRAFT: edit to your real post-hackathon plan.
export const NEXT = [
  'Verify every contract’s source on MonadScan',
  'Move pay-per-approval from Monad testnet to mainnet USDC',
  'Publish @guardianai/middleware to npm',
  'Deploy the Chainlink CRE consumer and run the threat oracle on testnet',
  'Register the first outside agent teams with ID cards',
  'External audit of the Monad contracts, then mainnet',
]
