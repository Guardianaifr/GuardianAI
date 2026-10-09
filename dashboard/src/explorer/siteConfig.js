/**
 * siteConfig.js: the few things you will change before submitting.
 *
 * REPO_PUBLIC: set to true once github.com/Guardianaifr/GuardianAI is public.
 *              While false, the page shows no repo links (they would 404 for judges).
 * VIDEO_URL:   paste the demo video link (YouTube/Loom) to show a "Watch the demo" button.
 * SPONSORS:    update `status` when something changes (e.g. the CRE workflow runs on a live DON).
 * FOUNDER, AUDIENCE, BUSINESS, NEXT: the "Who it's for" section. Judges score Founder & Market
 *              Readiness (25%) on this, so make every line something you will stand behind.
 *              BUSINESS and NEXT are DRAFTS: edit them to your real plan before submitting.
 */
export const REPO_URL = 'https://github.com/Guardianaifr/GuardianAI'
export const REPO_PUBLIC = true
export const VIDEO_URL = ''

export const repoLink = (path = '') =>
  REPO_PUBLIC ? `${REPO_URL}${path ? `/tree/main/${path}` : ''}` : null

export const SPONSORS = [
  {
    key: 'privy',
    name: 'Privy',
    bounty: 'Privy bounty',
    title: 'Server wallet the agent can’t misuse',
    body: 'The agent’s key is a Privy server wallet with a policy attached: it can only sign calls to GuardianAI’s contracts, a capped USDC approval and small x402 fees. Ask it to sign anything else and Privy refuses before a signature exists. It is also the operator key of the agent’s GuardianAgentWallet on Monad.',
    status: 'Live on Monad testnet · lock-test: 6/6 forbidden actions refused',
    statusKind: 'live',
    howToRun: 'cd tools/privy-agent && node agent.cjs lock-test',
    path: 'tools/privy-agent',
  },
  {
    key: 'mera',
    name: 'Category Labs Mera',
    bounty: 'Mera bounty',
    title: 'One passkey: agent identity, sealed memory, credential vault',
    body: 'The operator’s passkey derives a separate key for each job (one PRF salt per namespace): an Ed25519 identity per agent, an AES-GCM key for its memory, and a Mera vault for its credentials. The identity key signs an agent card that GuardianAI’s relay checks before approving any payment. Nothing is stored; open the handoff link on a second device and the same keys come back.',
    status: 'Live in your browser · real passkey, no simulation',
    statusKind: 'live',
    howToRun: 'Open /mera/ → Create operator passkey → Derive agent DID',
    liveUrl: '/mera/',
    liveLabel: 'Try it with your passkey',
    path: 'metropolis/mera',
  },
  {
    key: 'chainlink',
    name: 'Chainlink CRE',
    bounty: 'Chainlink CRE bounty',
    title: 'Decentralized threat oracle the wallet obeys',
    body: 'A CRE workflow has every node fetch GuardianAI’s scam list, the nodes agree on it, and a signed report is written to GuardianThreatOracle on Monad. Only the Chainlink forwarder can write to it. Every GuardianAgentWallet checks the oracle before each call, so a flagged destination is refused on-chain even when everything else approved it.',
    status: 'On Monad testnet via CRE simulation (--broadcast) · not yet on a live DON',
    statusKind: 'simulated',
    howToRun: 'cre workflow simulate guardian-threat-sync --target staging-settings --broadcast',
    path: 'metropolis/chainlink',
  },
  {
    key: 'envio',
    name: 'Envio HyperIndex',
    bounty: 'Envio bounty',
    title: 'Every enforcement decision, queryable',
    body: 'Indexes the agent-wallet factory (every new wallet), each wallet’s executions, owner overrides and freezes, and the Chainlink oracle’s reports and flagged addresses into one GraphQL API, synced with HyperSync.',
    status: 'Deployed on Envio Cloud (HyperSync)',
    statusKind: 'live',
    howToRun: 'cd metropolis/indexer && pnpm envio dev',
    path: 'metropolis/indexer',
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
  'Run the Chainlink CRE threat oracle on a live DON with the production forwarder',
  'Register the first outside agent teams with ID cards',
  'External audit of the Monad contracts, then mainnet',
]
