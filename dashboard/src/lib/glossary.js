/**
 * GuardianAI Glossary & Plain English Mapping Dictionary
 *
 * Translates low-level cryptographic and blockchain terms into
 * intuitive plain-English equivalents for web2 users in Simple mode,
 * while preserving precise technical terminology in Advanced mode.
 *
 * Every entry strictly avoids exaggerated claims ("secure", "verified", "hardware", "firewall", "vault").
 * Terms without a web2 consumer equivalent (precompile, Merkle root, PRF, relayer, entropy, bips, BFT consensus)
 * are marked hideInSimple: true to remain hidden behind "Show technical details" in Simple mode.
 * Each entry cites the exact repository file:line or vendor documentation that implements or references the primitive.
 */

export const GLOSSARY = {
  // TEE: Protected execution environment isolating code from untrusted host memory
  // Backed by: Privy key custody documentation (docs.privy.io/security/overview)
  "TEE": {
    simple: "Protected environment",
    advanced: "Trusted Execution Environment (TEE)",
    desc: "An isolated execution area inside a processor that separates code from host operating systems."
  },
  // Backed by: Privy key custody documentation (docs.privy.io/security/overview)
  "Trusted Execution Environment": {
    simple: "Protected environment",
    advanced: "Trusted Execution Environment",
    desc: "An isolated execution area inside a processor."
  },
  // Enclave: Isolated memory boundary
  // Backed by: Privy key custody documentation (docs.privy.io/security/overview)
  "Enclave": {
    simple: "Protected execution zone",
    advanced: "Enclave",
    desc: "An isolated processor boundary protecting runtime memory."
  },
  // Isolated Enclave: Memory boundary isolating runtime execution
  // Backed by: Privy key custody documentation (docs.privy.io/security/overview)
  "Isolated Enclave": {
    simple: "Protected execution zone",
    advanced: "Isolated Enclave",
    desc: "An isolated processor boundary protecting runtime memory."
  },
  // Attestation: Cryptographic EIP-712 signature validating execution payload
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:100-115
  "Attestation": {
    simple: "Signed safety check",
    advanced: "Cryptographic Attestation",
    desc: "A cryptographically signed safety check confirming parameters match policy rules."
  },
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:100-115
  "attestation": {
    simple: "signed safety check",
    advanced: "attestation",
    desc: "A cryptographically signed safety check."
  },
  // Session Signer: Temporary delegated key with restricted authorization
  // Backed by: dashboard/src/components/AgentDelegationModal.tsx:44-46, dashboard/src/lib/delegationAdapter.js:33
  "Session Signer": {
    simple: "Delegated agent key",
    advanced: "Session Signer",
    desc: "A temporary cryptographic key granted limited authority to execute specific transactions."
  },
  // Backed by: dashboard/src/components/AgentDelegationModal.tsx:44-46
  "Session Signers": {
    simple: "Delegated agent keys",
    advanced: "Session Signers",
    desc: "Temporary cryptographic keys granted limited authority to execute specific transactions."
  },
  // Backed by: dashboard/src/lib/delegationAdapter.js:33
  "session signer": {
    simple: "delegated agent key",
    advanced: "session signer",
    desc: "Temporary key with scoped authorization."
  },
  // Backed by: dashboard/src/lib/delegationAdapter.js:33
  "session signers": {
    simple: "delegated agent keys",
    advanced: "session signers",
    desc: "Temporary keys with scoped authorization."
  },
  // MPC: Multi-party computation key management
  // Backed by: dashboard/src/components/PrivyConfigProvider.tsx:26
  "MPC": {
    simple: "Multi-party key management",
    advanced: "Multi-Party Computation (MPC)",
    desc: "A protocol where cryptographic private key shares are distributed across independent parties."
  },
  // Monad: High-throughput EVM execution layer
  // Backed by: dashboard/src/lib/monadChain.ts:5, contracts/contracts/GuardianPolicyGuard.sol:1
  "Monad": {
    simple: "High-speed network",
    advanced: "Monad Parallel EVM",
    desc: "High-performance EVM-compatible layer 1 blockchain with parallel transaction execution."
  },
  // Backed by: dashboard/src/lib/monadChain.ts:5
  "Monad Testnet": {
    simple: "Test network",
    advanced: "Monad Testnet",
    desc: "Public test network for Monad parallel execution."
  },
  // RIP-7212: secp256r1 curve precompile for passkey authentication
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:41-42, 229-246
  "RIP-7212": {
    simple: "Passkey check",
    advanced: "RIP-7212 Precompile",
    desc: "Native EVM precompile for secp256r1 elliptic curve signature validation."
  },
  // Gas: Computation fee
  // Backed by: dashboard/src/components/AgentsTab.jsx:234, contracts/contracts/GuardianPolicyGuard.sol:160
  "Gas": {
    simple: "Execution fee",
    advanced: "Gas",
    desc: "Computational fee paid to execute an operation on the blockchain network."
  },
  // Backed by: dashboard/src/components/AgentsTab.jsx:234
  "gas": {
    simple: "execution fee",
    advanced: "gas",
    desc: "Computational execution fee."
  },
  // Backed by: dashboard/src/components/AgentsTab.jsx:234
  "gas limit": {
    simple: "fee limit",
    advanced: "gas limit",
    desc: "Maximum computational steps allocated for an execution."
  },
  // Policy Guard: Rules engine blocking unauthorized actions
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:18-35
  "Policy Guard": {
    simple: "Policy rules engine",
    advanced: "Policy Guard",
    desc: "Smart contract rules engine that validates permissions and stops rogue actions before execution."
  },
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:18-35
  "GuardianPolicyGuard": {
    simple: "Policy rules engine",
    advanced: "GuardianPolicyGuard.sol",
    desc: "Core on-chain enforcement contract for transaction pre-flight checks."
  },
  // Soulbound agent passport (ERC-5192): Agent passport and identity registry
  // Backed by: contracts/contracts/GuardianPassportSBT.sol:8-25, metropolis/indexer/schema.graphql:22
  "ERC-8004": {
    simple: "Registered agent ID",
    advanced: "Soulbound agent passport (ERC-5192)",
    desc: "Standard for autonomous AI agent identification, reputation registry, and execution delegation."
  },
  "ERC-5192": {
    simple: "Registered agent ID",
    advanced: "Soulbound agent passport (ERC-5192)",
    desc: "Standard for minimal soulbound non-transferable token identification."
  },
  // Soulbound: Non-transferable token standard ERC-5192
  // Backed by: contracts/contracts/GuardianPassportSBT.sol:8-25
  "Soulbound": {
    simple: "Non-transferable ID",
    advanced: "Soulbound Token (ERC-5192)",
    desc: "Identity credential permanently bound to an agent address that cannot be transferred."
  },
  // Backed by: contracts/contracts/GuardianPassportSBT.sol:8-25
  "Soulbound Token": {
    simple: "Non-transferable agent ID",
    advanced: "Soulbound Token (ERC-5192)",
    desc: "Non-transferable token representing permanent agent identity and reputation standing."
  },
  // EIP-712: Structured typed data hashing and signing
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:74-95
  "EIP-712": {
    simple: "Signed typed request",
    advanced: "EIP-712 Structured Data Signature",
    desc: "Standard for hashing and signing structured data parameters transparently."
  },
  // Merkle Root: Root hash committing state tree (hidden in Simple mode behind technical details)
  // Backed by: contracts/contracts/GuardianCortexAnchor.sol:20-35, metropolis/indexer/schema.graphql:34
  "Merkle Root": {
    simple: null,
    hideInSimple: true,
    advanced: "Merkle Root",
    desc: "Cryptographic root hash committing a batch of execution records."
  },
  // Precompile: Built-in node algorithm (hidden in Simple mode behind technical details)
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:41-42, 229-246
  "Precompile": {
    simple: null,
    hideInSimple: true,
    advanced: "EVM Precompile",
    desc: "Native node-level algorithm executed outside bytecode for efficiency."
  },
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:41-42, 229-246
  "precompile": {
    simple: null,
    hideInSimple: true,
    advanced: "precompile",
    desc: "Native node-level algorithm."
  },
  // PRF: WebAuthn pseudo-random function (hidden in Simple mode behind technical details)
  // Backed by: dashboard/src/components/AgentsTab.jsx:566
  "PRF": {
    simple: null,
    hideInSimple: true,
    advanced: "Pseudo-Random Function (PRF)",
    desc: "WebAuthn PRF extension allowing symmetric key derivation with authenticators."
  },
  // RPC: Communication endpoint
  // Backed by: dashboard/src/lib/guardianViemClient.ts:10
  "RPC": {
    simple: "Network connection",
    advanced: "JSON-RPC Endpoint",
    desc: "Communications interface used to read and submit data to blockchain nodes."
  },
  // Mempool: Pending transactions waiting for block inclusion
  // Backed by: dashboard/src/components/LogsTab.jsx:18
  "Mempool": {
    simple: "Pending action queue",
    advanced: "Transaction Mempool",
    desc: "Holding area for submitted actions awaiting network confirmation."
  },
  // BFT consensus: Distributed consensus protocol (hidden in Simple mode behind technical details)
  // Backed by: dashboard/src/components/DashboardTab.jsx:104
  "BFT consensus": {
    simple: null,
    hideInSimple: true,
    advanced: "BFT Consensus",
    desc: "Byzantine Fault Tolerant consensus ensuring network agreement across nodes."
  },
  // Smart contract: Deployed code on chain
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:1-20
  "Smart contract": {
    simple: "On-chain policy rule",
    advanced: "Smart Contract",
    desc: "Program code executed on the blockchain network."
  },
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:1-20
  "Smart Contracts": {
    simple: "On-chain policy rules",
    advanced: "Smart Contracts",
    desc: "Program code executed on the blockchain network."
  },
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:1-20
  "smart contract": {
    simple: "on-chain policy rule",
    advanced: "smart contract",
    desc: "Program code executed on the blockchain network."
  },
  // Relayer: Backend transaction submitter (hidden in Simple mode behind technical details)
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:142
  "Relayer": {
    simple: null,
    hideInSimple: true,
    advanced: "Attestation Relayer",
    desc: "Service submitting validated actions with signatures."
  },
  // Backed by: contracts/contracts/GuardianPolicyGuard.sol:142
  "relayer": {
    simple: null,
    hideInSimple: true,
    advanced: "relayer",
    desc: "Service submitting validated actions."
  },
  // Entropy: Prompt randomness measure (hidden in Simple mode behind technical details)
  // Backed by: dashboard/src/components/AgentsTab.jsx:131
  "Entropy": {
    simple: null,
    hideInSimple: true,
    advanced: "Shannon Entropy Analysis",
    desc: "Statistical measure of prompt randomness used to flag obfuscated injections."
  },
  // Bips: Basis points (hidden in Simple mode behind technical details)
  // Backed by: dashboard/src/components/AgentsTab.jsx:602
  "Bips": {
    simple: null,
    hideInSimple: true,
    advanced: "Basis Points (bips)",
    desc: "Unit of proportion equal to one hundredth of a percentage point."
  }
};

/**
 * Translates a technical term according to the active mode.
 * In Simple mode, returns null if hideInSimple is true (to be placed behind "Show technical details").
 *
 * @param {string} term - The technical term to lookup
 * @param {boolean} isAdvanced - Whether advanced mode is active
 * @returns {string|null} - The translated term, or null if hidden in Simple mode
 */
export function t(term, isAdvanced = false) {
  if (!term || typeof term !== "string") return term;
  
  if (isAdvanced) {
    if (GLOSSARY[term]?.advanced) return GLOSSARY[term].advanced;
    return term;
  }

  // Simple mode: if explicitly marked to hide behind technical details, return null
  if (GLOSSARY[term]?.hideInSimple) {
    return null;
  }

  // Simple mode: return plain English equivalent if present
  if (GLOSSARY[term]?.simple) {
    return GLOSSARY[term].simple;
  }

  // Case-insensitive fallback lookup
  const lower = term.toLowerCase();
  for (const [key, entry] of Object.entries(GLOSSARY)) {
    if (key.toLowerCase() === lower) {
      if (entry.hideInSimple) return null;
      if (entry.simple) return entry.simple;
    }
  }

  return term;
}

/**
 * Helper to sanitize free text by replacing common jargon phrases in Simple mode.
 * In Advanced mode, leaves text unchanged.
 * NOTE: Address and hash regexes are NOT included here to prevent altering hex data values.
 */
export function sanitizeJargon(text, isAdvanced = false) {
  if (!text || typeof text !== "string" || isAdvanced) return text;

  let cleaned = text;

  // Replacements in simple mode (strictly avoiding vault, firewall, hardware, secure, verified):
  const replacements = [
    [/\bERC-8004\b/gi, "Registered Agent ID"],
    [/\bRIP-7212\b/gi, "Passkey Check"],
    [/\bEIP-712\b/gi, "signed typed request"],
    [/\bTEE\b/gi, "Protected Environment"],
    [/\bhardware enclaves?\b/gi, "protected zone"],
    [/\benclaves?\b/gi, "protected zone"],
    [/\battestations?\b/gi, "signed safety check"],
    [/\bsession signers?\b/gi, "delegated agent keys"],
    [/\bMonad Testnet\b/gi, "Test Network"],
    [/\bMonad Parallel EVM\b/gi, "Parallel Execution Engine"],
    [/\bMonad\b/gi, "High-Speed Network"],
    [/\bGuardianPolicyGuard\.sol\b/gi, "Policy Rules Engine"],
    [/\bGuardianPolicyGuard\b/gi, "Policy Rules Engine"],
    [/\bgas limit\b/gi, "fee limit"],
    [/\bgas\b/gi, "execution fee"]
  ];

  for (const [regex, replacement] of replacements) {
    cleaned = cleaned.replace(regex, replacement);
  }

  return cleaned;
}
