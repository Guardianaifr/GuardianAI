/**
 * GuardianAI Glossary & Plain English Mapping Dictionary
 *
 * Translates low-level cryptographic and blockchain terms into
 * intuitive plain-English equivalents for web2 users in Simple mode,
 * while preserving precise technical terminology in Advanced mode.
 */

export const GLOSSARY = {
  // Hardware & Cryptographic Enclaves
  "TEE": {
    simple: "Hardware-secured vault",
    advanced: "Trusted Execution Environment (TEE)",
    desc: "A secure area inside a processor that isolates code and data from the operating system."
  },
  "Trusted Execution Environment": {
    simple: "Hardware-secured vault",
    advanced: "Trusted Execution Environment",
    desc: "Tamper-resistant hardware isolated from host system memory."
  },
  "Enclave": {
    simple: "Isolated security vault",
    advanced: "Hardware Enclave",
    desc: "Isolated processor boundary protecting keys from host memory inspection."
  },
  "hardware enclave": {
    simple: "isolated security vault",
    advanced: "hardware enclave",
    desc: "Isolated processor boundary."
  },
  "Attestation": {
    simple: "Cryptographic proof of integrity",
    advanced: "Cryptographic Attestation",
    desc: "Cryptographically signed verification confirming code running in an enclave hasn't been altered."
  },
  "attestation": {
    simple: "cryptographic proof",
    advanced: "attestation",
    desc: "Cryptographically signed verification."
  },
  "Session Signer": {
    simple: "Automated trading permission",
    advanced: "Session Signer",
    desc: "Temporary scoped cryptographic key granted authority to execute specific transactions."
  },
  "Session Signers": {
    simple: "Automated trading permissions",
    advanced: "Session Signers",
    desc: "Temporary scoped cryptographic keys granted authority to execute transactions."
  },
  "session signer": {
    simple: "automated trading permission",
    advanced: "session signer",
    desc: "Scoped authorization key."
  },
  "session signers": {
    simple: "automated trading permissions",
    advanced: "session signers",
    desc: "Scoped authorization keys."
  },
  "MPC": {
    simple: "Multi-key protection",
    advanced: "Multi-Party Computation (MPC)",
    desc: "Cryptographic protocol where private keys are split across multiple parties so no single party can leak them."
  },
  "Monad": {
    simple: "High-speed network",
    advanced: "Monad Parallel EVM",
    desc: "High-performance EVM-compatible layer 1 blockchain with parallel execution."
  },
  "Monad Testnet": {
    simple: "Secure test network",
    advanced: "Monad Testnet",
    desc: "Public test network for Monad parallel execution."
  },
  "RIP-7212": {
    simple: "Hardware passkey accelerator",
    advanced: "RIP-7212 Precompile",
    desc: "EVM precompile enabling gas-efficient native secp256r1 curve signature verification."
  },
  "Gas": {
    simple: "Network fee",
    advanced: "Gas",
    desc: "Computational fee paid to execute an operation on the network."
  },
  "gas": {
    simple: "network fee",
    advanced: "gas",
    desc: "Computational fee."
  },
  "gas limit": {
    simple: "maximum fee allocation",
    advanced: "gas limit",
    desc: "Upper bound of computational steps."
  },
  "Policy Guard": {
    simple: "Security firewall",
    advanced: "Policy Guard",
    desc: "Smart contract rules engine that validates permissions and aborts rogue actions before execution."
  },
  "GuardianPolicyGuard": {
    simple: "Automated Security Firewall",
    advanced: "GuardianPolicyGuard.sol",
    desc: "Core on-chain enforcement contract for transaction pre-flight checks."
  },
  "ERC-8004": {
    simple: "Agent digital ID",
    advanced: "ERC-8004 Trustless Agent Passport",
    desc: "Standard for autonomous AI agent identity, reputation registry, and execution delegation."
  },
  "Soulbound": {
    simple: "Non-transferable ID",
    advanced: "Soulbound Token (ERC-5192)",
    desc: "Cryptographic identity credential permanently tied to an agent that cannot be transferred or stolen."
  },
  "Soulbound Token": {
    simple: "Non-transferable agent ID",
    advanced: "Soulbound Token (ERC-5192)",
    desc: "Non-transferable token representing permanent agent identity and reputation."
  },
  "EIP-712": {
    simple: "Verified digital signature",
    advanced: "EIP-712 Structured Data Signature",
    desc: "Standard for hashing and signing typed structured data human-readably."
  },
  "Merkle Root": {
    simple: "Tamper-proof record summary",
    advanced: "Merkle Root",
    desc: "Cryptographic root hash verifying the integrity of an entire state dataset."
  },
  "Precompile": {
    simple: "Built-in speed engine",
    advanced: "EVM Precompile",
    desc: "Native node-level algorithm executed outside EVM bytecode for maximum throughput."
  },
  "precompile": {
    simple: "built-in speed engine",
    advanced: "precompile",
    desc: "Native node-level algorithm."
  },
  "PRF": {
    simple: "Hardware passkey derivation",
    advanced: "Pseudo-Random Function (PRF)",
    desc: "WebAuthn PRF extension allowing symmetric key derivation inside hardware authenticators."
  },
  "RPC": {
    simple: "Network connection",
    advanced: "JSON-RPC Endpoint",
    desc: "Communications endpoint used to interact with blockchain nodes."
  },
  "Mempool": {
    simple: "Pending action queue",
    advanced: "Transaction Mempool",
    desc: "Temporary holding area for unconfirmed transactions awaiting block inclusion."
  },
  "BFT consensus": {
    simple: "Agreement protocol",
    advanced: "BFT Consensus",
    desc: "Byzantine Fault Tolerant consensus ensuring network agreement even with failing nodes."
  },
  "Smart contract": {
    simple: "Automated security rule",
    advanced: "Smart Contract",
    desc: "Self-executing code deployed to the blockchain."
  },
  "Smart Contracts": {
    simple: "Automated security rules",
    advanced: "Smart Contracts",
    desc: "Self-executing code deployed to the blockchain."
  },
  "smart contract": {
    simple: "automated security rule",
    advanced: "smart contract",
    desc: "Self-executing code deployed to the blockchain."
  },
  "Relayer": {
    simple: "Transaction assistant",
    advanced: "Attestation Relayer",
    desc: "Off-chain service submitting validated transactions and cryptographic proofs."
  },
  "relayer": {
    simple: "transaction assistant",
    advanced: "relayer",
    desc: "Off-chain submission service."
  },
  "Entropy": {
    simple: "Unpredictability score",
    advanced: "Shannon Entropy Analysis",
    desc: "Statistical measure of prompt randomness used to detect obfuscated injection attacks."
  },
  "Bips": {
    simple: "Percentage basis",
    advanced: "Basis Points (bips)",
    desc: "One hundredth of a percentage point (1/100th of 1%)."
  }
};

/**
 * Translates a technical term according to the active mode.
 * @param {string} term - The technical term to lookup
 * @param {boolean} isAdvanced - Whether advanced mode is active
 * @returns {string} - The translated or original term
 */
export function t(term, isAdvanced = false) {
  if (!term || typeof term !== "string") return term;
  
  if (isAdvanced) {
    if (GLOSSARY[term]?.advanced) return GLOSSARY[term].advanced;
    return term;
  }

  // Simple mode: return plain English equivalent if present
  if (GLOSSARY[term]?.simple) {
    return GLOSSARY[term].simple;
  }

  // Case-insensitive fallback lookup
  const lower = term.toLowerCase();
  for (const [key, entry] of Object.entries(GLOSSARY)) {
    if (key.toLowerCase() === lower && entry.simple) {
      return entry.simple;
    }
  }

  return term;
}

/**
 * Helper to sanitize free text by replacing common jargon phrases in Simple mode.
 * In Advanced mode, leaves text unchanged.
 */
export function sanitizeJargon(text, isAdvanced = false) {
  if (!text || typeof text !== "string" || isAdvanced) return text;

  let cleaned = text;

  // Replacements in simple mode:
  const replacements = [
    [/\bERC-8004\b/gi, "Agent Identity"],
    [/\bRIP-7212\b/gi, "Passkey Engine"],
    [/\bprecompile\b/gi, "hardware accelerator"],
    [/\bprecompiles\b/gi, "hardware accelerators"],
    [/\bEIP-712\b/gi, "digital signature"],
    [/\bTEE\b/gi, "Secure Vault"],
    [/\benclave\b/gi, "secure area"],
    [/\benclaves\b/gi, "secure areas"],
    [/\battestation\b/gi, "security verification"],
    [/\battestations\b/gi, "security verifications"],
    [/\bsession signers?\b/gi, "automated permissions"],
    [/\bmempool\b/gi, "processing queue"],
    [/\bBFT consensus\b/gi, "network agreement"],
    [/\bMerkle root\b/gi, "tamper-proof summary"],
    [/\bMonad Testnet\b/gi, "Security Network"],
    [/\bMonad Parallel EVM\b/gi, "High-Speed Security Engine"],
    [/\bMonad\b/gi, "High-Speed Network"],
    [/\bGuardianPolicyGuard\.sol\b/gi, "Security Firewall"],
    [/\bGuardianPolicyGuard\b/gi, "Security Firewall"],
    [/\b0x[a-fA-F0-9]{40}\b/g, "Protected System Address"],
    [/\b0x[a-fA-F0-9]{4}\.\.\.[a-fA-F0-9]{4}\b/g, "Protected Address"],
    [/\b0x[a-fA-F0-9]{64}\b/g, "Security Verification ID"],
    [/\bgas limit\b/gi, "fee limit"],
    [/\bgas\b/gi, "transaction fee"]
  ];

  for (const [regex, replacement] of replacements) {
    cleaned = cleaned.replace(regex, replacement);
  }

  return cleaned;
}
