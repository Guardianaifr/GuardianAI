/**
 * mint_guardian_passport.ts
 *
 * Script to mint a GuardianPassportSBT for an AI agent.
 *
 * CRITICAL DESIGN NOTE — agentHash is computed OFF-CHAIN:
 * ─────────────────────────────────────────────────────────
 * The GuardianPassportSBT.sol contract expects `_agentHash` (bytes32) to be
 * supplied by the CALLER. The contract does NOT compute keccak256(agentId)
 * internally — it stores whatever bytes32 is passed in.
 *
 * Therefore this script computes:
 *   agentHash = keccak256(toHex(agentId))
 * before calling mint().
 *
 * Contract function signature (GuardianPassportSBT.sol line 133-138):
 *   function mint(
 *     address _to,
 *     bytes32 _agentHash,
 *     uint256 _score,
 *     string calldata _metadataURI
 *   ) external onlyOwner whenNotPaused nonReentrant returns (uint256 tokenId)
 *
 * Run with: npx ts-node backend/scripts/mint_guardian_passport.ts
 * Required env vars:
 *   GUARDIAN_DEPLOYER_PRIVATE_KEY — deployer/owner private key (0x-prefixed)
 *   MONAD_TESTNET_RPC             — optional, defaults to https://testnet-rpc.monad.xyz
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

// ── Configuration ─────────────────────────────────────────────────────────────

/** Verified GuardianPassportSBT deploy address on Monad Testnet */
const PASSPORT_SBT_ADDRESS = "0x65e081101a08F8c1C2df1cB9D008b3f988fF147f" as const;

const MONAD_TESTNET = {
  id: 10143,
  name: "Monad Testnet",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://testnet-rpc.monad.xyz"] },
    public: { http: ["https://testnet-rpc.monad.xyz"] },
  },
  testnet: true,
} as const;

// Minimal ABI for the mint function (no full import needed)
const PASSPORT_SBT_ABI = [
  {
    type: "function",
    name: "mint",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_to",          type: "address" },
      { name: "_agentHash",   type: "bytes32" },
      { name: "_score",       type: "uint256" },
      { name: "_metadataURI", type: "string"  },
    ],
    outputs: [{ name: "tokenId", type: "uint256" }],
  },
] as const;

// ── Inputs ─────────────────────────────────────────────────────────────────────

/** Address that will HOLD the SBT (agent's supervisor / owner wallet) */
const RECIPIENT_ADDRESS = process.env.GUARDIAN_RECIPIENT_ADDRESS ?? "";

/** Human-readable agent ID that uniquely identifies this agent */
const AGENT_ID = process.env.GUARDIAN_AGENT_ID ?? "guardian-agent-001";

/** Initial trust score (scaled by 100; 7500 = 75.00) */
const INITIAL_SCORE = 7500n;

/** Off-chain metadata URI for this passport */
const METADATA_URI =
  process.env.GUARDIAN_METADATA_URI ??
  `https://meta.guardianai.xyz/passport/${AGENT_ID}.json`;

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const deployerKey = process.env.GUARDIAN_DEPLOYER_PRIVATE_KEY as `0x${string}`;
  if (!deployerKey) {
    throw new Error("GUARDIAN_DEPLOYER_PRIVATE_KEY is not set");
  }
  if (!RECIPIENT_ADDRESS) {
    throw new Error("GUARDIAN_RECIPIENT_ADDRESS is not set");
  }

  const rpcUrl =
    process.env.MONAD_TESTNET_RPC ?? MONAD_TESTNET.rpcUrls.default.http[0];

  const account = privateKeyToAccount(deployerKey);

  const publicClient = createPublicClient({
    chain: MONAD_TESTNET as any,
    transport: http(rpcUrl),
  });

  const walletClient = createWalletClient({
    account,
    chain: MONAD_TESTNET as any,
    transport: http(rpcUrl),
  });

  // ── Compute agentHash OFF-CHAIN ───────────────────────────────────────────
  // The contract expects a pre-computed bytes32.
  // keccak256(toHex(agentId)) produces the canonical hash.
  // toHex() encodes the UTF-8 string as 0x-prefixed hex bytes.
  const agentHash = keccak256(toHex(AGENT_ID));

  console.log(`Minting GuardianPassportSBT`);
  console.log(`  Contract  : ${PASSPORT_SBT_ADDRESS}`);
  console.log(`  Recipient : ${RECIPIENT_ADDRESS}`);
  console.log(`  Agent ID  : ${AGENT_ID}`);
  console.log(`  agentHash : ${agentHash}  ← computed off-chain via keccak256(toHex(agentId))`);
  console.log(`  Score     : ${INITIAL_SCORE} (= ${Number(INITIAL_SCORE) / 100}%)`);
  console.log(`  Metadata  : ${METADATA_URI}`);
  console.log();

  // ── Simulate first to surface any revert reasons ─────────────────────────
  const { result: tokenId } = await publicClient.simulateContract({
    address: PASSPORT_SBT_ADDRESS,
    abi: PASSPORT_SBT_ABI,
    functionName: "mint",
    args: [
      RECIPIENT_ADDRESS as `0x${string}`,
      agentHash as `0x${string}`,
      INITIAL_SCORE,
      METADATA_URI,
    ],
    account: account.address,
  });

  console.log(`Simulation passed. Predicted tokenId: ${tokenId}`);

  // ── Send the actual transaction ───────────────────────────────────────────
  const txHash = await walletClient.writeContract({
    address: PASSPORT_SBT_ADDRESS,
    abi: PASSPORT_SBT_ABI,
    functionName: "mint",
    args: [
      RECIPIENT_ADDRESS as `0x${string}`,
      agentHash as `0x${string}`,
      INITIAL_SCORE,
      METADATA_URI,
    ],
  });

  console.log(`Transaction submitted: ${txHash}`);
  console.log(`Explorer: https://testnet.monadscan.com/tx/${txHash}`);

  // ── Wait for confirmation ─────────────────────────────────────────────────
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  if (receipt.status === "success") {
    console.log(`✅  Passport minted! tokenId=${tokenId}, block=${receipt.blockNumber}`);
  } else {
    console.error("❌  Transaction reverted:", receipt);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Mint script failed:", err);
  process.exit(1);
});
