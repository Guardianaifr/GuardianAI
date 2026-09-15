/**
 * setup_privy_policy.ts
 *
 * Creates Privy hardware Policy Engine rules for GuardianAI agents.
 *
 * Policy rules enforce:
 *   1. Only Monad Testnet (chain_id == 10143)
 *   2. Only the GuardianPolicyGuard contract (to == 0x32fa...1101)
 *   3. Max transaction value <= 5 MON (in wei)
 *
 * Uses the verified Privy Policy schema:
 *   field_source: 'ethereum_transaction'
 *   operator: 'eq'   (equality check)
 *   operator: 'gt'   (greater-than check for value cap)
 *
 * Run with: npx ts-node scripts/setup_privy_policy.ts
 * Requires env vars: PRIVY_APP_ID, PRIVY_APP_SECRET
 */

import * as fs from "fs";
import * as path from "path";
import { PrivyClient } from "@privy-io/node";

// Load .env from project root or current directory if env vars not already set
function loadEnv() {
  const candidates = [
    path.resolve(process.cwd(), ".env"),
    path.resolve(process.cwd(), "../.env"),
    path.resolve(__dirname, "../.env"),
  ];
  for (const envPath of candidates) {
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, "utf-8");
        for (const line of content.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          const eqIdx = trimmed.indexOf("=");
          if (eqIdx !== -1) {
            const key = trimmed.slice(0, eqIdx).trim();
            const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
            if (!process.env[key]) {
              process.env[key] = val;
            }
          }
        }
        break;
      } catch {
        // Continue to next candidate
      }
    }
  }
}
loadEnv();

const PRIVY_APP_ID = process.env.PRIVY_APP_ID ?? "";
const PRIVY_APP_SECRET = process.env.PRIVY_APP_SECRET ?? "";

if (!PRIVY_APP_ID || !PRIVY_APP_SECRET) {
  throw new Error(
    "Missing PRIVY_APP_ID or PRIVY_APP_SECRET environment variables"
  );
}

/** GuardianPolicyGuard verified deploy address on Monad Testnet */
const POLICY_GUARD_ADDRESS = "0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101";

/** 5 MON in wei (5 * 10^18) as decimal string */
const MAX_VALUE_WEI = (5n * 10n ** 18n).toString();

async function main() {
  const privy = new PrivyClient({ appId: PRIVY_APP_ID, appSecret: PRIVY_APP_SECRET });

  console.log("Creating Privy Policy Engine rules for GuardianAI…");

  /**
   * Create a wallet policy with an allowlist rule.
   *
   * Privy Policy Engine is an ALLOWLIST engine.
   * A single ALLOW rule restricts transactions to:
   *   1. Monad Testnet (chain_id == 10143)
   *   2. Target contract is GuardianPolicyGuard (0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101)
   *   3. Value <= 5 MON (5000000000000000000 wei)
   */
  const policy = await privy.policies().create({
    version: "1.0",
    chain_type: "ethereum",
    name: "guardian-agent-monad-policy",
    rules: [
      {
        name: "allow-monad-policyguard-5mon",
        method: "eth_sendTransaction",
        action: "ALLOW",
        conditions: [
          {
            field_source: "ethereum_transaction",
            field: "chain_id",
            operator: "eq",
            value: "10143",
          },
          {
            field_source: "ethereum_transaction",
            field: "to",
            operator: "eq",
            value: POLICY_GUARD_ADDRESS.toLowerCase(),
          },
          {
            field_source: "ethereum_transaction",
            field: "value",
            operator: "lte",
            value: MAX_VALUE_WEI,
          },
        ],
      },
    ],
  });

  console.log("✅  Policy created successfully:");
  console.log(`    Policy ID : ${policy.id}`);
  console.log(`    Name      : ${policy.name}`);
  console.log();
  console.log("Next steps:");
  console.log(
    "  1. Copy the Policy ID and set VITE_PRIVY_AGENT_POLICY_ID in the dashboard .env"
  );
  console.log(
    "  2. Pass the Policy ID to AgentDelegationModal's policyId prop"
  );
  console.log(
    "  3. Pass the Policy ID to addSigners() in AgentDelegationModal.tsx"
  );
}

main().catch((err) => {
  console.error("Policy setup failed:", err);
  process.exit(1);
});
