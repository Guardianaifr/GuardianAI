import {
  CronCapability,
  HTTPClient,
  EVMClient,
  handler,
  ConsensusAggregationByFields,
  median,
  identical,
  Runner,
  type NodeRuntime,
  type Runtime,
  getNetwork,
  bytesToHex,
  hexToBase64,
} from "@chainlink/cre-sdk"
import { encodeAbiParameters, parseAbiParameters } from "viem"

// ---------------------------------------------------------------------------
// Configuration & Types
// ---------------------------------------------------------------------------

type EvmConfig = {
  chainName: string
  consumerAddress: string
  gasLimit: string
}

type Config = {
  schedule: string
  apiUrl: string
  evms: EvmConfig[]
}

/**
 * ThreatReport represents the verified threat telemetry from GuardianAI.
 * Each field maps to a counter tracked by the off-chain security engine.
 */
type ThreatReport = {
  blocked: bigint
  intercepted: bigint
  passed: bigint
  threatDigest: string
}

// ---------------------------------------------------------------------------
// Node-Level Execution: Fetch Threat Stats
// ---------------------------------------------------------------------------

/**
 * fetchThreatStats runs independently on each DON node.
 * Each node fetches the latest threat statistics from the GuardianAI API,
 * then consensus aggregates the results for reliability.
 */
const fetchThreatStats = (nodeRuntime: NodeRuntime<Config>): ThreatReport => {
  const httpClient = new HTTPClient()

  const resp = httpClient
    .sendRequest(nodeRuntime, {
      url: nodeRuntime.config.apiUrl,
      method: "GET" as const,
    })
    .result()

  const body = JSON.parse(new TextDecoder().decode(resp.body))

  // Map the GuardianAI /stats response to our ThreatReport shape
  const stats = body.stats || body
  return {
    blocked: BigInt(stats.blocked || 0),
    intercepted: BigInt(stats.intercepted || 0),
    passed: BigInt(stats.passed || 0),
    threatDigest: body.threat_digest || "0x" + "0".repeat(64),
  }
}

// ---------------------------------------------------------------------------
// DON-Level Execution: Orchestrate & Write On-Chain
// ---------------------------------------------------------------------------

/**
 * onCronTrigger is the main callback executed when the cron trigger fires.
 * It orchestrates the full pipeline:
 *   1. Fetch threat stats (each node independently via runInNodeMode)
 *   2. Reach consensus across DON nodes
 *   3. Generate a signed report
 *   4. Write the verified report to the consumer contract on Monad
 */
const onCronTrigger = (runtime: Runtime<Config>): ThreatReport => {
  const evmConfig = runtime.config.evms[0]

  // Resolve the chain selector for Monad Testnet
  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: evmConfig.chainName,
  })
  if (!network) {
    throw new Error(`Unknown chain: ${evmConfig.chainName}`)
  }

  // Step 1: Fetch + Consensus
  // Each DON node calls the GuardianAI API independently.
  // Field-level consensus ensures numeric counters use median aggregation
  // while the cryptographic threat digest uses identical aggregation.
  const report = runtime
    .runInNodeMode(
      fetchThreatStats,
      ConsensusAggregationByFields<ThreatReport>({
        blocked: () => median(),
        intercepted: () => median(),
        passed: () => median(),
        threatDigest: () => identical(),
      })
    )()
    .result()

  runtime.log(
    `Guardian threat stats verified — blocked: ${report.blocked}, ` +
      `intercepted: ${report.intercepted}, passed: ${report.passed}`
  )

  // Step 2: Encode the report for the on-chain consumer contract
  const evmClient = new EVMClient(network.chainSelector.selector)

  const reportData = encodeAbiParameters(
    parseAbiParameters(
      "uint256 blocked, uint256 intercepted, uint256 passed, string threatDigest"
    ),
    [report.blocked, report.intercepted, report.passed, report.threatDigest]
  )

  // Step 3: Generate a cryptographically signed report via DON consensus
  const signedReport = runtime
    .report({
      encodedPayload: hexToBase64(reportData),
      encoderName: "evm",
      signingAlgo: "ecdsa",
      hashingAlgo: "keccak256",
    })
    .result()

  runtime.log(
    `Signed report generated — writing to consumer ${evmConfig.consumerAddress}`
  )

  // Step 4: Write the signed report to the GuardianThreatConsumer on Monad
  const writeResult = evmClient
    .writeReport(runtime, {
      receiver: evmConfig.consumerAddress,
      report: signedReport,
      gasConfig: {
        gasLimit: evmConfig.gasLimit,
      },
    })
    .result()

  const txHash = bytesToHex(writeResult.txHash || new Uint8Array(32))
  runtime.log(`✅ Threat report committed to Monad — TX: ${txHash}`)

  return report
}

// ---------------------------------------------------------------------------
// Workflow Registration
// ---------------------------------------------------------------------------

const initWorkflow = (config: Config) => {
  const cron = new CronCapability()
  return [handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)]
}

export async function main() {
  const runner = await Runner.newRunner<Config>()
  await runner.run(initWorkflow)
}
