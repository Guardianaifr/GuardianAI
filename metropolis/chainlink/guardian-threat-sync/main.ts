/**
 * GuardianAI × Chainlink CRE — decentralized threat oracle for Monad.
 *
 *   Cron ─▶ every DON node fetches GuardianAI's threat feed (HTTP)
 *        ─▶ consensus: scam list + digest must be IDENTICAL on all nodes, counters use the MEDIAN
 *        ─▶ the workflow re-checks the digest, encodes the report, the DON signs it
 *        ─▶ Chainlink Forwarder delivers it to GuardianThreatOracle.onReport() on Monad
 *
 * GuardianAgentWallets read GuardianThreatOracle.isFlagged() before every call, so an address the DON
 * agreed on is refused on-chain. No GuardianAI hot key can write the list: only the Forwarder can.
 *
 * Report ABI (must match GuardianThreatOracle.sol):
 *   (uint64 asOf, uint256 blocked, uint256 intercepted, uint256 passed, bytes32 feedDigest,
 *    address[] addrs, bool[] flagged)
 */
import {
  bytesToHex,
  ConsensusAggregationByFields,
  cre,
  getNetwork,
  hexToBase64,
  identical,
  median,
  ok,
  text,
  type HTTPSendRequester,
  type Runtime,
  Runner,
} from "@chainlink/cre-sdk"
import { encodeAbiParameters, getAddress, keccak256, parseAbiParameters, stringToHex, type Address, type Hex } from "viem"

type Config = {
  schedule: string
  feedUrl: string
  evms: { chainName: string; oracleAddress: string; gasLimit: string }[]
}

type Feed = {
  blocked: bigint
  intercepted: bigint
  passed: bigint
  entriesJson: string
  digest: string
}

type Entry = { address: string; flagged: boolean }

const MAX_ENTRIES = 100

// ── Node mode: each DON node fetches the feed on its own ──────────────────
const fetchFeed = (sendRequester: HTTPSendRequester, config: Config): Feed => {
  const response = sendRequester.sendRequest({ url: config.feedUrl, method: "GET" }).result()
  if (!ok(response)) {
    throw new Error(`GuardianAI feed request failed with status ${response.statusCode}`)
  }
  const body = JSON.parse(text(response))
  return {
    blocked: BigInt(body.stats?.blocked ?? 0),
    intercepted: BigInt(body.stats?.intercepted ?? 0),
    passed: BigInt(body.stats?.passed ?? 0),
    entriesJson: String(body.entries_json ?? "[]"),
    digest: String(body.digest ?? ""),
  }
}

// ── DON mode: verify, encode, sign, write ─────────────────────────────────
const onCronTrigger = (runtime: Runtime<Config>): string => {
  const evm = runtime.config.evms[0]
  const network = getNetwork({ chainFamily: "evm", chainSelectorName: evm.chainName, isTestnet: true })
  if (!network) throw new Error(`Unknown chain: ${evm.chainName}`)

  const http = new cre.capabilities.HTTPClient()
  const feed = http
    .sendRequest(
      runtime,
      fetchFeed,
      ConsensusAggregationByFields<Feed>({
        blocked: median,
        intercepted: median,
        passed: median,
        entriesJson: identical,
        digest: identical,
      }),
    )(runtime.config)
    .result()

  // Integrity: the list the nodes agreed on must hash to the digest GuardianAI published.
  const computed = keccak256(stringToHex(feed.entriesJson))
  if (computed.toLowerCase() !== feed.digest.toLowerCase()) {
    throw new Error(`Feed digest mismatch: computed ${computed}, feed says ${feed.digest}`)
  }

  const entries = JSON.parse(feed.entriesJson) as Entry[]
  if (entries.length > MAX_ENTRIES) throw new Error(`Feed has ${entries.length} entries, max ${MAX_ENTRIES}`)
  const addrs = entries.map((e) => getAddress(e.address) as Address)
  const flags = entries.map((e) => Boolean(e.flagged))

  // DON time, identical on every node; GuardianThreatOracle rejects anything not newer than the last report.
  const asOf = BigInt(Math.floor(runtime.now().getTime() / 1000))

  runtime.log(
    `Consensus reached — blocked=${feed.blocked} intercepted=${feed.intercepted} passed=${feed.passed}, ` +
      `${addrs.length} addresses (${flags.filter(Boolean).length} flagged), digest ${feed.digest}`,
  )

  const payload = encodeAbiParameters(
    parseAbiParameters("uint64, uint256, uint256, uint256, bytes32, address[], bool[]"),
    [asOf, feed.blocked, feed.intercepted, feed.passed, feed.digest as Hex, addrs, flags],
  )

  const report = runtime
    .report({
      encodedPayload: hexToBase64(payload),
      encoderName: "evm",
      signingAlgo: "ecdsa",
      hashingAlgo: "keccak256",
    })
    .result()

  const evmClient = new cre.capabilities.EVMClient(network.chainSelector.selector)
  const write = evmClient
    .writeReport(runtime, {
      receiver: evm.oracleAddress,
      report,
      gasConfig: { gasLimit: evm.gasLimit },
    })
    .result()

  const txHash = bytesToHex(write.txHash || new Uint8Array(32))
  runtime.log(`Report delivered to GuardianThreatOracle ${evm.oracleAddress} on ${evm.chainName} — tx ${txHash}`)
  return txHash
}

const initWorkflow = (config: Config) => {
  const cron = new cre.capabilities.CronCapability()
  return [cre.handler(cron.trigger({ schedule: config.schedule }), onCronTrigger)]
}

export async function main() {
  const runner = await Runner.newRunner<Config>()
  await runner.run(initWorkflow)
}

main()
