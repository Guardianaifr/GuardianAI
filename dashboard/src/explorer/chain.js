/**
 * chain.js
 *
 * Read-only calls to GuardianAI's deployed contracts on Monad testnet.
 * No wallet, no signing, no gas: everything uses eth_call / eth_blockNumber.
 *
 * Addresses: contracts/deployments/monad_testnet_10143/deployment-summary.json
 */
import { Interface, id, getAddress, isAddress, keccak256, Wallet, hexlify } from 'ethers'

export const RPC_URL = import.meta.env.VITE_MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz'
export const EXPLORER = 'https://testnet.monadscan.com'

export const CONTRACTS = {
  policyGuard: { name: 'GuardianPolicyGuard', label: 'Payment guard', address: '0x90Fdc8E1e5C951701eCd84677038B38560CdEF60' },
  passport: { name: 'GuardianPassportSBT', label: 'Agent ID cards', address: '0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff' },
  threatFeed: { name: 'GuardianThreatFeedRegistry', label: 'Scam address list', address: '0x576CC248D8c406ac302b74e7BFd571E9F989f467' },
}

export const addressUrl = (a) => `${EXPLORER}/address/${a}`
export const txUrl = (h) => `${EXPLORER}/tx/${h}`

// An approved agent action that passed every PolicyGuard check (calls a test contract's doSomething(42), no funds moved): status Success, sent to GuardianPolicyGuard,
// selector 0x3cb7461c = executeWithAttestation(address,bytes,(bytes32,address,bytes32,uint256,uint8,uint256,uint256),bytes).
export const APPROVED_PAYMENT_TX = { hash: '0xda14b65c639fe6fe7b160bb8610524c429b1bdb9b73f208ba9ae1e6d67481c87', block: 66451553 }
// x402 pay-per-approval: an agent paid $0.01 USDC for one approved attestation (tools/x402_e2e.py)
// A real payment: the GuardianAI agent's Privy wallet paid 1 USDC to a vendor through PolicyGuard (transferFrom),
// after GuardianAI approved it; Privy's policy only lets this wallet sign calls to PolicyGuard (tools/privy-agent).
export const REAL_PAYMENT_TX = { hash: '0x96ffc13e35866c43ffdc37300319037f4fc5f8eeb090f55754b79a798eadf22a', block: 67838692 }
export const PRIVY_AGENT_WALLET = '0x27FFBa14315383f61B4F9F9244a95fEdEA459923'
export const X402_FEE_TX = { hash: '0xe2e0238a8a431325a6ff9b480e939275e28c173053aa759c5eea77004681173b', block: 67838677 } // paid from the agent's Privy wallet

// The deployer / attestation signer. Passports owned by any other wallet are external integrations.
export const TEAM_WALLET = '0x1D4549B95dccAC8203393543187b25B3137D0bf6'

const policyGuardIface = new Interface([
  'function executeWithAttestation(address target, bytes data, (bytes32 agentId, address targetContract, bytes32 calldataHash, uint256 value, uint8 riskScore, uint256 nonce, uint256 deadline) attestation, bytes signature) payable returns (bytes)',
  'function maxAllowedRiskScore() view returns (uint8)',
  'function paused() view returns (bool)',
  'error InvalidTargetAddress()',
  'error SelfCallProhibited()',
  'error PassportRevokedOrInactive(bytes32 agentId)',
  'error ValueMismatch(uint256 expected, uint256 actual)',
  'error AttestationExpired(uint256 deadline, uint256 currentTimestamp)',
  'error RiskScoreExceedsThreshold(uint8 riskScore, uint8 maxAllowed)',
  'error NonceAlreadyUsed(bytes32 agentId, uint256 nonce)',
  'error TargetMismatch(address expectedTarget, address actualTarget)',
  'error CalldataHashMismatch()',
  'error InvalidAttestationSignature()',
  'error EnforcedPause()',
  'error ECDSAInvalidSignature()',
  'error ECDSAInvalidSignatureLength(uint256 length)',
  'error ECDSAInvalidSignatureS(bytes32 s)',
])

const passportIface = new Interface([
  'function activePassportCount() view returns (uint256)',
  'function passports(uint256) view returns (bytes32 agentHash, uint8 tier, uint256 trustScore, uint256 issuedAt, uint256 updatedAt, bool revoked, string metadataURI)',
])

const threatIface = new Interface([
  'function evmAddressCount() view returns (uint256)',
  'function evmAddresses(uint256) view returns (address)',
  'function isMalicious(address) view returns (bool, string)',
])

let rpcId = 0

async function rpc(method, params, timeoutMs = 12000) {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
      signal: ctrl.signal,
    })
    if (!res.ok) throw new Error(`Network responded with HTTP ${res.status}`)
    return await res.json()
  } catch (err) {
    if (err?.name === 'AbortError') throw new Error('The Monad testnet took too long to answer.')
    throw err
  } finally {
    clearTimeout(timer)
  }
}

async function ethCall(to, data, value) {
  const tx = { to, data }
  if (value) tx.value = value
  return rpc('eth_call', [tx, 'latest'])
}

async function read(iface, to, fn, args = []) {
  const res = await ethCall(to, iface.encodeFunctionData(fn, args))
  if (res.error) throw new Error(res.error.message || 'Contract read failed')
  return iface.decodeFunctionResult(fn, res.result)[0]
}

export async function getBlockNumber() {
  const res = await rpc('eth_blockNumber', [])
  if (res.error) throw new Error(res.error.message)
  return Number(BigInt(res.result))
}

/** Live numbers shown in the "Live from the blockchain" section. */
export async function readLiveStats() {
  const [block, passports, scamCount, maxRisk, paused] = await Promise.all([
    getBlockNumber(),
    read(passportIface, CONTRACTS.passport.address, 'activePassportCount'),
    read(threatIface, CONTRACTS.threatFeed.address, 'evmAddressCount'),
    read(policyGuardIface, CONTRACTS.policyGuard.address, 'maxAllowedRiskScore'),
    read(policyGuardIface, CONTRACTS.policyGuard.address, 'paused'),
  ])
  return {
    block,
    activePassports: Number(passports),
    scamAddresses: Number(scamCount),
    maxRisk: Number(maxRisk),
    paused: Boolean(paused),
    readAt: new Date(),
  }
}

export async function getFirstScamAddress() {
  const count = await read(threatIface, CONTRACTS.threatFeed.address, 'evmAddressCount')
  if (Number(count) === 0) return null
  return getAddress(await read(threatIface, CONTRACTS.threatFeed.address, 'evmAddresses', [0]))
}

export async function checkAddress(input) {
  const raw = String(input || '').trim()
  if (!isAddress(raw)) throw new Error('That doesn’t look like a wallet address. It should start with 0x and have 42 characters.')
  const address = getAddress(raw.toLowerCase())
  const data = threatIface.encodeFunctionData('isMalicious', [address])
  const [block, res] = await Promise.all([getBlockNumber(), ethCall(CONTRACTS.threatFeed.address, data)])
  if (res.error) throw new Error(res.error.message || 'Contract read failed')
  const [malicious, reason] = threatIface.decodeFunctionResult('isMalicious', res.result)
  return {
    address,
    malicious: Boolean(malicious),
    reason: String(reason || ''),
    block,
    proof: {
      contract: CONTRACTS.threatFeed,
      call: `isMalicious(${address})`,
      rawResult: `(${Boolean(malicious)}, "${String(reason || '')}")`,
    },
  }
}

const STRANGER = '0x9999120485f8064FF369dCDe4bA4eC1101f08E00'

const EIP712_DOMAIN = { name: 'GuardianPolicyGuard', version: '1', chainId: 10143, verifyingContract: CONTRACTS.policyGuard.address }
const EIP712_TYPES = {
  SafetyAttestation: [
    { name: 'agentId', type: 'bytes32' },
    { name: 'targetContract', type: 'address' },
    { name: 'calldataHash', type: 'bytes32' },
    { name: 'value', type: 'uint256' },
    { name: 'riskScore', type: 'uint8' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
}

/** First non-revoked passport's agent id, read live (token ids start at 1). */
export async function getActiveAgentId(maxTokenId = 10) {
  for (let i = 1; i <= maxTokenId; i++) {
    const res = await ethCall(CONTRACTS.passport.address, passportIface.encodeFunctionData('passports', [i]))
    if (res.error) continue
    const [agentHash, , trustScore, , , revoked] = passportIface.decodeFunctionResult('passports', res.result)
    if (agentHash !== '0x' + '0'.repeat(64) && !revoked) return { agentId: agentHash, tokenId: i, trustScore: Number(trustScore) }
  }
  return null
}

/**
 * Asks the payment guard contract to approve a payment, without sending it.
 * Returns the contract's real answer (it reverts with a named reason when it refuses).
 */
async function simulatePayment({ agentLabel, agentId, riskScore, valueWei, signWith }) {
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600)
  const attestation = {
    agentId: agentId || id(agentLabel),
    targetContract: STRANGER,
    calldataHash: keccak256('0x'),
    value: valueWei,
    riskScore,
    nonce: BigInt(Date.now()),
    deadline,
  }
  let signature = '0x00'
  let signer = null
  if (signWith) {
    signer = signWith.address
    signature = await signWith.signTypedData(EIP712_DOMAIN, EIP712_TYPES, attestation)
  }
  const data = policyGuardIface.encodeFunctionData('executeWithAttestation', [STRANGER, '0x', attestation, signature])
  const valueHex = valueWei > 0n ? '0x' + valueWei.toString(16) : undefined

  const [block, res] = await Promise.all([
    getBlockNumber(),
    ethCall(CONTRACTS.policyGuard.address, data, valueHex),
  ])

  const revertData = res?.error?.data
  let decoded = null
  if (typeof revertData === 'string' && revertData.startsWith('0x') && revertData.length >= 10) {
    try {
      decoded = policyGuardIface.parseError(revertData)
    } catch {
      decoded = null
    }
  }

  return {
    block,
    refused: Boolean(res?.error),
    errorName: decoded?.name || null,
    errorArgs: decoded ? decoded.args.map((a) => (typeof a === 'bigint' ? a.toString() : String(a))) : [],
    rawRevert: revertData || res?.error?.message || null,
    rpcMessage: res?.error?.message || null,
    proof: {
      contract: CONTRACTS.policyGuard,
      call: `executeWithAttestation(to: ${STRANGER.slice(0, 10)}…, value: ${(Number(valueWei) / 1e18).toString()} MON, riskScore: ${riskScore}, agent: ${agentLabel ? `"${agentLabel}"` : `${attestation.agentId.slice(0, 10)}…`}${signer ? `, signed by ${signer.slice(0, 10)}…` : ''})`,
    },
  }
}

export function simulateRiskyPayment() {
  return simulatePayment({ agentLabel: 'demo-agent', riskScore: 99, valueWei: 10n * 10n ** 18n })
}

/**
 * A registered, low-risk agent tries to pay with an approval it signed itself
 * (a fresh random key standing in for an attacker or a compromised agent).
 */
export async function simulateForgedApproval() {
  const active = await getActiveAgentId()
  if (!active) throw new Error('No active agent passport found on-chain to run this test.')
  const key = new Uint8Array(32)
  globalThis.crypto.getRandomValues(key)
  const attacker = new Wallet(hexlify(key)) // throwaway key standing in for the attacker
  const r = await simulatePayment({ agentId: active.agentId, riskScore: 5, valueWei: 0n, signWith: attacker })
  return { ...r, agentTokenId: active.tokenId, forgedBy: attacker.address }
}

export function simulateUnknownAgent() {
  return simulatePayment({ agentLabel: `unregistered-agent-${Date.now()}`, riskScore: 5, valueWei: 0n })
}

/** Plain-language explanation for each contract refusal reason. */
export function explainRefusal(errorName, args = []) {
  switch (errorName) {
    case 'RiskScoreExceedsThreshold':
      return `GuardianAI rated this payment ${args[0]}/100 risk. The contract only allows payments up to ${args[1]}/100, so it refused.`
    case 'PassportRevokedOrInactive':
      return 'This agent has no active GuardianAI ID card, so the contract refused to let it pay anyone.'
    case 'InvalidAttestationSignature':
    case 'ECDSAInvalidSignature':
    case 'ECDSAInvalidSignatureLength':
    case 'ECDSAInvalidSignatureS':
      return 'The approval wasn’t signed by GuardianAI, so the contract refused it, even though the agent is registered and the risk is low.'
    case 'AttestationExpired':
      return 'The approval had expired, so the contract refused it.'
    case 'ValueMismatch':
      return 'The amount didn’t match what GuardianAI approved, so the contract refused it.'
    case 'EnforcedPause':
      return 'All agent payments are paused right now.'
    default:
      return errorName ? `The contract refused the payment (${errorName}).` : 'The contract refused the payment.'
  }
}


/** Every contract in contracts/deployments/monad_testnet_10143/deployment-summary.json. */
export const ALL_CONTRACTS = [
  { name: 'GuardianPolicyGuard', role: 'Checks GuardianAI’s signed approval before any agent payment runs', address: '0x90Fdc8E1e5C951701eCd84677038B38560CdEF60' },
  { name: 'GuardianPassportSBT', role: 'Agent ID cards that can’t be transferred, and can be revoked', address: '0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff' },
  { name: 'IdentityRegistryTestnet', role: 'ERC-8004 agent identity registry', address: '0xda5dA75777d30d6d7586b97965dD906AD032E3ff' },
  { name: 'GuardianThreatFeedRegistry', role: 'On-chain list of known scam wallets', address: '0x576CC248D8c406ac302b74e7BFd571E9F989f467' },
  { name: 'GuardianRiskAttestation', role: 'Publishes risk scores for smart contracts', address: '0x7e0631bB10ABAE7dd6D8b7A0762e9f9Ab81d6c87' },
  { name: 'GuardianCortexAnchor', role: 'Anchors fingerprints of GuardianAI’s audit logs on-chain', address: '0x78aFC34a9653c762cA9827370A94a02f7412dBfa' },
  { name: 'GuardianInterlockRegistry', role: 'Lets two agents mutually authorize each other', address: '0x03bd6268f886DE88670B66FAC71cBd3CcC35D67d' },
  { name: 'GuardianInsuranceLedger', role: 'Records protection certificates on-chain', address: '0x671F73068BF55a30299719D76db0d3031A64Bb22' },
  { name: 'GuardianTimelock', role: 'Timelock controller for delayed admin changes', address: '0xBBcBd965DB982d4A1aC01CADb1C98d4e86a2b1dc' },
]

/** Asks the chain whether code exists at each address. Returns { [address]: bytecodeBytes }. */
export async function checkDeployed(addresses) {
  const entries = await Promise.all(addresses.map(async (a) => {
    const res = await rpc('eth_getCode', [a, 'latest'])
    if (res.error) throw new Error(res.error.message)
    const hex = res.result || '0x'
    return [a, Math.max(0, (hex.length - 2) / 2)]
  }))
  return Object.fromEntries(entries)
}

/* ------------------------------------------------------------------ */
/* Registry reads for the console                                      */
/* ------------------------------------------------------------------ */

const TIERS = ['Unverified', 'Silver', 'Gold', 'Diamond'] // GuardianPassportSBT.Tier

const erc721Iface = new Interface(['function ownerOf(uint256) view returns (address)'])
const guardIface = new Interface([
  'function attestationSigner() view returns (address)',
  'function passportRegistry() view returns (address)',
])

export async function getBalance(address) {
  const res = await rpc('eth_getBalance', [address, 'latest'])
  if (res.error) throw new Error(res.error.message)
  return BigInt(res.result)
}

export function formatMon(wei, digits = 4) {
  const whole = wei / 10n ** 18n
  const frac = (wei % 10n ** 18n).toString().padStart(18, '0').slice(0, digits).replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}

/** Every agent ID card, by walking token ids from 1 until ownerOf reverts. */
export async function listPassports(max = 50) {
  const out = []
  for (let i = 1; i <= max; i++) {
    const own = await ethCall(CONTRACTS.passport.address, erc721Iface.encodeFunctionData('ownerOf', [i]))
    if (own.error) break
    const owner = getAddress(erc721Iface.decodeFunctionResult('ownerOf', own.result)[0])
    const res = await ethCall(CONTRACTS.passport.address, passportIface.encodeFunctionData('passports', [i]))
    if (res.error) break
    const [agentHash, tier, trustScore, issuedAt, , revoked, metadataURI] = passportIface.decodeFunctionResult('passports', res.result)
    const file = String(metadataURI || '').split('/').pop()?.replace(/\.json$/i, '') || ''
    out.push({
      tokenId: i,
      agentId: agentHash,
      name: file ? file.charAt(0).toUpperCase() + file.slice(1) : `Agent #${i}`,
      tier: TIERS[Number(tier)] || `Tier ${tier}`,
      trustScore: Number(trustScore) / 100,
      issuedAt: new Date(Number(issuedAt) * 1000),
      revoked: Boolean(revoked),
      metadataURI: String(metadataURI || ''),
      owner,
    })
  }
  return out
}

/** Every EVM scam wallet on the list, with the reason it was listed. */
export async function listScamWallets() {
  const count = Number(await read(threatIface, CONTRACTS.threatFeed.address, 'evmAddressCount'))
  const out = []
  for (let i = 0; i < count; i++) {
    const address = getAddress(await read(threatIface, CONTRACTS.threatFeed.address, 'evmAddresses', [i]))
    const res = await ethCall(CONTRACTS.threatFeed.address, threatIface.encodeFunctionData('isMalicious', [address]))
    const [listed, reason] = res.error ? [true, ''] : threatIface.decodeFunctionResult('isMalicious', res.result)
    out.push({ address, listed: Boolean(listed), reason: String(reason || '') })
  }
  return out
}

export async function readGuardSettings() {
  const [maxRisk, paused, signer, registry] = await Promise.all([
    read(policyGuardIface, CONTRACTS.policyGuard.address, 'maxAllowedRiskScore'),
    read(policyGuardIface, CONTRACTS.policyGuard.address, 'paused'),
    read(guardIface, CONTRACTS.policyGuard.address, 'attestationSigner'),
    read(guardIface, CONTRACTS.policyGuard.address, 'passportRegistry'),
  ])
  return { maxRisk: Number(maxRisk), paused: Boolean(paused), signer: getAddress(signer), registry: getAddress(registry) }
}

export const ipfsToHttp = (uri) => (uri.startsWith('ipfs://') ? `https://ipfs.io/ipfs/${uri.slice(7)}` : uri)
