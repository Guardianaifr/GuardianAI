import { describe, it, expect } from 'vitest'
import { AbiCoder, Interface, ZeroAddress, getAddress, id } from 'ethers'
import {
  agentLabel, agentIdOf, loadAgentKey, saveAgentKey, newAgentKey, explainTxError, readGuardedWallet, factoryIface, guardedWalletIface,
} from '../explorer/guardedWallet.js'
import { CONTRACTS } from '../explorer/chain.js'

const OWNER = '0x1D4549B95dccAC8203393543187b25B3137D0bf6'
const WALLET = '0x00000000000000000000000000000000000000aa'
const OPERATOR = '0x00000000000000000000000000000000000000bb'
const SIGNER = '0x9bA531633087fE75D5992723003Be0A40eA02209'

function memoryStorage() {
  const m = new Map()
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) }
}

describe('agent identity', () => {
  it('is the same for checksummed and lowercase owner addresses', () => {
    expect(agentLabel(OWNER)).toBe(`console:${OWNER.toLowerCase()}`)
    expect(agentIdOf(OWNER.toLowerCase())).toBe(agentIdOf(OWNER))
  })
  it('hashes the label the way the relay does (keccak256 of the UTF-8 string)', () => {
    expect(agentIdOf(OWNER)).toBe(id(`console:${OWNER.toLowerCase()}`))
  })
})

describe('agent key storage', () => {
  it('round-trips a key per owner', () => {
    const s = memoryStorage()
    const k = newAgentKey()
    expect(saveAgentKey(OWNER, k, s)).toBe(true)
    expect(loadAgentKey(OWNER.toLowerCase(), s).address).toBe(k.address)
  })
  it('returns null when storage is missing or throws', () => {
    expect(loadAgentKey(OWNER, memoryStorage())).toBeNull()
    const broken = { getItem: () => { throw new Error('blocked') }, setItem: () => { throw new Error('blocked') } }
    expect(loadAgentKey(OWNER, broken)).toBeNull()
    expect(saveAgentKey(OWNER, newAgentKey(), broken)).toBe(false)
  })
})

describe('explainTxError', () => {
  it('reports a cancelled request', () => {
    expect(explainTxError({ code: 'ACTION_REJECTED' })).toMatch(/cancelled/)
    expect(explainTxError({ info: { error: { code: 4001 } } })).toMatch(/cancelled/)
  })
  it('decodes contract errors nested the way wallets return them', () => {
    const notOwner = guardedWalletIface.encodeErrorResult('OwnableUnauthorizedAccount', [OPERATOR])
    expect(explainTxError({ info: { error: { data: notOwner } } })).toMatch(/Only the wallet’s owner/)
    const exists = factoryIface.encodeErrorResult('WalletExists', [WALLET])
    expect(explainTxError({ error: { data: { data: exists } } })).toMatch(/already have a guarded wallet/)
    const paused = guardedWalletIface.encodeErrorResult('EnforcedPause', [])
    expect(explainTxError({ data: paused })).toMatch(/frozen/)
  })
  it('falls back to the message for unknown errors', () => {
    expect(explainTxError({ shortMessage: 'nope' })).toBe('nope')
    expect(explainTxError(new Error('insufficient funds for gas * price + value'))).toMatch(/Not enough MON/)
  })
})

describe('readGuardedWallet', () => {
  const coder = AbiCoder.defaultAbiCoder()
  const passport = new Interface(['function isPassportActive(bytes32) view returns (bool)'])
  function fakeProvider(walletAddr, overrides = {}) {
    const answers = {
      [`${CONTRACTS.walletFactory.address}:walletOf`]: coder.encode(['address'], [walletAddr]),
      [`${CONTRACTS.walletFactory.address}:guardianSigner`]: coder.encode(['address'], [SIGNER]),
      [`${getAddress(WALLET)}:owner`]: coder.encode(['address'], [OWNER]),
      [`${getAddress(WALLET)}:operator`]: coder.encode(['address'], [OPERATOR]),
      [`${getAddress(WALLET)}:guardianSigner`]: coder.encode(['address'], [SIGNER]),
      [`${getAddress(WALLET)}:passportRegistry`]: coder.encode(['address'], [CONTRACTS.passport.address]),
      [`${getAddress(WALLET)}:threatOracle`]: coder.encode(['address'], [overrides.oracle ?? ZeroAddress]),
      [`${getAddress(WALLET)}:maxAllowedRiskScore`]: coder.encode(['uint8'], [25]),
      [`${getAddress(WALLET)}:paused`]: coder.encode(['bool'], [overrides.paused ?? false]),
      [`${CONTRACTS.passport.address}:isPassportActive`]: coder.encode(['bool'], [false]),
    }
    const name = (to, data) => {
      for (const iface of [factoryIface, guardedWalletIface, passport]) {
        try { return iface.parseTransaction({ data }).name } catch { /* next */ }
      }
      return '?'
    }
    return {
      provider: null,
      call: async (tx) => {
        const key = `${getAddress(tx.to)}:${name(tx.to, tx.data)}`
        if (!(key in answers)) throw new Error(`unexpected call ${key}`)
        return answers[key]
      },
      getBalance: async () => 5n * 10n ** 16n,
    }
  }

  it('returns no wallet when the factory has none for this owner', async () => {
    const r = await readGuardedWallet(OWNER, fakeProvider(ZeroAddress))
    expect(r.wallet).toBeNull()
    expect(r.agentId).toBe(agentIdOf(OWNER))
  })

  it('reads the wallet state and flags scam protection off', async () => {
    const r = await readGuardedWallet(OWNER, fakeProvider(WALLET))
    expect(r).toMatchObject({
      wallet: getAddress(WALLET), operator: getAddress(OPERATOR), paused: false, maxRisk: 25,
      scamProtection: false, approvalsByGuardian: true, idCardRequired: true, hasPassport: false, balance: 5n * 10n ** 16n,
    })
  })

  it('recognises GuardianAI’s threat oracle and a frozen wallet', async () => {
    const r = await readGuardedWallet(OWNER, fakeProvider(WALLET, { oracle: CONTRACTS.threatOracle.address, paused: true }))
    expect(r.scamProtection).toBe(true)
    expect(r.usesGuardianOracle).toBe(true)
    expect(r.paused).toBe(true)
  })
})

/* ---------------- step 4 ---------------- */
import {
  requestApproval, runScenario, forgedExecuteData, issuerIface, RELAY_URL, PAY_BACK_WEI, INJECTION_PROMPT,
} from '../explorer/guardedWallet.js'
import { Wallet, Interface as Iface, verifyTypedData, keccak256 as k256 } from 'ethers'
import { CRE_FLAGGED_ADDRESS } from '../explorer/chain.js'

const BIG_NONCE = '298572376488742497377271420186234103387'
const execIface = new Iface(['function execute(address,uint256,bytes,(bytes32,address,bytes32,uint256,uint8,uint256,uint256),bytes)'])

function relayReply({ status = 'approved', risk = 0, reasons = [], target = OWNER } = {}) {
  // Build calldata containing the big nonce, and a JSON body with the nonce as a raw number (like the relay does).
  const wrapped = execIface.encodeFunctionData('execute', [target, PAY_BACK_WEI, '0x', [agentIdOf(OWNER), target, k256('0x'), PAY_BACK_WEI, risk, BigInt(BIG_NONCE), 1999999999n], '0x' + '11'.repeat(65)])
  const att = status === 'approved' ? `{"agentId":"${agentIdOf(OWNER)}","nonce":${BIG_NONCE}}` : 'null'
  return `{"status":"${status}","risk_score":${risk},"reasons":${JSON.stringify(reasons)},"attestation":${att},"wrapped_calldata":${status === 'approved' ? `"${wrapped}"` : 'null'}}`
}

function fakeFetch(handler) {
  const calls = []
  const f = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) })
    const { status = 200, text } = handler(JSON.parse(opts.body))
    return { status, ok: status < 400, text: async () => text }
  }
  f.calls = calls
  return f
}

function fakeChain({ callRevert = null, balance = 10n ** 17n } = {}) {
  return {
    call: async () => { if (callRevert) { const e = new Error('execution reverted'); e.data = callRevert; throw e } return '0x' },
    getBalance: async () => balance,
    estimateGas: async () => { throw new Error('estimateGas should not be reached in these tests') },
  }
}

describe('requestApproval', () => {
  it('sends the console agent id, wallet and value as a string', async () => {
    const f = fakeFetch(() => ({ text: relayReply() }))
    await requestApproval({ owner: OWNER, wallet: WALLET, target: OWNER, valueWei: PAY_BACK_WEI, prompt: 'hi' }, f)
    expect(f.calls[0].url).toBe(`${RELAY_URL}/api/v1/attest`)
    expect(f.calls[0].body).toEqual({ agent_id: `console:${OWNER.toLowerCase()}`, target: getAddress(OWNER), value: '1000000000000000', wallet: getAddress(WALLET), data: '0x', prompt: 'hi' })
  })
  it('keeps the exact 128-bit nonce: wrapped_calldata is taken as-is', async () => {
    const r = await requestApproval({ owner: OWNER, wallet: WALLET, target: OWNER, valueWei: PAY_BACK_WEI }, fakeFetch(() => ({ text: relayReply() })))
    const decoded = execIface.decodeFunctionData('execute', r.wrappedCalldata)
    expect(decoded[3][5].toString()).toBe(BIG_NONCE)
    expect(Number(BIG_NONCE).toString()).not.toBe(BIG_NONCE) // what JSON.parse alone would have given
  })
  it('reports a block, a 429 and a broken reply', async () => {
    const blocked = await requestApproval({ owner: OWNER, wallet: WALLET, target: OWNER, valueWei: 1n }, fakeFetch(() => ({ text: relayReply({ status: 'blocked', risk: 100, reasons: ['scam'] }) })))
    expect(blocked).toMatchObject({ status: 'blocked', riskScore: 100, reasons: ['scam'], wrappedCalldata: null })
    const busy = await requestApproval({ owner: OWNER, wallet: WALLET, target: OWNER, valueWei: 1n }, fakeFetch(() => ({ status: 429, text: '{"error":"slow down"}' })))
    expect(busy).toMatchObject({ status: 'busy', reasons: ['slow down'] })
    await expect(requestApproval({ owner: OWNER, wallet: WALLET, target: OWNER, valueWei: 1n }, fakeFetch(() => ({ status: 502, text: '<html>' }))))
      .rejects.toThrow(/HTTP 502/)
  })
})

describe('runScenario', () => {
  const agentKey = new Wallet('0x' + '22'.repeat(32))
  const base = { owner: OWNER, wallet: WALLET, agentKey, scamAddress: '0x535eA8d8eABA5D072f7DfCef98C32d8D1d8E1CBd' }
  const revert = (name, args = []) => guardedWalletIface.encodeErrorResult(name, args)

  it('scam list: relay blocks, nothing reaches the chain', async () => {
    const f = fakeFetch(() => ({ text: relayReply({ status: 'blocked', risk: 100, reasons: ['on GuardianAI’s scam list'] }) }))
    const r = await runScenario('scamList', { ...base, fetchImpl: f, provider: fakeChain({ callRevert: '0xdead' }) })
    expect(r).toMatchObject({ outcome: 'blocked', layer: 'relay', riskScore: 100 })
    expect(f.calls[0].body.target).toBe(getAddress(base.scamAddress))
  })
  it('injection: sends the injected prompt and reports the block', async () => {
    const f = fakeFetch(() => ({ text: relayReply({ status: 'blocked', risk: 50, reasons: ['Prompt injection'] }) }))
    const r = await runScenario('injection', { ...base, fetchImpl: f, provider: fakeChain() })
    expect(f.calls[0].body.prompt).toBe(INJECTION_PROMPT)
    expect(r).toMatchObject({ outcome: 'blocked', layer: 'relay', riskScore: 50 })
  })
  it('chainlink: relay approves, chain refuses with FlaggedDestination when protection is on', async () => {
    const f = fakeFetch(() => ({ text: relayReply({ target: CRE_FLAGGED_ADDRESS }) }))
    const r = await runScenario('chainlink', { ...base, fetchImpl: f, provider: fakeChain({ callRevert: revert('FlaggedDestination', [CRE_FLAGGED_ADDRESS]) }) })
    expect(r).toMatchObject({ outcome: 'refused', layer: 'chain', revert: 'FlaggedDestination' })
  })
  it('chainlink: with protection off it says so and sends nothing', async () => {
    const f = fakeFetch(() => ({ text: relayReply({ target: CRE_FLAGGED_ADDRESS }) }))
    const r = await runScenario('chainlink', { ...base, fetchImpl: f, provider: fakeChain() })
    expect(r.outcome).toBe('would-pass')
    expect(r.message).toMatch(/Turn on scam protection/)
  })
  it('forged: chain refuses the self-signed approval', async () => {
    const r = await runScenario('forged', { ...base, provider: fakeChain({ callRevert: revert('InvalidAttestationSignature') }) })
    expect(r).toMatchObject({ outcome: 'refused', layer: 'chain', revert: 'InvalidAttestationSignature' })
  })
  it('pay back: a frozen wallet is caught in the dry run, nothing is sent', async () => {
    const f = fakeFetch(() => ({ text: relayReply() }))
    const r = await runScenario('payBack', { ...base, fetchImpl: f, provider: fakeChain({ callRevert: revert('EnforcedPause') }) })
    expect(r).toMatchObject({ outcome: 'refused', layer: 'chain', revert: 'EnforcedPause' })
    expect(r.message).toMatch(/frozen/)
  })
  it('pay back: no gas means no send and a clear message', async () => {
    const f = fakeFetch(() => ({ text: relayReply() }))
    const r = await runScenario('payBack', { ...base, fetchImpl: f, provider: fakeChain({ balance: 0n }) })
    expect(r.outcome).toBe('error')
    expect(r.message).toMatch(/Give your agent gas/)
  })
  it('relay unreachable is reported, not thrown', async () => {
    const r = await runScenario('injection', { ...base, provider: fakeChain(), fetchImpl: async () => { throw new TypeError('Failed to fetch') } })
    expect(r).toMatchObject({ outcome: 'error', message: 'Couldn’t reach GuardianAI’s relay.' })
  })
})

describe('forgedExecuteData', () => {
  it('is signed by the agent key, not GuardianAI, over the wallet’s domain', async () => {
    const agentKey = new Wallet('0x' + '33'.repeat(32))
    const data = await forgedExecuteData(agentKey, OWNER, WALLET, OWNER, PAY_BACK_WEI)
    const [target, value, , att, sig] = guardedWalletIface.decodeFunctionData('execute', data)
    expect(target).toBe(getAddress(OWNER))
    expect(value).toBe(PAY_BACK_WEI)
    const types = { SafetyAttestation: [
      { name: 'agentId', type: 'bytes32' }, { name: 'targetContract', type: 'address' }, { name: 'calldataHash', type: 'bytes32' },
      { name: 'value', type: 'uint256' }, { name: 'riskScore', type: 'uint8' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }] }
    const msg = { agentId: att[0], targetContract: att[1], calldataHash: att[2], value: att[3], riskScore: att[4], nonce: att[5], deadline: att[6] }
    const signer = verifyTypedData({ name: 'GuardianAgentWallet', version: '1', chainId: 10143, verifyingContract: getAddress(WALLET) }, types, msg, sig)
    expect(signer).toBe(agentKey.address)
  })
})

describe('issuer errors', () => {
  it('are explained', () => {
    expect(explainTxError({ data: issuerIface.encodeErrorResult('AlreadyClaimed', [5n]) })).toMatch(/already claimed/)
    expect(explainTxError({ data: issuerIface.encodeErrorResult('NoGuardedWallet', [OWNER, agentIdOf(OWNER)]) })).toMatch(/Create your guarded wallet/)
  })
})
