/**
 * Decoding tests for explorer/chain.js.
 * The fixture replies below are real responses from https://testnet-rpc.monad.xyz,
 * captured 2026-10-01 by replaying the exact eth_call payloads this module builds.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'
import { Interface, verifyTypedData } from 'ethers'
import {
  simulateRiskyPayment, simulateUnknownAgent, simulateForgedApproval, readLiveStats, checkAddress, explainRefusal, listPassports, formatMon,
} from '../explorer/chain.js'

const REAL = {
  block: '0x4030bf1',
  riskRevert: '0xbf27de8800000000000000000000000000000000000000000000000000000000000000630000000000000000000000000000000000000000000000000000000000000019',
  passportRevert: '0xe81a2b776c06d33a359091cbf791827e1268cbcf90aaf6fa4effaef83c08fb969db1dabf',
  activePassportCount: '0x0000000000000000000000000000000000000000000000000000000000000003',
  evmAddressCount: '0x0000000000000000000000000000000000000000000000000000000000000001',
  maxAllowedRiskScore: '0x0000000000000000000000000000000000000000000000000000000000000019',
  paused: '0x0000000000000000000000000000000000000000000000000000000000000000',
  // passports(1) on GuardianPassportSBT (real reply): agentHash 0x59c9…1944, tier 3, trustScore 9400, not revoked, ipfs://…/eliza.json
  passport1: '0x59c94de45fb130bf65b9dbbf826fd773392686e99ab15cfac83e97ea6c2f1944000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000024b8000000000000000000000000000000000000000000000000000000006aba9084000000000000000000000000000000000000000000000000000000006aba9084000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004d697066733a2f2f62616679626569676479727a74357366703775646d37687537367568377932366e6633656675796c71616266336f636c67747179353566627a64692f656c697a612e6a736f6e00000000000000000000000000000000000000',
  forgedRevert: '0x159c4a13',
  isMaliciousTrue: '0x0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000344d6f6e616420746573746e6574207068697368696e6720647261696e657220666c616767656420627920477561726469616e4149000000000000000000000000',
}

function mockRpc(handler) {
  vi.stubGlobal('fetch', async (_url, opts) => {
    const body = JSON.parse(opts.body)
    const reply = body.method === 'eth_blockNumber' ? { result: REAL.block } : handler(body.params[0])
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: body.id, ...reply }) }
  })
}

afterEach(() => vi.unstubAllGlobals())

describe('chain.js against real Monad replies', () => {
  it('risky payment: decodes RiskScoreExceedsThreshold(99, 25)', async () => {
    mockRpc(() => ({ error: { code: 3, message: 'execution reverted', data: REAL.riskRevert } }))
    const r = await simulateRiskyPayment()
    expect(r.refused).toBe(true)
    expect(r.errorName).toBe('RiskScoreExceedsThreshold')
    expect(r.errorArgs).toEqual(['99', '25'])
    expect(r.block).toBe(67308529)
    expect(explainRefusal(r.errorName, r.errorArgs)).toBe(
      'GuardianAI rated this payment 99/100 risk. The contract only allows payments up to 25/100, so it refused.',
    )
  })

  it('unknown agent: decodes PassportRevokedOrInactive', async () => {
    mockRpc(() => ({ error: { code: 3, message: 'execution reverted', data: REAL.passportRevert } }))
    const r = await simulateUnknownAgent()
    expect(r.refused).toBe(true)
    expect(r.errorName).toBe('PassportRevokedOrInactive')
  })

  it('live stats: decodes counts, risk limit and pause flag', async () => {
    const bySelector = {
      '0xc4c1defc': REAL.activePassportCount,
      '0x1c74ff85': REAL.evmAddressCount,
      '0xd31e46ab': REAL.maxAllowedRiskScore,
      '0x5c975abb': REAL.paused,
    }
    mockRpc((tx) => ({ result: bySelector[tx.data.slice(0, 10)] }))
    const s = await readLiveStats()
    expect({ block: s.block, activePassports: s.activePassports, scamAddresses: s.scamAddresses, maxRisk: s.maxRisk, paused: s.paused })
      .toEqual({ block: 67308529, activePassports: 3, scamAddresses: 1, maxRisk: 25, paused: false })
  })

  it('address check: decodes (bool, reason) from isMalicious', async () => {
    mockRpc(() => ({ result: REAL.isMaliciousTrue }))
    const r = await checkAddress('0x535ea8d8eaba5d072f7dfcef98c32d8d1d8e1cbd')
    expect(r.malicious).toBe(true)
    expect(r.reason).toBe('Monad testnet phishing drainer flagged by GuardianAI')
    expect(r.address.toLowerCase()).toBe('0x535ea8d8eaba5d072f7dfcef98c32d8d1d8e1cbd')
  })

  it('address check: rejects input that is not an address, without calling the network', async () => {
    const spy = vi.fn()
    vi.stubGlobal('fetch', spy)
    await expect(checkAddress('hello')).rejects.toThrow('doesn’t look like a wallet address')
    expect(spy).not.toHaveBeenCalled()
  })

  it('forged approval: signs a real EIP-712 approval with a throwaway key and decodes InvalidAttestationSignature', async () => {
    let sentCall = null
    mockRpc((tx) => {
      if (tx.data.startsWith('0xcb22f5fd')) return { result: REAL.passport1 }
      sentCall = tx
      return { error: { code: 3, message: 'execution reverted', data: REAL.forgedRevert } }
    })
    const r = await simulateForgedApproval()
    expect(r.refused).toBe(true)
    expect(r.errorName).toBe('InvalidAttestationSignature')
    expect(r.agentTokenId).toBe(1)

    // The calldata carries the live agent id and a genuine 65-byte signature from the throwaway key.
    const iface = new Interface(['function executeWithAttestation(address target, bytes data, (bytes32 agentId, address targetContract, bytes32 calldataHash, uint256 value, uint8 riskScore, uint256 nonce, uint256 deadline) attestation, bytes signature)'])
    const [, , att, sig] = iface.decodeFunctionData('executeWithAttestation', sentCall.data)
    expect(att.agentId).toBe('0x59c94de45fb130bf65b9dbbf826fd773392686e99ab15cfac83e97ea6c2f1944')
    expect(Number(att.riskScore)).toBe(5)
    expect((sig.length - 2) / 2).toBe(65)
    const recovered = verifyTypedData(
      { name: 'GuardianPolicyGuard', version: '1', chainId: 10143, verifyingContract: '0x90Fdc8E1e5C951701eCd84677038B38560CdEF60' },
      { SafetyAttestation: [
        { name: 'agentId', type: 'bytes32' }, { name: 'targetContract', type: 'address' }, { name: 'calldataHash', type: 'bytes32' },
        { name: 'value', type: 'uint256' }, { name: 'riskScore', type: 'uint8' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
      ] },
      { agentId: att.agentId, targetContract: att.targetContract, calldataHash: att.calldataHash, value: att.value, riskScore: att.riskScore, nonce: att.nonce, deadline: att.deadline },
      sig,
    )
    expect(recovered).toBe(r.forgedBy)
    expect(explainRefusal(r.errorName, r.errorArgs)).toContain('wasn’t signed by GuardianAI')
  })

  it('listPassports: walks token ids until ownerOf reverts and decodes each card (real replies)', async () => {
    const owner = '0x0000000000000000000000001d4549b95dccac8203393543187b25b3137d0bf6'
    mockRpc((tx) => {
      const id = parseInt(tx.data.slice(10), 16)
      if (tx.data.startsWith('0x6352211e')) return id <= 1 ? { result: owner } : { error: { code: 3, message: 'execution reverted' } }
      if (tx.data.startsWith('0xcb22f5fd')) return { result: REAL.passport1 }
      return { error: { code: -1, message: 'unexpected call' } }
    })
    const list = await listPassports()
    expect(list).toHaveLength(1)
    expect(list[0]).toMatchObject({ tokenId: 1, name: 'Eliza', tier: 'Diamond', trustScore: 94, revoked: false })
    expect(list[0].owner.toLowerCase()).toBe('0x1d4549b95dccac8203393543187b25b3137d0bf6')
  })

  it('formatMon: shows whole and fractional MON without float rounding', () => {
    expect(formatMon(0n)).toBe('0')
    expect(formatMon(10n ** 18n)).toBe('1')
    expect(formatMon(1234567890000000000n)).toBe('1.2345')
    expect(formatMon(500000000000000n)).toBe('0.0005')
  })
})
