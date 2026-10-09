#!/usr/bin/env node
/**
 * GuardianAI agent on a Privy server wallet (Monad testnet).
 *
 * Two locks, owned by different parties:
 *   1. Privy policy (policy.cjs): the wallet can only sign calls to GuardianPolicyGuard, a capped USDC
 *      approval to PolicyGuard, and small x402 fee payments. Everything else is refused by Privy.
 *   2. GuardianAI: PolicyGuard only executes with a fresh approval signed by the GuardianAI relay
 *      (scam list, per-agent caps, prompt checks), verified on-chain.
 *
 * Commands:
 *   node agent.cjs setup                 create the policy + wallet (ids saved to .state.json)
 *   node agent.cjs status                balances, allowance, ID card status
 *   node agent.cjs lock-test             try to make the wallet sign forbidden things; Privy must refuse
 *   node agent.cjs approve [usdc]        let PolicyGuard pull up to N USDC (default 20)
 *   node agent.cjs pay <to> <usdc> [prompt]   pay through GuardianAI (x402 fee from the Privy wallet)
 *   node agent.cjs update-policy         push policy.cjs (adds the GuardianAgentWallet + pull authorization)
 *
 * GuardianAgentWallet (funds live in a contract; every call needs this key AND a GuardianAI approval):
 *   node agent.cjs wallet-status
 *   node agent.cjs wallet-pay <to> <mon> [prompt]       approved by GuardianAI, executed by the wallet
 *   node agent.cjs wallet-pay-usdc <to> <usdc> [prompt]
 *   node agent.cjs wallet-fund <usdc>                    move USDC from this key into the wallet (via PolicyGuard)
 *   node agent.cjs wallet-bypass [to] [mon]              skip GuardianAI: send execute() with a forged approval;
 *                                                        the chain must revert it (InvalidAttestationSignature)
 *
 * Env (.env at repo root, or dashboard/.env): PRIVY_APP_ID or VITE_PRIVY_APP_ID, PRIVY_APP_SECRET,
 * GUARDIAN_X402_PAY_TO, MONAD_TESTNET_RPC (optional), GUARDIAN_RELAY_URL (default http://127.0.0.1:8546)
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || !t.includes('=')) continue;
    const i = t.indexOf('=');
    const k = t.slice(0, i).trim();
    const v = t.slice(i + 1).trim().replace(/^['"]|['"]$/g, '');
    if (!(k in process.env)) process.env[k] = v;
  }
}
loadEnv(path.join(ROOT, '.env'));
loadEnv(path.join(ROOT, 'dashboard', '.env'));

const { PrivyClient } = require('@privy-io/node');
const {
  createPublicClient, http, getAddress, encodeFunctionData, parseAbi, keccak256, toBytes, formatEther, formatUnits, parseEther, decodeErrorResult,
} = require('viem');
const { guardianAgentPolicy } = require('./policy.cjs');

const CHAIN_ID = 10143;
const POLICY_GUARD = '0x90Fdc8E1e5C951701eCd84677038B38560CdEF60';
const PASSPORT = '0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff';
const USDC = '0x534b2f3A21130d7a60830c2Df862319e593943A3';
const RPC = process.env.MONAD_TESTNET_RPC || 'https://testnet-rpc.monad.xyz';
const RELAY = (process.env.GUARDIAN_RELAY_URL || 'http://127.0.0.1:8546').replace(/\/$/, '');
const STATE = path.join(__dirname, '.state.json');
const SCAN = 'https://testnet.monadscan.com';
const STRANGER = getAddress('0x7a3b9c1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b');
const DEPLOYMENTS = path.join(ROOT, 'metropolis', 'deployments-monad.json');
// Optional passkey agent card from the operator console (website/mera/). Signed statement, not a secret.
const AGENT_CARD = process.env.GUARDIAN_AGENT_CARD || path.join(__dirname, '.agent-card.json');
function agentCard() {
  if (!fs.existsSync(AGENT_CARD)) return undefined;
  return JSON.parse(fs.readFileSync(AGENT_CARD, 'utf8'));
}
const WALLET_ABI = parseAbi([
  'function execute(address target,uint256 value,bytes data,(bytes32 agentId,address targetContract,bytes32 calldataHash,uint256 value,uint8 riskScore,uint256 nonce,uint256 deadline) attestation,bytes signature) returns (bytes)',
  'function operator() view returns (address)',
  'function guardianSigner() view returns (address)',
  'function threatOracle() view returns (address)',
  'function paused() view returns (bool)',
  'error InvalidAttestationSignature()',
  'error NotOperator(address caller)',
  'error FlaggedDestination(address account)',
  'error CalldataHashMismatch()',
  'error AgentMismatch(bytes32 expected, bytes32 actual)',
]);

const monad = { id: CHAIN_ID, name: 'Monad Testnet', nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 }, rpcUrls: { default: { http: [RPC] } } };
const pub = createPublicClient({ chain: monad, transport: http(RPC) });
const erc20 = parseAbi([
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address,address) view returns (uint256)',
  'function transfer(address,uint256) returns (bool)',
  'function transferFrom(address,address,uint256) returns (bool)',
  'function approve(address,uint256) returns (bool)',
]);

function privy() {
  const appId = process.env.PRIVY_APP_ID || process.env.VITE_PRIVY_APP_ID;
  const appSecret = process.env.PRIVY_APP_SECRET;
  if (!appId || !appSecret) {
    console.error('Missing Privy credentials: set PRIVY_APP_SECRET (and PRIVY_APP_ID or VITE_PRIVY_APP_ID) in .env');
    process.exit(2);
  }
  return new PrivyClient({ appId, appSecret });
}
const readState = () => (fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, 'utf8')) : {});
const writeState = (s) => fs.writeFileSync(STATE, JSON.stringify(s, null, 2));
function wallet() {
  const s = readState();
  if (!s.walletId) { console.error('No agent wallet yet: run `node agent.cjs setup` first'); process.exit(2); }
  return s;
}
const agentIdFor = (address) => `privy-agent:${address.toLowerCase()}`;

function agentWalletFor(address) {
  const dep = fs.existsSync(DEPLOYMENTS) ? JSON.parse(fs.readFileSync(DEPLOYMENTS, 'utf8')) : {};
  const w = (dep.agentWallets || {})[agentIdFor(address)];
  return w ? getAddress(w.wallet) : null;
}

async function signAndSend(client, s, tx) {
  const [nonce, fees, gas] = await Promise.all([
    pub.getTransactionCount({ address: s.address, blockTag: 'pending' }),
    pub.estimateFeesPerGas(),
    // tx.gas lets a demo send a transaction the chain will revert (estimateGas would refuse it first).
    tx.gas ? Promise.resolve((BigInt(tx.gas) * 10n) / 12n) : pub.estimateGas({ account: s.address, to: tx.to, data: tx.data, value: 0n }),
  ]);
  const unsigned = {
    to: tx.to, data: tx.data, value: '0x0', chain_id: CHAIN_ID, type: 2,
    nonce: `0x${nonce.toString(16)}`, gas_limit: `0x${((gas * 12n) / 10n).toString(16)}`,
    max_fee_per_gas: `0x${fees.maxFeePerGas.toString(16)}`,
    max_priority_fee_per_gas: `0x${fees.maxPriorityFeePerGas.toString(16)}`,
  };
  const signed = await client.wallets().ethereum().signTransaction(s.walletId, { params: { transaction: unsigned } });
  const hash = await pub.sendRawTransaction({ serializedTransaction: signed.signed_transaction });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  return { hash, receipt };
}

async function trySign(client, s, label, transaction) {
  try {
    await client.wallets().ethereum().signTransaction(s.walletId, { params: { transaction: { chain_id: CHAIN_ID, ...transaction } } });
    console.log(`FAIL   Privy SIGNED: ${label}`);
    return false;
  } catch (e) {
    const msg = String(e?.error?.error || e?.message || e).replace(/\s+/g, ' ').slice(0, 140);
    console.log(`PASS   Privy refused: ${label}  [${e?.status || ''} ${msg}]`);
    return true;
  }
}

const commands = {
  async setup() {
    const client = privy();
    const s = readState();
    const payTo = process.env.GUARDIAN_X402_PAY_TO;
    if (!s.policyId) {
      const p = await client.policies().create(guardianAgentPolicy({ policyGuard: POLICY_GUARD, usdc: USDC, payTo }));
      s.policyId = p.id;
      writeState(s);
      console.log('policy created:', p.id);
    }
    if (!s.walletId) {
      const w = await client.wallets().create({ chain_type: 'ethereum', policy_ids: [s.policyId] });
      Object.assign(s, { walletId: w.id, address: getAddress(w.address) });
      writeState(s);
      console.log('wallet created:', w.id);
    }
    const agentId = agentIdFor(s.address);
    console.log(JSON.stringify({ address: s.address, walletId: s.walletId, policyId: s.policyId, agentId, agentHash: keccak256(toBytes(agentId)) }, null, 2));
    console.log(`\nNext: send this wallet ~0.2 testnet MON (gas) and some testnet USDC, and give it a GuardianAI ID card:\n  python tools/mint_agent_passport.py ${s.address}`);
  },

  async status() {
    const s = wallet();
    const agentHash = keccak256(toBytes(agentIdFor(s.address)));
    const [mon, usdc, allowance, active] = await Promise.all([
      pub.getBalance({ address: s.address }),
      pub.readContract({ address: USDC, abi: erc20, functionName: 'balanceOf', args: [s.address] }),
      pub.readContract({ address: USDC, abi: erc20, functionName: 'allowance', args: [s.address, POLICY_GUARD] }),
      pub.readContract({ address: PASSPORT, abi: parseAbi(['function isPassportActive(bytes32) view returns (bool)']), functionName: 'isPassportActive', args: [agentHash] }),
    ]);
    console.log(JSON.stringify({
      address: s.address, mon: formatEther(mon), usdc: formatUnits(usdc, 6),
      usdcAllowanceToPolicyGuard: formatUnits(allowance, 6), idCardActive: active, agentId: agentIdFor(s.address),
    }, null, 2));
  },

  async 'lock-test'() {
    const client = privy();
    const s = wallet();
    const results = [
      await trySign(client, s, 'send 0.1 MON straight to a stranger', { to: STRANGER, value: '0x16345785d8a0000' }),
      await trySign(client, s, 'USDC transfer straight to a stranger', { to: USDC, data: encodeFunctionData({ abi: erc20, functionName: 'transfer', args: [STRANGER, 1_000_000n] }) }),
      await trySign(client, s, 'USDC approve to a stranger', { to: USDC, data: encodeFunctionData({ abi: erc20, functionName: 'approve', args: [STRANGER, 1_000_000n] }) }),
      await trySign(client, s, 'USDC approve to PolicyGuard above the cap (1000 USDC)', { to: USDC, data: encodeFunctionData({ abi: erc20, functionName: 'approve', args: [POLICY_GUARD, 1_000_000_000n] }) }),
      await trySign(client, s, 'call PolicyGuard while sending 1 MON', { to: POLICY_GUARD, value: '0xde0b6b3a7640000', data: '0x' }),
      await trySign(client, s, 'same call on another chain (Ethereum mainnet)', { to: POLICY_GUARD, chain_id: 1, data: '0x' }),
    ];
    const ok = results.filter(Boolean).length;
    console.log(`\n${ok}/${results.length} forbidden actions refused by Privy`);
    process.exitCode = ok === results.length ? 0 : 1;
  },

  async approve(amount = '20') {
    const client = privy();
    const s = wallet();
    const units = BigInt(Math.round(Number(amount) * 1e6));
    const { hash, receipt } = await signAndSend(client, s, { to: USDC, data: encodeFunctionData({ abi: erc20, functionName: 'approve', args: [POLICY_GUARD, units] }) });
    console.log(`approve ${amount} USDC to PolicyGuard: ${receipt.status} ${SCAN}/tx/${hash}`);
  },

  async pay(to, amount, ...promptWords) {
    if (!to || !amount) { console.error('usage: node agent.cjs pay <recipient> <usdc> [prompt]'); process.exit(2); }
    const client = privy();
    const s = wallet();
    const prompt = promptWords.join(' ') || `Pay ${amount} USDC to ${to}`;
    const inner = encodeFunctionData({ abi: erc20, functionName: 'transferFrom', args: [s.address, getAddress(to), BigInt(Math.round(Number(amount) * 1e6))] });

    // Ask GuardianAI for an approval. If the relay charges with x402, the Privy wallet pays the fee.
    let doFetch = fetch;
    try {
      const { createX402Client } = require('@privy-io/node/x402');
      const { wrapFetchWithPayment } = require('@x402/fetch');
      doFetch = wrapFetchWithPayment(fetch, createX402Client(client, { walletId: s.walletId, address: s.address }));
    } catch (e) {
      console.log(`(x402 client unavailable, calling the relay without payment: ${e.message})`);
    }
    // Prove this pull is ours: the relay refuses transferFrom through the shared PolicyGuard without it.
    const deadline = Math.floor(Date.now() / 1000) + 120;
    const pullAuth = await client.wallets().ethereum().signTypedData(s.walletId, {
      params: {
        typed_data: {
          domain: { name: 'GuardianAI Pull Authorization', version: '1', chainId: CHAIN_ID, verifyingContract: POLICY_GUARD },
          types: {
            PullAuthorization: [
              { name: 'from', type: 'address' }, { name: 'target', type: 'address' }, { name: 'calldataHash', type: 'bytes32' },
              { name: 'value', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
            ],
          },
          primary_type: 'PullAuthorization',
          message: { from: s.address, target: USDC, calldataHash: keccak256(inner), value: 0, deadline },
        },
      },
    });
    const res = await doFetch(`${RELAY}/api/v1/attest`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_id: agentIdFor(s.address), target: USDC, data: inner, value: 0, prompt,
        owner_authorization: { signature: pullAuth.signature, deadline },
      }),
    });
    const fee = res.headers.get('payment-response');
    if (fee) {
      const settle = JSON.parse(Buffer.from(fee, 'base64').toString());
      console.log(`x402 fee paid from the Privy wallet: ${settle.success} ${SCAN}/tx/${settle.transaction}`);
    }
    const body = await res.json().catch(() => ({}));
    console.log(`GuardianAI: HTTP ${res.status} ${body.status || ''} risk=${body.risk_score ?? '-'} ${(body.reasons || []).join('; ')}${body.agent_identity ? ` identity=${body.agent_identity}` : ''}`);
    if (body.status !== 'approved') { console.log('No approval, so nothing is signed or sent.'); process.exitCode = 1; return; }

    const { hash, receipt } = await signAndSend(client, s, { to: POLICY_GUARD, data: body.wrapped_calldata });
    console.log(`PolicyGuard executeWithAttestation: ${receipt.status} block ${receipt.blockNumber} ${SCAN}/tx/${hash}`);
  },

  async 'update-policy'() {
    const client = privy();
    const s = wallet();
    const agentWallet = agentWalletFor(s.address);
    const policy = guardianAgentPolicy({
      policyGuard: POLICY_GUARD, usdc: USDC, payTo: process.env.GUARDIAN_X402_PAY_TO, agentWallets: agentWallet ? [agentWallet] : [],
    });
    const p = await client.policies().update(s.policyId, { name: policy.name, rules: policy.rules });
    console.log(`policy ${p.id} updated: ${p.rules.length} rules`);
    for (const r of p.rules) console.log(`  ${r.action}  ${r.method}  ${r.name}`);
  },

  async 'wallet-status'() {
    const s = wallet();
    const w = agentWalletFor(s.address);
    if (!w) { console.error('No GuardianAgentWallet for this agent in metropolis/deployments-monad.json'); process.exit(2); }
    const read = (functionName) => pub.readContract({ address: w, abi: WALLET_ABI, functionName });
    const [mon, usdc, operator, signer, oracle, paused] = await Promise.all([
      pub.getBalance({ address: w }),
      pub.readContract({ address: USDC, abi: erc20, functionName: 'balanceOf', args: [w] }),
      read('operator'), read('guardianSigner'), read('threatOracle'), read('paused'),
    ]);
    console.log(JSON.stringify({ wallet: w, mon: formatEther(mon), usdc: formatUnits(usdc, 6), operator, guardianSigner: signer, threatOracle: oracle, paused, scan: `${SCAN}/address/${w}` }, null, 2));
  },

  async 'wallet-pay'(to, amount, ...promptWords) {
    if (!to || !amount) { console.error('usage: node agent.cjs wallet-pay <to> <mon> [prompt]'); process.exit(2); }
    return walletAct({ to: getAddress(to), value: parseEther(amount), data: '0x', prompt: promptWords.join(' ') || `Send ${amount} MON to ${to}` });
  },

  async 'wallet-pay-usdc'(to, amount, ...promptWords) {
    if (!to || !amount) { console.error('usage: node agent.cjs wallet-pay-usdc <to> <usdc> [prompt]'); process.exit(2); }
    const data = encodeFunctionData({ abi: erc20, functionName: 'transfer', args: [getAddress(to), BigInt(Math.round(Number(amount) * 1e6))] });
    return walletAct({ to: USDC, value: 0n, data, prompt: promptWords.join(' ') || `Pay ${amount} USDC to ${to}` });
  },

  async 'wallet-fund'(amount = '10') {
    const s = wallet();
    const w = agentWalletFor(s.address);
    if (!w) { console.error('No GuardianAgentWallet for this agent'); process.exit(2); }
    return commands.pay(w, amount, `Move ${amount} USDC into my GuardianAgentWallet`);
  },

  async 'wallet-bypass'(to = STRANGER, amount = '0.05') {
    const client = privy();
    const s = wallet();
    const w = agentWalletFor(s.address);
    if (!w) { console.error('No GuardianAgentWallet for this agent'); process.exit(2); }
    const value = parseEther(amount);
    // The agent skips GuardianAI and approves itself: a well-formed attestation with a signature GuardianAI never made.
    const forged = {
      agentId: keccak256(toBytes(agentIdFor(s.address))), targetContract: getAddress(to), calldataHash: keccak256('0x'),
      value, riskScore: 0, nonce: BigInt(Date.now()), deadline: BigInt(Math.floor(Date.now() / 1000) + 300),
    };
    // Signed with a throwaway key (a perfectly valid ECDSA signature), just not GuardianAI's.
    const { privateKeyToAccount, generatePrivateKey } = require('viem/accounts');
    const selfSigner = privateKeyToAccount(generatePrivateKey());
    const fakeSig = await selfSigner.signTypedData({
      domain: { name: 'GuardianAgentWallet', version: '1', chainId: CHAIN_ID, verifyingContract: w },
      types: {
        SafetyAttestation: [
          { name: 'agentId', type: 'bytes32' }, { name: 'targetContract', type: 'address' }, { name: 'calldataHash', type: 'bytes32' },
          { name: 'value', type: 'uint256' }, { name: 'riskScore', type: 'uint8' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
        ],
      },
      primaryType: 'SafetyAttestation',
      message: forged,
    });
    console.log(`agent self-signs an approval with ${selfSigner.address} (GuardianAI's signer is ${await pub.readContract({ address: w, abi: WALLET_ABI, functionName: 'guardianSigner' })})`);
    const data = encodeFunctionData({ abi: WALLET_ABI, functionName: 'execute', args: [getAddress(to), value, '0x', forged, fakeSig] });
    try {
      await pub.call({ account: s.address, to: w, data });
      console.log('UNEXPECTED: simulation succeeded');
    } catch (e) {
      console.log(`eth_call says: ${revertName(e)}`);
    }
    const { hash, receipt } = await signAndSend(client, s, { to: w, data, gas: 200000 });
    console.log(`bypass tx mined: status=${receipt.status} (expected: reverted) ${SCAN}/tx/${hash}`);
    const bal = await pub.getBalance({ address: w });
    console.log(`wallet still holds ${formatEther(bal)} MON`);
    process.exitCode = receipt.status === 'reverted' ? 0 : 1;
  },
};

function revertName(e) {
  const raw = e?.cause?.data ?? e?.data ?? e?.cause?.cause?.data;
  const hex = typeof raw === 'string' ? raw : raw?.data;
  if (hex && hex.length >= 10) {
    try { return `reverted with ${decodeErrorResult({ abi: WALLET_ABI, data: hex }).errorName}`; } catch {}
    return `reverted with ${hex.slice(0, 10)}`;
  }
  return (e?.shortMessage || e?.message || String(e)).slice(0, 200);
}

async function walletAct({ to, value, data, prompt }) {
  const client = privy();
  const s = wallet();
  const w = agentWalletFor(s.address);
  if (!w) { console.error('No GuardianAgentWallet for this agent'); process.exit(2); }
  const res = await fetch(`${RELAY}/api/v1/attest`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_id: agentIdFor(s.address), wallet: w, target: to, data, value: value.toString(), prompt, agent_card: agentCard() }),
  });
  const body = await res.json().catch(() => ({}));
  console.log(`GuardianAI: HTTP ${res.status} ${body.status || ''} risk=${body.risk_score ?? '-'} ${(body.reasons || []).join('; ')}${body.agent_identity ? ` identity=${body.agent_identity}` : ''}`);
  if (body.status !== 'approved') { console.log('No approval, so nothing is signed or sent.'); process.exitCode = 1; return; }
  try {
    await pub.call({ account: s.address, to: w, data: body.wrapped_calldata });
  } catch (e) {
    console.log(`The chain refuses it before sending: ${revertName(e)}`);
    const { hash, receipt } = await signAndSend(client, s, { to: w, data: body.wrapped_calldata, gas: 250000 });
    console.log(`sent anyway to prove it on-chain: status=${receipt.status} ${SCAN}/tx/${hash}`);
    process.exitCode = 1;
    return;
  }
  const { hash, receipt } = await signAndSend(client, s, { to: w, data: body.wrapped_calldata });
  console.log(`GuardianAgentWallet.execute: ${receipt.status} block ${receipt.blockNumber} ${SCAN}/tx/${hash}`);
}

const [cmd, ...args] = process.argv.slice(2);
if (!commands[cmd]) {
  console.log('usage: node agent.cjs <setup|status|lock-test|approve|pay|update-policy|wallet-status|wallet-pay|wallet-pay-usdc|wallet-fund|wallet-bypass> ...');
  process.exit(cmd ? 2 : 0);
}
commands[cmd](...args).catch((e) => { console.error(e?.status || '', e?.message || e); process.exit(1); });
