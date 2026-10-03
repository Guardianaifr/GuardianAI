// The Privy policy that locks a GuardianAI agent wallet. Anything not matched by an ALLOW rule is denied
// by Privy's policy engine, inside Privy's secure enclave, before a signature exists.
const { getAddress } = require('viem');

const both = (a) => [a.toLowerCase(), getAddress(a)]; // Privy string compares are case-sensitive

const ERC20_APPROVE_ABI = [{
  type: 'function', name: 'approve', stateMutability: 'nonpayable',
  inputs: [{ name: 'spender', type: 'address' }, { name: 'amount', type: 'uint256' }],
  outputs: [{ name: '', type: 'bool' }],
}];

const TRANSFER_WITH_AUTH_TYPES = {
  types: {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
    ],
  },
  primary_type: 'TransferWithAuthorization',
};

function guardianAgentPolicy({ policyGuard, usdc, payTo, chainId = 10143, maxApproveUnits = '20000000', maxFeeUnits = '50000' }) {
  const chain = String(chainId);
  const txRules = (method) => [
    {
      name: `${method.replace('eth_', '')}: PolicyGuard only, no MON`,
      method, action: 'ALLOW',
      conditions: [
        { field_source: 'ethereum_transaction', field: 'to', operator: 'in', value: both(policyGuard) },
        { field_source: 'ethereum_transaction', field: 'chain_id', operator: 'eq', value: chain },
        { field_source: 'ethereum_transaction', field: 'value', operator: 'lte', value: '0x0' },
      ],
    },
    {
      name: `${method.replace('eth_', '')}: capped USDC approve`,
      method, action: 'ALLOW',
      conditions: [
        { field_source: 'ethereum_transaction', field: 'to', operator: 'in', value: both(usdc) },
        { field_source: 'ethereum_transaction', field: 'chain_id', operator: 'eq', value: chain },
        { field_source: 'ethereum_calldata', field: 'approve.spender', abi: ERC20_APPROVE_ABI, operator: 'in', value: both(policyGuard) },
        { field_source: 'ethereum_calldata', field: 'approve.amount', abi: ERC20_APPROVE_ABI, operator: 'lte', value: maxApproveUnits },
      ],
    },
  ];
  const rules = [...txRules('eth_signTransaction'), ...txRules('eth_sendTransaction')];
  if (payTo) {
    rules.push({
      name: 'x402: small USDC fees to GuardianAI only',
      method: 'eth_signTypedData_v4', action: 'ALLOW',
      conditions: [
        { field_source: 'ethereum_typed_data_domain', field: 'verifyingContract', operator: 'in', value: both(usdc) },
        { field_source: 'ethereum_typed_data_domain', field: 'chainId', operator: 'eq', value: chain },
        { field_source: 'ethereum_typed_data_message', field: 'to', typed_data: TRANSFER_WITH_AUTH_TYPES, operator: 'in', value: both(payTo) },
        { field_source: 'ethereum_typed_data_message', field: 'value', typed_data: TRANSFER_WITH_AUTH_TYPES, operator: 'lte', value: maxFeeUnits },
      ],
    });
  }
  return { version: '1.0', name: 'GuardianAI agent lock', chain_type: 'ethereum', rules };
}

module.exports = { guardianAgentPolicy };
