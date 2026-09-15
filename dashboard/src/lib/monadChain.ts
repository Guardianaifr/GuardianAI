/**
 * Viem chain definition for Monad Testnet.
 *
 * Chain ID : 10143
 * RPC      : https://testnet-rpc.monad.xyz
 * Explorer : https://testnet.monadscan.com
 */

export const monadTestnet = {
  id: 10143,
  name: "Monad Testnet",
  nativeCurrency: {
    name: "Monad",
    symbol: "MON",
    decimals: 18,
  },
  rpcUrls: {
    default: {
      http: ["https://testnet-rpc.monad.xyz"],
    },
    public: {
      http: ["https://testnet-rpc.monad.xyz"],
    },
  },
  blockExplorers: {
    default: {
      name: "MonadScan",
      url: "https://testnet.monadscan.com",
    },
  },
  testnet: true,
} as const;
