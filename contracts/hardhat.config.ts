import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
// import * as tenderly from "@tenderly/hardhat-tenderly";

dotenv.config({ path: "../.env" });
// tenderly.setup({ automaticVerifications: false });

const DEPLOYER_KEY = process.env.GUARDIAN_DEPLOYER_PRIVATE_KEY || "0x" + "00".repeat(32);

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "cancun",
    },
  },
  networks: {
    hardhat: {},
    monad_testnet: {
      url: process.env.MONAD_TESTNET_RPC || "https://testnet-rpc.monad.xyz",
      chainId: 10143,
      // Same registrar-key fallback as base_sepolia so testnet rehearsal
      // works from the shared .env.
      accounts: [
        process.env.GUARDIAN_DEPLOYER_PRIVATE_KEY ||
        process.env.GUARDIAN_ERC8004_REGISTRAR_KEY ||
        "0x" + "00".repeat(32),
      ],
    },
    base: {
      url: process.env.BASE_RPC || "https://mainnet.base.org",
      chainId: 8453,
      accounts: [DEPLOYER_KEY],
    },
    base_sepolia: {
      url: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org",
      chainId: 84532,
      // Falls back to the ERC-8004 registrar key so testnet rehearsal works
      // with the same .env the demo uses.
      accounts: [
        process.env.GUARDIAN_DEPLOYER_PRIVATE_KEY ||
        process.env.GUARDIAN_ERC8004_REGISTRAR_KEY ||
        "0x" + "00".repeat(32),
      ],
    },
    ethereum: {
      url: process.env.ETH_RPC || "https://eth.llamarpc.com",
      chainId: 1,
      accounts: [DEPLOYER_KEY],
    },
  },
  etherscan: {
    apiKey: {
      monad_testnet: process.env.MONADSCAN_API_KEY || "",
      base: process.env.BASESCAN_API_KEY || "",
      mainnet: process.env.ETHERSCAN_API_KEY || "",
    },
    customChains: [
      {
        network: "monad_testnet",
        chainId: 10143,
        urls: {
          apiURL: "https://testnet.monadscan.com/api",
          browserURL: "https://testnet.monadscan.com",
        },
      },
    ],
  },
  sourcify: {
    enabled: true,
    apiUrl: "https://sourcify-api-monad.blockvision.org",
    browserUrl: "https://testnet.monadvision.com",
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },
  tenderly: {
    project: process.env.TENDERLY_PROJECT_SLUG || "project",
    username: process.env.TENDERLY_ACCOUNT_SLUG || "monad-86d12ef02b",
    privateVerification: false,
  },
};

export default config;
