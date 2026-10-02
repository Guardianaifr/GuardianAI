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
      // Registrar-key fallback so testnet rehearsal works from the shared .env.
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
    tenderly_virtual_testnet: {
      url: process.env.TENDERLY_VIRTUAL_TESTNET_RPC || "http://127.0.0.1:8545",
      chainId: 1,
      accounts: [DEPLOYER_KEY],
    },
    tenderly_monad_testnet: {
      url: process.env.TENDERLY_MONAD_VNET_RPC || "http://127.0.0.1:8545",
      chainId: 143,
      accounts: [DEPLOYER_KEY],
    },
  },
  etherscan: {
    apiKey: {
      monad_testnet: process.env.MONADSCAN_API_KEY || "",
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
