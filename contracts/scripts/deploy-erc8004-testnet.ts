import { ethers } from "hardhat";

/**
 * Deploys the GuardianAI TESTNET STAND-IN ERC-8004 Identity Registry to
 * Base Sepolia. See IdentityRegistryTestnet.sol for scope and honesty notes.
 *
 * Usage (from contracts/):
 *   GUARDIAN_DEPLOYER_PRIVATE_KEY=0x... npx hardhat run \
 *     scripts/deploy-erc8004-testnet.ts --network base_sepolia
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("deployer:", deployer.address);

  const factory = await ethers.getContractFactory("IdentityRegistryTestnet");
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("IdentityRegistryTestnet deployed:", address);
  console.log("REGISTRY_ADDRESS=" + address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
