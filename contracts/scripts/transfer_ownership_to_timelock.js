const { ethers } = require("hardhat");

// FILL THESE IN before running:
const TIMELOCK_ADDRESS = process.env.TIMELOCK_ADDRESS;
// Add all 6 Guardian contract addresses:
const GUARDIAN_CONTRACTS = [
  process.env.INSURANCE_LEDGER_ADDRESS,
  process.env.CORTEX_ANCHOR_ADDRESS,
  process.env.PASSPORT_SBT_ADDRESS,
  process.env.INTERLOCK_REGISTRY_ADDRESS,
  process.env.RISK_ATTESTATION_ADDRESS,
  process.env.THREAT_FEED_REGISTRY_ADDRESS
].filter(Boolean);

async function main() {
  if (!TIMELOCK_ADDRESS) {
    throw new Error(
      "TIMELOCK_ADDRESS env var required. " +
      "Deploy GuardianTimelock first."
    );
  }
  if (GUARDIAN_CONTRACTS.length === 0) {
    throw new Error("No contract addresses provided.");
  }

  const [deployer] = await ethers.getSigners();
  console.log("Transferring ownership to timelock:", TIMELOCK_ADDRESS);

  for (const contractAddress of GUARDIAN_CONTRACTS) {
    const contract = await ethers.getContractAt(
      "Ownable",
      contractAddress
    );
    const currentOwner = await contract.owner();
    
    if (currentOwner.toLowerCase() !== deployer.address.toLowerCase()) {
      console.log(
        `SKIP ${contractAddress}: owner is ${currentOwner},`,
        `not deployer`
      );
      continue;
    }

    const tx = await contract.transferOwnership(TIMELOCK_ADDRESS);
    await tx.wait();
    console.log(
      `✓ ${contractAddress} ownership transferred to timelock`
    );
  }

  console.log("\nNext steps:");
  console.log("1. Verify all transfers with: contract.owner()");
  console.log("2. Renounce timelock admin role:");
  console.log(
    "   timelock.renounceRole(TIMELOCK_ADMIN_ROLE, deployer.address)"
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
