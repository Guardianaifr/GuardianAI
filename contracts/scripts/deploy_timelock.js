const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying GuardianTimelock with:", deployer.address);

  // CONFIGURE THESE before mainnet deployment:
  // proposers: multi-sig addresses that can propose operations
  // executors: [ethers.ZeroAddress] means anyone can execute after delay
  // admin: deployer initially — MUST renounce after setup
  const proposers = [deployer.address]; // Replace with multi-sig
  const executors = [ethers.ZeroAddress]; // Open execution after delay
  const admin = deployer.address; // Will renounce after ownership transfer

  const GuardianTimelock = await ethers.getContractFactory(
    "GuardianTimelock"
  );
  const timelock = await GuardianTimelock.deploy(
    proposers,
    executors,
    admin
  );
  await timelock.waitForDeployment();

  console.log("GuardianTimelock deployed to:", 
    await timelock.getAddress());
  console.log("Min delay:", await timelock.getMinDelay(), "seconds");
  console.log(
    "IMPORTANT: Transfer ownership of all 6 Guardian contracts",
    "to this timelock address, then renounce admin role."
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
