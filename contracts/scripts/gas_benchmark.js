const { ethers } = require("hardhat");

async function main() {
    console.log("Deploying GuardianThreatFeedRegistry...");
    const Registry = await ethers.getContractFactory("GuardianThreatFeedRegistry");
    const registry = await Registry.deploy();
    await registry.waitForDeployment();
    const registryAddress = await registry.getAddress();
    console.log("Deployed to:", registryAddress);

    const [owner] = await ethers.getSigners();
    // Use dummy addresses for benchmarking
    const addresses = [];
    for(let i=1; i<=56; i++) {
        const hex = i.toString(16).padStart(40, '0');
        addresses.push("0x" + hex);
    }
    const reason = "High Risk entity";

    // 1. Benchmark Sequential (Before)
    let totalGasSequential = 0n;
    for(let i=0; i<56; i++) {
        const tx = await registry.addAddress(addresses[i], reason);
        const receipt = await tx.wait();
        totalGasSequential += receipt.gasUsed;
    }
    console.log(`\nBefore (56 individual txs): ${totalGasSequential.toString()} gas`);

    // Reset by deploying a fresh contract for clean state
    const registry2 = await Registry.deploy();
    await registry2.waitForDeployment();

    // 2. Benchmark Batched (After) - batch 1 (50), batch 2 (6)
    const batch1 = addresses.slice(0, 50);
    const reasons1 = Array(50).fill(reason);
    
    const batch2 = addresses.slice(50, 56);
    const reasons2 = Array(6).fill(reason);

    let totalGasBatched = 0n;
    
    const tx1 = await registry2.addAddressesBatch(batch1, reasons1);
    const receipt1 = await tx1.wait();
    totalGasBatched += receipt1.gasUsed;

    const tx2 = await registry2.addAddressesBatch(batch2, reasons2);
    const receipt2 = await tx2.wait();
    totalGasBatched += receipt2.gasUsed;

    console.log(`After (2 batched txs): ${totalGasBatched.toString()} gas`);
    
    const savings = ((totalGasSequential - totalGasBatched) * 100n) / totalGasSequential;
    console.log(`Savings on first full sync: ${savings.toString()}%`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
