import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const contracts = [
  'GuardianPolicyGuard',
  'GuardianThreatFeedRegistry',
  'GuardianPassportSBT',
  'GuardianCortexAnchor',
  'GuardianRiskAttestation'
];

const artifactsDir = path.resolve(__dirname, '../../../contracts/artifacts/contracts');
const outputDir = path.resolve(__dirname, '../abis');

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

console.log(`[sync-indexer-abis] Reading Hardhat build artifacts from: ${artifactsDir}`);
console.log(`[sync-indexer-abis] Target ABI output directory: ${outputDir}`);

let successCount = 0;

for (const name of contracts) {
  const artifactPath = path.join(artifactsDir, `${name}.sol`, `${name}.json`);
  if (!fs.existsSync(artifactPath)) {
    console.error(`[-] Artifact not found for: ${name} at ${artifactPath}`);
    process.exit(1);
  }

  const raw = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const abi = raw.abi;
  if (!abi || !Array.isArray(abi)) {
    console.error(`[-] Missing ABI array in artifact: ${name}`);
    process.exit(1);
  }

  const outputPath = path.join(outputDir, `${name}.json`);
  fs.writeFileSync(outputPath, JSON.stringify(abi, null, 2), 'utf8');
  console.log(`[+] Exported clean ABI for ${name} (${abi.length} elements) -> ${outputPath}`);
  successCount++;
}

console.log(`[sync-indexer-abis] Successfully synced ${successCount} contract ABIs.`);