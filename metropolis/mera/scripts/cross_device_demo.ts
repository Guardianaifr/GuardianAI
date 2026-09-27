import GuardianMeraEngine from '../src/guardian_mera_engine';
import { MockWebAuthnClient } from '../src/mock_webauthn_client';

const COLORS = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  blue: "\x1b[34m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
  magenta: "\x1b[35m"
};

function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runDemo() {
  console.log(`${COLORS.magenta}=== GuardianAI + Mera Passkey Enclave Demo ===${COLORS.reset}\n`);

  // 1. Create MockWebAuthnClient (simulating Passkey on Device A)
  const masterSecret = new Uint8Array(32);
  crypto.getRandomValues(masterSecret); // fixed for this demo

  console.log(`${COLORS.blue}[Device A] Initializing Passkey...${COLORS.reset}`);
  const clientA = new MockWebAuthnClient({ masterSecret });
  const engineA = new GuardianMeraEngine('demo.guardianai.local');

  // 2. Mint agent identity
  console.log(`\n${COLORS.blue}[Device A] Minting Agent Identity for 'guardian-alpha'...${COLORS.reset}`);
  const identity = await engineA.deriveAgentIdentity('guardian-alpha', clientA);
  console.log(`${COLORS.green}✔ Identity Derived!${COLORS.reset}`);
  console.log(`${COLORS.cyan}  DID: ${identity.did}${COLORS.reset}`);
  console.log(`${COLORS.cyan}  Public Key: ${toHexString(identity.publicKey)}${COLORS.reset}`);

  // 3. Seal a strategy message
  const secretMessage = "Rebalance portfolio if price divergence exceeds 0.15%";
  console.log(`\n${COLORS.blue}[Device A] Sealing Memory...${COLORS.reset}`);
  console.log(`  Plaintext: "${secretMessage}"`);
  
  const sealed = await engineA.sealMemory('guardian-alpha', 'session-demo', 1, secretMessage, clientA);
  console.log(`${COLORS.green}✔ Memory Sealed!${COLORS.reset}`);
  console.log(`${COLORS.cyan}  Ciphertext (hex): ${toHexString(sealed.ciphertext)}${COLORS.reset}`);
  console.log(`${COLORS.cyan}  IV (hex): ${toHexString(sealed.iv)}${COLORS.reset}`);
  console.log(`${COLORS.cyan}  AAD: ${sealed.aad}${COLORS.reset}`);

  // 4. Simulate Device B
  console.log(`\n${COLORS.magenta}--- Simulating Cross-Device Sync (Device B / Incognito) ---${COLORS.reset}\n`);
  
  console.log(`${COLORS.blue}[Device B] Initializing Passkey with same Master Secret...${COLORS.reset}`);
  const clientB = new MockWebAuthnClient({ masterSecret });
  const engineB = new GuardianMeraEngine('demo.guardianai.local');

  // 5. Derive identity again
  console.log(`\n${COLORS.blue}[Device B] Deriving Identity for 'guardian-alpha'...${COLORS.reset}`);
  const identityB = await engineB.deriveAgentIdentity('guardian-alpha', clientB);
  console.log(`${COLORS.green}✔ Identity Derived!${COLORS.reset}`);
  console.log(`${COLORS.cyan}  DID: ${identityB.did}${COLORS.reset}`);
  if (identity.did === identityB.did) {
    console.log(`${COLORS.green}  ✔ MATCHES DEVICE A${COLORS.reset}`);
  } else {
    console.log(`${COLORS.red}  ✖ MISMATCH${COLORS.reset}`);
  }

  // 6. Unseal memory
  console.log(`\n${COLORS.blue}[Device B] Unsealing Memory...${COLORS.reset}`);
  const unsealed = await engineB.unsealMemory('guardian-alpha', sealed.ciphertext, sealed.iv, sealed.aad, clientB);
  if (!unsealed.poisoned) {
    console.log(`${COLORS.green}✔ Memory Unsealed!${COLORS.reset}`);
    console.log(`${COLORS.cyan}  Plaintext: "${unsealed.plaintext}"${COLORS.reset}`);
  } else {
    console.log(`${COLORS.red}✖ Failed to unseal${COLORS.reset}`);
  }

  // 7. Simulate Tampering
  console.log(`\n${COLORS.magenta}--- Simulating Active Tamper Attack ---${COLORS.reset}\n`);
  console.log(`${COLORS.blue}[Attacker] Flipping 1 byte in ciphertext...${COLORS.reset}`);
  
  const tamperedCiphertext = new Uint8Array(sealed.ciphertext);
  tamperedCiphertext[0] ^= 0x01; // flip a bit

  console.log(`\n${COLORS.blue}[Device B] Unsealing Tampered Memory...${COLORS.reset}`);
  const tamperedResult = await engineB.unsealMemory('guardian-alpha', tamperedCiphertext, sealed.iv, sealed.aad, clientB);
  
  if (tamperedResult.poisoned) {
    console.log(`${COLORS.green}✔ Tamper Tripwire Triggered!${COLORS.reset}`);
    console.log(`${COLORS.red}  Error: ${tamperedResult.error}${COLORS.reset}`);
  } else {
    console.log(`${COLORS.red}✖ Tamper detection failed${COLORS.reset}`);
  }

  console.log(`\n${COLORS.magenta}=== Demo Completed Successfully ===${COLORS.reset}`);
}

runDemo().catch(console.error);
