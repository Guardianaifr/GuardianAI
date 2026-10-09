# GuardianAI Operator Passkey (Mera)

> **Monad Metropolis: Mera bounty.** One operator passkey is the root of trust for a fleet of AI agents.
> Each job gets its own PRF salt, so the same passkey gives every agent an identity, an encrypted memory
> and a credential vault. Everything is re-derived on demand from the passkey; no key is stored anywhere.
> None of the namespaces signs a blockchain transaction.

**Live page:** https://aiguardian.dev/mera/ (source `website/mera/`, deployed with the site: `firebase deploy --only hosting`). Real passkeys only: the page calls
`@category-labs/mera` with its default browser client (`navigator.credentials`), with no simulation fallback.

---

## 1. The namespaces

| Namespace (salt) | Primitive | What it does in GuardianAI |
| --- | --- | --- |
| `SHA-256("guardianai:v1:agent:identity:<agentId>")` | **Derivation**: PRF output is the Ed25519 private key inside `createEd25519SigningSession`, ended (zeroed) right after use | Agent DID `did:guardian:ed25519:<pubkey>`, and the key that signs the agent's **card** for the GuardianAI relay |
| `SHA-256("guardianai:v1:agent:memory:<agentId>")` | **Encryption**: PRF → HKDF-SHA256 (`guardianai:v1:encrypt:memory`) → non-extractable AES-256-GCM key, AAD `agentId:session:seq:timestamp` | Agent memory stored only as ciphertext. One flipped bit fails the GCM tag → `MEMORY_POISONING_DETECTED` → agent quarantined |
| Fresh random salt per secret (Mera secret vault) | **Encryption**: `createSecretVaultWithExistingPasskey` / `decryptSecretVaultWithPasskey` | Wraps credentials the agent needs (API keys, the Privy app secret) so they are not kept in plain text in `.env` |

Different agent ids give unrelated salts, so two agents of one operator cannot be linked by their keys.

### Where it plugs into GuardianAI (non-account work)

GuardianAI's relay signs EIP-712 approvals for agent payments. Before this change, `agent_id` in
`POST /api/v1/attest` was whatever the caller said (listed as a known limitation in `metropolis/README.md`).
Now an agent can be **registered to an operator passkey**:

1. In the console, the identity key signs an agent card:
   ```
   GuardianAI agent card v1
   agent: <agentId>
   wallet: <GuardianAgentWallet address>
   expires: <unix seconds, max 30 days>
   ```
2. The relay keeps `config/agent_passkey_identities.json` (`{agentId: did}`; public keys only).
3. For a registered agent, `/api/v1/attest` refuses to evaluate anything unless the request carries a card
   that verifies against the registered DID, names the same wallet and has not expired
   (`guardian/relayer/agent_card.py`). Approved responses say `"agent_identity": "passkey-verified"`.
4. `tools/privy-agent/agent.cjs` sends the card from `tools/privy-agent/.agent-card.json` (or
   `GUARDIAN_AGENT_CARD`) automatically.

Without the operator's passkey nobody can produce a card for a registered agent. The card is a signed
statement, not a secret: spending still needs the agent's own key on-chain (`GuardianAgentWallet`).

---

## 2. Live demo (the cross-device test)

**Devices that deliver PRF** (Mera's [authenticator support](https://mera.category.xyz/authenticator-support/)):
Chrome 132+ **signed in to Google Password Manager** (desktop and Android), iCloud Keychain (iOS 18+ /
macOS 15+), Windows 11 25H2+ Windows Password Manager, 1Password, YubiKey 5. A Chrome *local* profile and
Windows 10 Windows Hello do not return PRF output.

Both devices must open the **same HTTPS origin**: the PRF output depends on the relying party id
(the page uses `location.hostname`). `localhost` works for single-device testing.

1. **Device A**: open the page → *Create operator passkey* (saved to your passkey provider).
2. *Derive agent DID* → *Seal memory* → *Lock in vault* (use a dummy credential on camera).
3. *Make handoff link + QR*. The link holds only the DID, ciphertext and the vault, in the URL fragment
   (never sent to a server).
4. **Device B** (phone, or a fresh browser profile on the same passkey account): scan the QR →
   *Use a synced passkey* → *Derive agent DID* shows **✔ Same DID** → *Unseal* shows the memory →
   *Unlock vault* shows the credential (masked).
5. *Tamper 1 bit* → *Unseal* → **MEMORY_POISONING_DETECTED**, agent quarantined.
6. *Sign agent card* for the agent's wallet → put the DID in `config/agent_passkey_identities.json`, the card
   in `tools/privy-agent/.agent-card.json` → `node agent.cjs wallet-pay ...` prints `identity=passkey-verified`.
   Delete the card file and the same payment is refused: `agent card required`.

The relay registry uses the agent id the Privy agent sends: `privy-agent:<agent address, lowercase>`.
Use that id in the console when issuing its card.

---

## 3. Tests

```bash
cd metropolis/mera
npm test                 # 26 Vitest tests (engine, namespaces, agent card, handoff capsule, vault)
npm run typecheck
npm run build:console    # rebuilds website/mera/app.js from src/operator_console.ts

# Real WebAuthn PRF in headless Chromium (DevTools virtual authenticator, hasPrf=true), no mocks in the page
pip install playwright && python -m playwright install chromium
python scripts/e2e_virtual_passkey.py

# Relay side
python -m pytest tests/test_agent_card.py   # includes a card signed in the browser by the e2e run
```

`e2e_virtual_passkey.py` checks: passkey creation with PRF, DID derivation, seal/unseal, 1-bit tamper →
quarantine, vault lock/unlock, agent card signed by the DID, handoff link carries no plaintext, browser
storage holds only the public credential id, the same DID/memory/vault come back on a wiped page, and a
different passkey gets a different DID and cannot decrypt.

The older `npm run demo` / `npm run test:hard` scripts use `MockWebAuthnClient` (HMAC stand-in for a
passkey) and remain as headless regression tests; they are not the live demo.

---

## 4. Honest limitations

- The virtual authenticator cannot export a credential's PRF secret, so the automated "second device" is the
  same authenticator behind a wiped page. The real cross-device run is manual (section 2).
- Each namespace is a separate passkey prompt (Mera returns one PRF output per ceremony).
- The agent CLI cannot run WebAuthn, so the agent card is issued in the browser and handed to the agent;
  the vault is unlocked in the browser, not by the agent process.
- The registry maps agent ids to DIDs by hand; revoking a card early means removing the agent's DID.
- The memory tripwire quarantines in the console and in the ElizaOS middleware (`recordCryptographicTamper`);
  it does not pause the on-chain wallet automatically.

## 5. Files

```
metropolis/mera/src/guardian_mera_engine.ts   namespaces, identity, agent card, seal/unseal
metropolis/mera/src/capsule.ts                handoff link format (validated on load)
metropolis/mera/src/operator_console.ts       browser console → website/mera/app.js
metropolis/mera/scripts/e2e_virtual_passkey.py real-PRF browser test
website/mera/index.html                       the page
guardian/relayer/agent_card.py                relay-side card verification
config/agent_passkey_identities.example.json  registry format
```
