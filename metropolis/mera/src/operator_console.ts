/**
 * GuardianAI Operator Passkey console (browser). Bundled to website/mera/app.js by scripts/build-console.mjs.
 *
 * Real passkeys only: every derivation below runs a WebAuthn PRF ceremony through Mera's default
 * browser client (navigator.credentials). There is no simulation fallback on this page.
 */
import {
  createPasskeyWithPrfOutput,
  createSecretVaultWithExistingPasskey,
  decryptSecretVaultWithPasskey,
  isMeraError,
} from '@category-labs/mera';
import type { PasskeySecretVault } from '@category-labs/mera';
import QRCode from 'qrcode';
import {
  deriveAgentIdentity,
  sealMemory,
  unsealMemory,
  signAgentCard,
  namespaceSalt,
  toHex,
  IDENTITY_NAMESPACE,
  MEMORY_NAMESPACE,
} from './guardian_mera_engine';
import { b64url, fromB64url, encodeCapsule, decodeCapsule, isValidAgentId } from './capsule';
import type { Capsule } from './capsule';

const rpId = location.hostname;
const CRED_KEY = 'guardianai.mera.credentialId'; // credential id only: public, not a secret

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

type State = {
  credentialId?: string;
  did?: string;
  expectedDid?: string;
  memory?: { c: Uint8Array; iv: Uint8Array; aad: string };
  vault?: PasskeySecretVault;
};
const state: State = {};

function log(text: string, kind: 'info' | 'ok' | 'bad' | 'step' = 'info') {
  const line = document.createElement('div');
  line.className = `log-${kind}`;
  line.textContent = `${new Date().toLocaleTimeString()}  ${text}`;
  const box = $('log');
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function errText(e: unknown): string {
  if (isMeraError(e)) {
    if (e.code === 'PRF_UNAVAILABLE') return 'PRF_UNAVAILABLE: this passkey provider does not support PRF. Use Chrome signed in to Google Password Manager, iCloud Keychain (iOS 18+/macOS 15+), Windows 11 25H2+, or a YubiKey 5.';
    if (e.code === 'PASSKEY_OPERATION_FAILED') return `Passkey prompt failed or was cancelled (${e.message})`;
    return `${e.code}: ${e.message}`;
  }
  return String((e as Error)?.message ?? e);
}

function agentId(): string {
  const id = $<HTMLInputElement>('agentId').value.trim();
  if (!isValidAgentId(id)) throw new Error('Agent id: 1-96 chars of letters, digits, : . _ -');
  return id;
}

function loadCredential() {
  try {
    const id = localStorage.getItem(CRED_KEY);
    if (id) state.credentialId = id;
  } catch { /* storage blocked: the platform passkey picker still works */ }
  renderCredential();
}

function saveCredential(id: string) {
  state.credentialId = id;
  try { localStorage.setItem(CRED_KEY, id); } catch { /* ignore */ }
  renderCredential();
}

function renderCredential() {
  $('credStatus').textContent = state.credentialId
    ? `Operator passkey selected (credential ${state.credentialId.slice(0, 10)}…). This device stores only that public credential id.`
    : 'No passkey selected yet. Create one, or use a synced passkey: your device will show its passkey picker.';
  let stored = '(nothing)';
  try { stored = Object.keys(localStorage).filter(k => k.startsWith('guardianai.')).join(', ') || '(nothing)'; } catch { /* ignore */ }
  $('storedKeys').textContent = stored;
}

async function busy<T>(button: HTMLButtonElement, fn: () => Promise<T>): Promise<T | undefined> {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Waiting for passkey…';
  try {
    return await fn();
  } catch (e) {
    log(errText(e), 'bad');
    return undefined;
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

async function showSalt(label: string, el: string) {
  $(el).textContent = `salt = SHA-256("${label}") = ${toHex(await namespaceSalt(label)).slice(0, 16)}…`;
}

// ── Operator passkey ────────────────────────────────────────────────────────
async function createOperatorPasskey(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    log('Creating a new operator passkey (one prompt, maybe two if PRF is evaluated after creation)…', 'step');
    const res = await createPasskeyWithPrfOutput({
      rp: { id: rpId, name: 'GuardianAI Operator' },
      user: { name: 'guardianai-operator', displayName: 'GuardianAI operator' },
    });
    res.prfOutput.fill(0); // only needed to prove PRF works; real keys are derived per namespace below
    saveCredential(res.credentialId);
    log('Passkey created and PRF confirmed. It syncs through your passkey provider to your other devices.', 'ok');
  });
}

function useAnyPasskey() {
  state.credentialId = undefined;
  try { localStorage.removeItem(CRED_KEY); } catch { /* ignore */ }
  renderCredential();
  log('Next action will show the device passkey picker (use this on a second device or fresh browser profile).', 'info');
}

// ── Namespace 1: identity (derivation) ─────────────────────────────────────
async function deriveIdentity(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    const id = agentId();
    await showSalt(IDENTITY_NAMESPACE + id, 'idSalt');
    log(`Passkey PRF on identity namespace for "${id}"…`, 'step');
    const { identity, credentialId } = await deriveAgentIdentity(id, undefined, rpId, state.credentialId);
    if (credentialId) saveCredential(credentialId);
    state.did = identity.did;
    $('didOut').textContent = identity.did;
    const match = $('didMatch');
    if (state.expectedDid) {
      const ok = state.expectedDid === identity.did;
      match.textContent = ok ? '✔ Same DID as the device that made the handoff link' : '✖ Different DID: different passkey or agent id';
      match.className = ok ? 'badge ok' : 'badge bad';
      log(ok ? 'Cross-device check: DID matches the first device.' : 'Cross-device check: DID does NOT match.', ok ? 'ok' : 'bad');
    } else {
      match.textContent = 'Derived on this device. The private key was zeroed; only the public key is shown.';
      match.className = 'badge';
    }
    log(`Agent DID ${identity.did.slice(0, 40)}…`, 'ok');
  });
}

// ── Namespace 2: memory (encryption) ───────────────────────────────────────
function renderMemory() {
  $('memCipher').textContent = state.memory
    ? `ciphertext ${toHex(state.memory.c).slice(0, 48)}… (${state.memory.c.length} bytes)\niv ${toHex(state.memory.iv)}\naad ${state.memory.aad}`
    : '(no sealed memory yet)';
}

async function seal(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    const id = agentId();
    const text = $<HTMLTextAreaElement>('memIn').value;
    if (!text.trim()) throw new Error('Write something for the agent to remember first.');
    await showSalt(MEMORY_NAMESPACE + id, 'memSalt');
    log(`Passkey PRF on memory namespace for "${id}" → HKDF → AES-256-GCM…`, 'step');
    const { sealed, credentialId } = await sealMemory(id, 'console', Date.now() % 1_000_000, text, undefined, rpId, state.credentialId);
    if (credentialId) saveCredential(credentialId);
    state.memory = { c: sealed.ciphertext, iv: sealed.iv, aad: sealed.aad };
    renderMemory();
    $('memOut').textContent = '';
    setQuarantine(false);
    log('Memory sealed. Only ciphertext exists now; the plaintext is not stored anywhere.', 'ok');
  });
}

async function unseal(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    const id = agentId();
    if (!state.memory) throw new Error('No sealed memory. Seal some, or open a handoff link.');
    log(`Passkey PRF on memory namespace for "${id}" → decrypt…`, 'step');
    const r = await unsealMemory(id, state.memory.c, state.memory.iv, state.memory.aad, undefined, rpId, state.credentialId);
    if (r.poisoned) {
      setQuarantine(true);
      $('memOut').textContent = '';
      log('MEMORY_POISONING_DETECTED: AES-GCM tag check failed. Agent quarantined.', 'bad');
    } else if (r.plaintext === null) {
      log(r.detail, 'bad');
    } else {
      setQuarantine(false);
      $('memOut').textContent = r.plaintext;
      log('Memory decrypted with a key re-derived from the passkey.', 'ok');
    }
  });
}

function tamper() {
  if (!state.memory) { log('Seal memory first.', 'bad'); return; }
  const c = new Uint8Array(state.memory.c);
  c[0] ^= 0x01;
  state.memory = { ...state.memory, c };
  renderMemory();
  log('Attacker flipped 1 bit of the stored ciphertext. Now press Unseal.', 'bad');
}

function setQuarantine(on: boolean) {
  $('quarantine').hidden = !on;
}

// ── Namespace 3: credential vault (Mera secret vault, fresh random salt) ───
async function lockVault(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    const secretInput = $<HTMLInputElement>('vaultIn');
    const credentialText = secretInput.value;
    if (!credentialText) throw new Error('Enter the credential to lock (for the demo use a dummy API key).');
    log('Passkey PRF with a fresh random salt → Mera secret vault…', 'step');
    const vault = await createSecretVaultWithExistingPasskey({
      rpId,
      secret: new TextEncoder().encode(credentialText),
      ...(state.credentialId ? { credential: { credentialId: state.credentialId } } : {}),
    });
    secretInput.value = '';
    state.vault = vault;
    if (!state.credentialId) saveCredential(vault.credential.credentialId);
    $('vaultJson').textContent = JSON.stringify(vault, null, 1);
    $('vaultOut').textContent = '';
    log('Credential locked. The input box was cleared; only the vault ciphertext remains.', 'ok');
  });
}

async function unlockVault(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    if (!state.vault) throw new Error('No vault yet. Lock a credential, or open a handoff link that has one.');
    log('Passkey PRF with the vault salt → decrypt…', 'step');
    const bytes = await decryptSecretVaultWithPasskey({ rpId, vault: state.vault });
    const text = new TextDecoder().decode(bytes);
    bytes.fill(0);
    const masked = text.length <= 8 ? '•'.repeat(text.length) : `${text.slice(0, 4)}${'•'.repeat(Math.min(text.length - 8, 24))}${text.slice(-4)}`;
    $('vaultOut').textContent = masked;
    log('Vault unlocked on this device (shown masked).', 'ok');
  });
}

// ── Cross-device handoff ───────────────────────────────────────────────────
async function makeHandoff() {
  try {
    const capsule: Capsule = { v: 1, agent: agentId() };
    if (state.did) capsule.did = state.did;
    if (state.memory) capsule.memory = { c: b64url(state.memory.c), iv: b64url(state.memory.iv), aad: state.memory.aad };
    if (state.vault) capsule.vault = state.vault;
    if (!capsule.memory && !capsule.vault && !capsule.did) throw new Error('Derive the DID or seal memory first.');
    const url = `${location.origin}${location.pathname}#c=${encodeCapsule(capsule)}`;
    $<HTMLInputElement>('handoffUrl').value = url;
    await QRCode.toCanvas($<HTMLCanvasElement>('qr'), url, { errorCorrectionLevel: 'L', margin: 1, width: 260 });
    $('handoffBox').hidden = false;
    log(`Handoff link ready (${url.length} chars). It carries only the DID, ciphertext and the vault: no keys.`, 'ok');
  } catch (e) {
    log(errText(e), 'bad');
  }
}

function loadFromFragment() {
  const m = location.hash.match(/^#c=([A-Za-z0-9_-]+)$/);
  if (!m) return;
  try {
    const capsule = decodeCapsule(m[1]);
    $<HTMLInputElement>('agentId').value = capsule.agent;
    state.expectedDid = capsule.did;
    if (capsule.memory) {
      state.memory = { c: fromB64url(capsule.memory.c), iv: fromB64url(capsule.memory.iv), aad: capsule.memory.aad };
    }
    if (capsule.vault) {
      state.vault = capsule.vault;
      $('vaultJson').textContent = JSON.stringify(capsule.vault, null, 1);
    }
    renderMemory();
    $('handoffBanner').hidden = false;
    log(`Loaded a handoff for "${capsule.agent}". It contains no keys: press "Use a synced passkey", then derive and unseal.`, 'info');
  } catch (e) {
    log(`Ignored a malformed handoff link: ${errText(e)}`, 'bad');
  }
}

// ── Agent card for the GuardianAI relay ────────────────────────────────────
async function issueCard(btn: HTMLButtonElement) {
  await busy(btn, async () => {
    const id = agentId();
    const wallet = $<HTMLInputElement>('cardWallet').value.trim();
    const days = Math.max(1, Math.min(30, Number($<HTMLInputElement>('cardDays').value) || 7));
    const expires = Math.floor(Date.now() / 1000) + days * 86400;
    log(`Passkey PRF on identity namespace → Ed25519 signs the agent card for ${wallet}…`, 'step');
    const { card, credentialId } = await signAgentCard(id, wallet, expires, undefined, rpId, state.credentialId);
    if (credentialId) saveCredential(credentialId);
    $('cardJson').textContent = JSON.stringify(card, null, 2);
    $('registryLine').textContent = JSON.stringify({ [card.agent_id]: card.did }, null, 2);
    log('Agent card signed. Give the card to the agent and register the DID with the relay.', 'ok');
  });
}

async function prfSupport() {
  const el = $('prfStatus');
  if (!window.isSecureContext || !('PublicKeyCredential' in window)) {
    el.textContent = 'Passkeys need HTTPS (or localhost) and a WebAuthn browser.';
    el.className = 'badge bad';
    return;
  }
  let caps: Record<string, boolean> | undefined;
  try {
    const getCaps = (PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> }).getClientCapabilities;
    caps = getCaps ? await getCaps.call(PublicKeyCredential) : undefined;
  } catch { /* older browsers */ }
  const prf = caps?.['extension:prf'];
  el.textContent = prf === true
    ? `Browser supports the PRF extension. Relying party: ${rpId}`
    : `Browser did not report PRF support${prf === false ? '' : ' (unknown)'}; your passkey provider must support it. Relying party: ${rpId}`;
  el.className = prf === true ? 'badge ok' : 'badge warn';
}

function copy(id: string) {
  const el = $(id) as HTMLInputElement | HTMLElement;
  const text = 'value' in el ? (el as HTMLInputElement).value : el.textContent || '';
  navigator.clipboard?.writeText(text).then(() => log('Copied.', 'info'), () => log('Copy failed: select and copy manually.', 'bad'));
}

function bind(id: string, fn: (b: HTMLButtonElement) => unknown) {
  const b = $<HTMLButtonElement>(id);
  b.addEventListener('click', () => fn(b));
}

window.addEventListener('DOMContentLoaded', () => {
  $('rpId').textContent = rpId;
  bind('btnCreate', createOperatorPasskey);
  bind('btnAny', useAnyPasskey);
  bind('btnDerive', deriveIdentity);
  bind('btnSeal', seal);
  bind('btnUnseal', unseal);
  bind('btnTamper', tamper);
  bind('btnLock', lockVault);
  bind('btnUnlock', unlockVault);
  bind('btnHandoff', makeHandoff);
  bind('btnCopyLink', () => copy('handoffUrl'));
  bind('btnCard', issueCard);
  bind('btnCopyCard', () => copy('cardJson'));
  loadCredential();
  loadFromFragment();
  renderMemory();
  void prfSupport();
});
