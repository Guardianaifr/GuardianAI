import { getPasskeyPrfOutput, createEd25519SigningSession } from '@category-labs/mera';
function toHexString(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
export async function deriveAgentIdentity(agentId, webAuthnClient, rpId = 'guardianai.localhost', credentialId) {
    const encoder = new TextEncoder();
    const saltString = "guardianai:v1:agent:identity:" + agentId;
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));
    const prfOutput = await getPasskeyPrfOutput({
        rpId,
        prfSalt: salt,
        webAuthnClient,
        ...(credentialId ? { credential: { credentialId } } : {})
    });
    const session = createEd25519SigningSession({ privateKey: prfOutput.prfOutput });
    const publicKey = session.publicKey;
    const did = `did:guardian:ed25519:${toHexString(publicKey)}`;
    session.end();
    // Overwrite the raw PRF output buffer in RAM for defense-in-depth
    prfOutput.prfOutput.fill(0);
    return {
        identity: { publicKey, did, agentId },
        credentialId: prfOutput.credentialId || credentialId || null
    };
}
export async function sealMemory(agentId, sessionId, seqNo, plaintext, webAuthnClient, rpId = 'guardianai.localhost', credentialId) {
    const encoder = new TextEncoder();
    const saltString = "guardianai:v1:agent:memory:" + agentId;
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));
    const prfOutput = await getPasskeyPrfOutput({
        rpId,
        prfSalt: salt,
        webAuthnClient,
        ...(credentialId ? { credential: { credentialId } } : {})
    });
    const baseKey = await crypto.subtle.importKey('raw', prfOutput.prfOutput, 'HKDF', false, ['deriveKey']);
    // Zero raw PRF buffer in RAM once imported into WebCrypto
    prfOutput.prfOutput.fill(0);
    const aesKey = await crypto.subtle.deriveKey({
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: encoder.encode('guardianai:v1:encrypt:memory')
    }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const timestamp = Date.now();
    const aadString = `${agentId}:${sessionId}:${seqNo}:${timestamp}`;
    const aad = encoder.encode(aadString);
    const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, aesKey, encoder.encode(plaintext));
    return {
        sealed: {
            ciphertext: new Uint8Array(ciphertextBuf),
            iv,
            aad: aadString,
            timestamp
        },
        credentialId: prfOutput.credentialId || credentialId || null
    };
}
export async function unsealMemory(agentId, ciphertext, iv, aad, webAuthnClient, rpId = 'guardianai.localhost', credentialId) {
    const encoder = new TextEncoder();
    const saltString = "guardianai:v1:agent:memory:" + agentId;
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));
    let prfOutput;
    try {
        prfOutput = await getPasskeyPrfOutput({
            rpId,
            prfSalt: salt,
            webAuthnClient,
            ...(credentialId ? { credential: { credentialId } } : {})
        });
    }
    catch (authError) {
        return {
            plaintext: null,
            poisoned: true,
            error: authError?.message?.includes('PRF') ? 'AUTHENTICATOR_ERROR' : 'MEMORY_POISONING_DETECTED'
        };
    }
    const baseKey = await crypto.subtle.importKey('raw', prfOutput.prfOutput, 'HKDF', false, ['deriveKey']);
    // Zero raw PRF buffer in RAM once imported into WebCrypto
    prfOutput.prfOutput.fill(0);
    const aesKey = await crypto.subtle.deriveKey({
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: encoder.encode('guardianai:v1:encrypt:memory')
    }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    try {
        const plaintextBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: encoder.encode(aad) }, aesKey, ciphertext);
        const decoder = new TextDecoder();
        return { plaintext: decoder.decode(plaintextBuf), poisoned: false };
    }
    catch (error) {
        return { plaintext: null, poisoned: true, error: 'MEMORY_POISONING_DETECTED' };
    }
}
export default class GuardianMeraEngine {
    credentialId = null;
    rpId;
    constructor(rpId = 'guardianai.localhost') {
        this.rpId = rpId;
    }
    setCredentialId(id) {
        this.credentialId = id;
    }
    getCredentialId() {
        return this.credentialId;
    }
    async deriveAgentIdentity(agentId, webAuthnClient) {
        const { identity, credentialId } = await deriveAgentIdentity(agentId, webAuthnClient, this.rpId, this.credentialId ?? undefined);
        if (credentialId && !this.credentialId) {
            this.credentialId = credentialId;
        }
        return identity;
    }
    async sealMemory(agentId, sessionId, seqNo, plaintext, webAuthnClient) {
        const { sealed, credentialId } = await sealMemory(agentId, sessionId, seqNo, plaintext, webAuthnClient, this.rpId, this.credentialId ?? undefined);
        if (credentialId && !this.credentialId) {
            this.credentialId = credentialId;
        }
        return sealed;
    }
    async unsealMemory(agentId, ciphertext, iv, aad, webAuthnClient) {
        return unsealMemory(agentId, ciphertext, iv, aad, webAuthnClient, this.rpId, this.credentialId ?? undefined);
    }
}
