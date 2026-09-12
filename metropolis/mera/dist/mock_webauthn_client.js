/**
 * MockWebAuthnClient — Deterministic PRF simulator for headless CI testing.
 *
 * Implements Mera's WebAuthnClient interface using HMAC-SHA256.
 * Given the same masterSecret + salt, produces identical PRF output,
 * simulating cross-device passkey sync behavior.
 *
 * NEVER use this in production — only for automated tests and judge fallback.
 */
export class MockWebAuthnClient {
    masterSecret;
    credentialId;
    constructor(config) {
        if (config.masterSecret.length !== 32) {
            throw new Error('masterSecret must be exactly 32 bytes');
        }
        this.masterSecret = config.masterSecret;
        this.credentialId = config.credentialId ?? crypto.getRandomValues(new Uint8Array(32));
    }
    async createCredential(request) {
        const prfSalt = request.prfSalt;
        const prfOutput = await this.computePrf(prfSalt);
        return {
            credentialId: this.credentialId,
            prfEnabled: true,
            prfOutput: new Uint8Array(prfOutput),
        };
    }
    async getCredential(request) {
        const prfSalt = request.prfSalt;
        const prfOutput = await this.computePrf(prfSalt);
        return {
            credentialId: this.credentialId,
            prfOutput: new Uint8Array(prfOutput),
        };
    }
    /**
     * Deterministic PRF: HMAC-SHA256(masterSecret, salt)
     * Same master + same salt = same 32-byte output, simulating cross-device sync.
     */
    async computePrf(salt) {
        const key = await crypto.subtle.importKey('raw', this.masterSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return crypto.subtle.sign('HMAC', key, salt);
    }
}
