/**
 * MockWebAuthnClient — Deterministic PRF simulator for headless CI testing.
 *
 * Implements Mera's WebAuthnClient interface using HMAC-SHA256.
 * Given the same masterSecret + salt, produces identical PRF output,
 * simulating cross-device passkey sync behavior.
 *
 * NEVER use this in production — only for automated tests and judge fallback.
 */
import type { WebAuthnClient } from '@category-labs/mera';
export interface MockConfig {
    /** 32-byte master secret simulating the passkey's internal PRF key */
    masterSecret: Uint8Array;
    /** Simulated credential ID */
    credentialId?: Uint8Array;
}
export declare class MockWebAuthnClient implements WebAuthnClient {
    private readonly masterSecret;
    private readonly credentialId;
    constructor(config: MockConfig);
    createCredential(request: WebAuthnClient.CreateCredentialRequest): Promise<WebAuthnClient.CreateCredentialResult>;
    getCredential(request: WebAuthnClient.GetCredentialRequest): Promise<WebAuthnClient.GetCredentialResult>;
    /**
     * Deterministic PRF: HMAC-SHA256(masterSecret, salt)
     * Same master + same salt = same 32-byte output, simulating cross-device sync.
     */
    private computePrf;
}
