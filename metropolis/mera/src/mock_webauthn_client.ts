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

export class MockWebAuthnClient implements WebAuthnClient {
  private readonly masterSecret: Uint8Array;
  private readonly credentialId: Uint8Array;

  constructor(config: MockConfig) {
    if (config.masterSecret.length !== 32) {
      throw new Error('masterSecret must be exactly 32 bytes');
    }
    this.masterSecret = config.masterSecret;
    this.credentialId = config.credentialId ?? crypto.getRandomValues(new Uint8Array(32));
  }

  async createCredential(request: WebAuthnClient.CreateCredentialRequest): Promise<WebAuthnClient.CreateCredentialResult> {
    const prfSalt = request.prfSalt;
    const prfOutput = await this.computePrf(prfSalt);

    return {
      credentialId: this.credentialId,
      prfEnabled: true,
      prfOutput: new Uint8Array(prfOutput),
    };
  }

  async getCredential(request: WebAuthnClient.GetCredentialRequest): Promise<WebAuthnClient.GetCredentialResult> {
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
  private async computePrf(salt: Uint8Array): Promise<ArrayBuffer> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.masterSecret as any,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return crypto.subtle.sign('HMAC', key, salt as any);
  }
}
