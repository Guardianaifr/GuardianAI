import type { WebAuthnClient } from '@category-labs/mera';
export type SealedMemory = {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    aad: string;
    timestamp: number;
};
export type AgentIdentity = {
    publicKey: Uint8Array;
    did: string;
    agentId: string;
};
export type UnsealResult = {
    plaintext: string;
    poisoned: false;
} | {
    plaintext: null;
    poisoned: true;
    error: string;
};
export declare function deriveAgentIdentity(agentId: string, webAuthnClient: WebAuthnClient, rpId?: string, credentialId?: string): Promise<{
    identity: AgentIdentity;
    credentialId: string | null;
}>;
export declare function sealMemory(agentId: string, sessionId: string, seqNo: number, plaintext: string, webAuthnClient: WebAuthnClient, rpId?: string, credentialId?: string): Promise<{
    sealed: SealedMemory;
    credentialId: string | null;
}>;
export declare function unsealMemory(agentId: string, ciphertext: Uint8Array, iv: Uint8Array, aad: string, webAuthnClient: WebAuthnClient, rpId?: string, credentialId?: string): Promise<UnsealResult>;
export default class GuardianMeraEngine {
    private credentialId;
    private rpId;
    constructor(rpId?: string);
    setCredentialId(id: string): void;
    getCredentialId(): string | null;
    deriveAgentIdentity(agentId: string, webAuthnClient: WebAuthnClient): Promise<AgentIdentity>;
    sealMemory(agentId: string, sessionId: string, seqNo: number, plaintext: string, webAuthnClient: WebAuthnClient): Promise<SealedMemory>;
    unsealMemory(agentId: string, ciphertext: Uint8Array, iv: Uint8Array, aad: string, webAuthnClient: WebAuthnClient): Promise<UnsealResult>;
}
