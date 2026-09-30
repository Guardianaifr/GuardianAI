/**
 * PrivyConfigProvider.tsx
 *
 * Wraps the application in PrivyProvider configured for GuardianAI:
 *  - Monad Testnet (Chain ID 10143)
 *  - Embedded wallets auto-created for users who don't have one
 *  - Dark theme with Monad purple accent (#836EF9)
 */

import React from "react";
import { PrivyProvider } from "@privy-io/react-auth";
import { monadTestnet } from "../lib/monadChain";
import { isDemoModeActive } from "../lib/demoMode";

interface PrivyConfigProviderProps {
  children: React.ReactNode;
}

export const PrivyConfigProvider: React.FC<PrivyConfigProviderProps> = ({
  children,
}) => {
  const isDemo = isDemoModeActive();
  const rawAppId = import.meta.env.VITE_PRIVY_APP_ID;
  const cleanAppId = typeof rawAppId === "string" ? rawAppId.trim() : "";

  let resolvedAppId: string | null = null;
  let configError: string | null = null;

  if (cleanAppId.length === 25) {
    resolvedAppId = cleanAppId;
  } else if (isDemo) {
    // Explicit demo mode permits fallback demo ID
    resolvedAppId = "clxguardianmonaddemo00000";
  } else {
    // Outside demo mode: fail closed with visible error; no silent demo-ID fallback, no padEnd
    if (!cleanAppId) {
      configError = "Missing VITE_PRIVY_APP_ID environment variable.";
    } else {
      configError = `Invalid VITE_PRIVY_APP_ID length (${cleanAppId.length} characters). Expected exactly 25 characters.`;
    }
  }

  if (configError || !resolvedAppId) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] text-white flex flex-col items-center justify-center p-6 text-center font-sans">
        <div className="max-w-md w-full bg-red-950/40 border border-red-500/50 rounded-xl p-6 shadow-2xl backdrop-blur-md">
          <div className="w-12 h-12 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center mx-auto mb-4 text-2xl font-bold">
            !
          </div>
          <h2 className="text-xl font-bold text-red-200 mb-2">Privy Configuration Error</h2>
          <p className="text-sm text-red-300 mb-4">{configError}</p>
          <div className="text-xs text-neutral-400 text-left bg-black/40 p-3 rounded border border-neutral-800 space-y-2">
            <p>
              <strong>Production Mode:</strong> Privy authentication requires a valid 25-character App ID to initialize outside demo mode.
            </p>
            <p>
              Please configure <code className="text-amber-300">VITE_PRIVY_APP_ID</code> in your production environment, or append <code className="text-cyan-300">?demo=true</code> to the URL to explore in demo mode.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <PrivyProvider
      appId={resolvedAppId}
      config={{
        /* ---------- Supported login methods ---------- */
        loginMethods: ["email", "wallet", "google"],

        /* ---------- Embedded wallet ---------- */
        embeddedWallets: {
          createOnLogin: "users-without-wallets",
        },

        /* ---------- Default chain ---------- */
        defaultChain: monadTestnet as any,
        supportedChains: [monadTestnet as any],

        /* ---------- Appearance ---------- */
        appearance: {
          theme: "dark",
          accentColor: "#836EF9", // Monad purple
          logo: "/guardian-logo.svg",
        },
      }}
    >
      {children}
    </PrivyProvider>
  );
};

export default PrivyConfigProvider;
