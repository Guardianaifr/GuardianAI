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

interface PrivyConfigProviderProps {
  children: React.ReactNode;
}

const PRIVY_APP_ID = (import.meta.env.VITE_PRIVY_APP_ID as string) || "clx_guardian_demo";

export const PrivyConfigProvider: React.FC<PrivyConfigProviderProps> = ({
  children,
}) => {
  return (
    <PrivyProvider
      appId={PRIVY_APP_ID}
      config={{
        /* ---------- Supported login methods ---------- */
        loginMethods: ["email", "wallet", "google"],

        /* ---------- Embedded wallet ---------- */
        embeddedWallets: {
          // Automatically create an embedded wallet for users who don't
          // connect an external wallet (simplifies agent delegation UX).
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
