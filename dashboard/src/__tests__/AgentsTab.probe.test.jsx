import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AgentsTab } from '../components/AgentsTab.jsx'

const switchChainSpy = vi.fn()
const getEthereumProviderSpy = vi.fn()

const mockWallet = {
  walletClientType: 'privy',
  address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
  switchChain: switchChainSpy,
  getEthereumProvider: getEthereumProviderSpy
}

vi.mock('@privy-io/react-auth', () => ({
  usePrivy: () => ({
    authenticated: true,
    user: {
      wallet: { address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' }
    }
  }),
  useWallets: () => ({
    wallets: [mockWallet]
  })
}))

vi.mock('@/lib/demoMode', () => ({
  isDemoModeActive: () => false
}))

describe('AgentsTab Component - Authenticated Non-Demo Probe Wallet Spies', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('clicks probe buttons outside demo mode: spies NEVER called and "Attestation Relayer Required" displays', async () => {
    render(
      <AgentsTab
        isConnectedSupervisor={true}
        supervisorAddress="0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        truncatedSupervisor="0x742d...f44e"
        isAdvanced={true}
      />
    )

    // Find all "Simulate Probe" sub-tabs on reference cards (3 cards: Eliza, Mera, Passport)
    const simulateTabs = screen.getAllByRole('button', { name: /simulate probe/i })
    expect(simulateTabs.length).toBe(3)

    // 1. Switch Eliza card (tab 0) to "Simulate Probe" and click injection probe
    fireEvent.click(simulateTabs[0])
    const elizaProbeBtn = await screen.findByRole('button', { name: /simulate prompt injection probe/i })
    fireEvent.click(elizaProbeBtn)

    // Assert "Attestation Relayer Required" is displayed
    await waitFor(() => {
      const relayerAlert = screen.getAllByText(/Attestation Relayer Required/i)
      expect(relayerAlert.length).toBeGreaterThanOrEqual(1)
    })

    // Assert spies are NOT called
    expect(switchChainSpy).not.toHaveBeenCalled()
    expect(getEthereumProviderSpy).not.toHaveBeenCalled()

    // 2. Click Eliza valid swap probe
    const elizaSwapBtn = screen.getByRole('button', { name: /simulated swap \(demo only\)/i })
    fireEvent.click(elizaSwapBtn)
    expect(switchChainSpy).not.toHaveBeenCalled()
    expect(getEthereumProviderSpy).not.toHaveBeenCalled()

    // 3. Switch Mera card (tab 1) to "Simulate Probe" and click tamper probe
    fireEvent.click(simulateTabs[1])
    const meraTamperBtn = await screen.findByRole('button', { name: /simulate memory tamper probe/i })
    fireEvent.click(meraTamperBtn)
    expect(switchChainSpy).not.toHaveBeenCalled()
    expect(getEthereumProviderSpy).not.toHaveBeenCalled()

    const meraValidBtn = screen.getByRole('button', { name: /simulated call \(demo only\)/i })
    fireEvent.click(meraValidBtn)
    expect(switchChainSpy).not.toHaveBeenCalled()
    expect(getEthereumProviderSpy).not.toHaveBeenCalled()

    // 4. Switch Passport card (tab 2) to "Simulate Probe" and click check probes
    fireEvent.click(simulateTabs[2])
    const passportRevokeBtn = await screen.findByRole('button', { name: /check test id revoked-agent-01/i })
    fireEvent.click(passportRevokeBtn)
    expect(switchChainSpy).not.toHaveBeenCalled()
    expect(getEthereumProviderSpy).not.toHaveBeenCalled()

    const passportActiveBtn = screen.getByRole('button', { name: /simulate valid identity check/i })
    fireEvent.click(passportActiveBtn)
    expect(switchChainSpy).not.toHaveBeenCalled()
    expect(getEthereumProviderSpy).not.toHaveBeenCalled()

    // Across all probe button executions:
    expect(switchChainSpy).toHaveBeenCalledTimes(0)
    expect(getEthereumProviderSpy).toHaveBeenCalledTimes(0)
  })
})
