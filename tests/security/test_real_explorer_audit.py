import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer

class TestRealExplorerOnChainAudit:
    """
    Tests the SmartContractAnalyzer's dynamic on-chain explorer fetching capability.
    Instead of using raw GitHub links, this queries block explorer networks (via Sourcify)
    using contract addresses to fetch verified source codes dynamically and audit them.
    """

    def test_onchain_ethereum_uniswap_router(self):
        """
        Fetches the Uniswap V2 Router02 contract from the Ethereum network (on-chain)
        and verifies the static analysis is performed successfully.
        """
        # Uniswap V2 Router02 address on Ethereum
        router_address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        
        try:
            analyzer = SmartContractAnalyzer.from_onchain(
                contract_address=router_address,
                chain="ethereum"
            )
        except Exception as e:
            pytest.skip(f"Failed to fetch Uniswap Router from block explorer network (Sourcify): {e}")
            
        assert analyzer.contract_name == "UniswapV2Router02"
        assert analyzer.contract_address.lower() == router_address.lower()
        assert analyzer.chain == "ethereum"
        
        # Run analysis
        result = analyzer.analyze()
        assert result.vulnerabilities_found > 0
        assert any(v["rule_id"] == "SC-061" for v in result.vulnerabilities) # Oracle manipulation

    def test_onchain_base_usdc(self):
        """
        Fetches the USDC Token contract from the Base network (on-chain)
        and verifies the analyzer parses it.
        """
        # USDC address on Base
        base_usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bda02913"
        
        try:
            analyzer = SmartContractAnalyzer.from_onchain(
                contract_address=base_usdc,
                chain="base"
            )
        except Exception as e:
            pytest.skip(f"Failed to fetch Base USDC from block explorer network (Sourcify): {e}")
            
        assert analyzer.contract_name in ["AdminUpgradeabilityProxy", "FiatToken", "USDC"]
        assert analyzer.contract_address.lower() == base_usdc.lower()
        assert analyzer.chain == "base"
        
        # Analyze should run fine
        result = analyzer.analyze()
        assert isinstance(result.score, float)

    def test_onchain_invalid_address_error(self):
        """
        Verifies that passing an invalid EVM address format raises a ValueError.
        """
        with pytest.raises(ValueError, match="Invalid EVM contract address"):
            SmartContractAnalyzer.from_onchain(
                contract_address="0xInvalidAddressLength",
                chain="ethereum"
            )
            
    def test_onchain_unsupported_chain_error(self):
        """
        Verifies that passing an unsupported chain name raises a ValueError.
        """
        with pytest.raises(ValueError, match="Unsupported chain"):
            SmartContractAnalyzer.from_onchain(
                contract_address="0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
                chain="unsupported_chain_name"
            )
