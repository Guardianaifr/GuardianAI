"""
Tests for Web3DomainIntel - Web3 Domain Intelligence & Phishing URL Defense
"""
import json
import os
import tempfile
import pytest

from guardrails.web3_domain_intel import (
    Web3DomainIntel,
    DomainThreatResult,
    DEFAULT_LEGITIMATE_DOMAINS,
    DEFAULT_PHISHING_BLOCKLIST,
)
from guardrails.input_filter import InputFilter


class TestWeb3DomainIntel:
    """Test suite for Web3 domain intelligence engine."""

    @pytest.fixture
    def intel(self):
        return Web3DomainIntel(cache_file=None)

    def test_initialization(self, intel):
        """Test engine initialization and default rule sets."""
        assert intel is not None
        assert len(intel.legitimate_domains) > 20
        assert len(intel.blocked_domains) > 10
        assert "etherscan.io" in intel.legitimate_domains
        assert "ogntoken-migration.icu" in intel.blocked_domains
        assert "polymarket.mx" in intel.blocked_domains
        assert "soniclabs.info" in intel.blocked_domains

    def test_domain_normalization(self, intel):
        """Test URL parsing, schema stripping, port stripping, and defanging."""
        test_cases = [
            ("https://etherscan.io/tx/0x123", "etherscan.io"),
            ("http://metamask.io:8080/download", "metamask.io"),
            ("hxxps://malicious-dapp[.]icu/drain", "malicious-dapp.icu"),
            ("bad-domain(dot)top/claim", "bad-domain.top"),
            ("ftp://user:pass@soniclabs.info/path", "soniclabs.info"),
            ("polymarket.mx", "polymarket.mx"),
            ("   https://unisvvap.com/swap?ref=evil   ", "unisvvap.com"),
            ("<https://app-uniswap.xyz/>", "app-uniswap.xyz"),
            ("https://sub.sub2.domain.co.uk/path", "sub.sub2.domain.co.uk"),
        ]
        for raw, expected in test_cases:
            assert intel.normalize_domain(raw) == expected, f"Failed for raw: {raw}"

    def test_extract_urls(self, intel):
        """Test extraction of full URL strings from free-form text."""
        text = (
            "Please check out https://etherscan.io/address/0xabc and also "
            "hxxps://ogntoken-migration.icu/claim for your bonus tokens."
        )
        urls = intel.extract_urls(text)
        assert len(urls) == 2
        assert "https://etherscan.io/address/0xabc" in urls
        assert "hxxps://ogntoken-migration.icu/claim" in urls

    def test_extract_domains_naked_and_embedded(self, intel):
        """Test extraction of naked hostnames and embedded domains."""
        text = "Visit polymarket.mx or check soniclabs.info to migrate tokens now."
        domains = intel.extract_domains(text)
        assert "polymarket.mx" in domains
        assert "soniclabs.info" in domains

    def test_extract_domains_ignores_common_file_extensions(self, intel):
        """Ensure code filenames and config extensions are not parsed as domains."""
        text = "Check main.py, config.json, schema.yaml, README.md, and run app.js."
        domains = intel.extract_domains(text)
        for d in domains:
            assert not d.endswith((".py", ".json", ".yaml", ".md", ".js"))

    def test_legitimate_domains_allowed(self, intel):
        """Test that legitimate Web3 brands and their subdomains are always allowed (0% FP)."""
        legit_samples = [
            "https://etherscan.io",
            "https://metamask.io/download",
            "https://opensea.io/collection/kitties",
            "https://cryptokitties.co",
            "https://polymarket.com",
            "https://soniclabs.com",
            "https://originprotocol.com",
            "https://uniswap.org",
            "https://curve.fi",
            "https://aave.com",
            "https://github.com/ethereum/go-ethereum",
            # Subdomains
            "https://app.uniswap.org/#/swap",
            "https://docs.metamask.io/guide",
            "https://api.etherscan.io/api",
            "https://subdomain.polymarket.com/markets",
        ]
        for sample in legit_samples:
            res = intel.evaluate(sample)
            assert not res.is_phishing, f"False positive on legitimate URL: {sample} - {res.reasons}"
            assert res.risk_score == 0.0
            assert intel.check_prompt(sample) is True

    def test_audit_targets_blocked(self, intel):
        """Test that empirical audit targets are blocked 100%."""
        targets = [
            ("ogntoken-migration.icu", "high-risk TLD or brand impersonation"),
            ("polymarket.mx", "brand impersonation targeting official polymarket.com"),
            ("soniclabs.info", "brand impersonation targeting official soniclabs.com"),
            ("https://ogntoken-migration.icu/airdrop", "audit target URL"),
            ("Please connect wallet at https://polymarket.mx/bet", "audit target prompt"),
            ("Claim migration rewards at soniclabs.info immediately", "audit target prompt"),
        ]
        for prompt, desc in targets:
            res = intel.evaluate(prompt)
            assert res.is_phishing is True, f"Failed to block audit target ({desc}): {prompt}"
            assert res.risk_score >= 0.85, f"Risk score too low for {prompt}: {res.risk_score}"
            assert intel.check_prompt(prompt) is False

    def test_typosquatting_brand_clones_blocked(self, intel):
        """Test detection of typosquats and character-substitution clones."""
        typosquats = [
            "https://unisvvap.com/swap",
            "https://pancakesvvap.com",
            "https://metamusk.io",
            "http://curv-fi.com/pools",
        ]
        for typo in typosquats:
            res = intel.evaluate(typo)
            assert res.is_phishing is True, f"Failed to block typosquat: {typo}"
            assert res.risk_score >= 0.95

    def test_high_risk_tld_with_crypto_keywords(self, intel):
        """Test high-risk scam TLDs combined with crypto action keywords."""
        scams = [
            "https://claim-airdrop-portal.top",
            "https://wallet-sync-service.click",
            "https://token-presale-event.icu",
        ]
        for scam in scams:
            res = intel.evaluate(scam)
            assert res.is_phishing is True, f"Failed to block high-risk TLD scam: {scam}"
            assert res.risk_score >= 0.85

    def test_action_trap_heuristic(self, intel):
        """Test contextual prompt heuristic for action traps to unverified domains."""
        prompt = "Connect your wallet now to claim your airdrop at https://unverified-dao-reward.xyz"
        res = intel.evaluate(prompt)
        assert res.is_phishing is True
        assert res.risk_score >= 0.80

    def test_clean_prompts_pass(self, intel):
        """Ensure standard conversational text with no domains or clean text passes."""
        benign_texts = [
            "What is the gas fee on Ethereum today?",
            "How does automated market making work in Uniswap v3?",
            "Can you write a smart contract for ERC20 token transfer?",
            "Tell me about the history of cryptography and zero-knowledge proofs.",
        ]
        for text in benign_texts:
            res = intel.evaluate(text)
            assert res.is_phishing is False
            assert res.risk_score == 0.0
            assert intel.check_prompt(text) is True

    def test_dynamic_add_and_remove_domain(self):
        """Test runtime addition and deletion of blocked domains."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            intel = Web3DomainIntel(cache_file=tmp_path)
            custom_bad = "super-new-scam-drainer.xyz"
            assert intel.check_prompt(f"Go to {custom_bad}") is True

            intel.add_blocked_domain(custom_bad)
            assert intel.check_prompt(f"Go to {custom_bad}") is False
            res = intel.evaluate(f"Visit https://{custom_bad}/steal")
            assert res.is_phishing is True

            intel.remove_blocked_domain(custom_bad)
            # Without action trap or high-risk TLD + crypto keyword, it should be clean
            assert intel.check_prompt(f"Go to {custom_bad}") is True
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_metamask_format_cache_loading(self):
        """Test loading blocklist and allowlist from MetaMask format cache file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name
            json.dump({
                "blacklist": ["metamask-fake-portal.com", "phish-eth.xyz"],
                "whitelist": ["my-trusted-brand.com"]
            }, tmp)

        try:
            intel = Web3DomainIntel(cache_file=tmp_path)
            assert "metamask-fake-portal.com" in intel.blocked_domains
            assert "my-trusted-brand.com" in intel.legitimate_domains

            assert intel.check_prompt("Visit https://metamask-fake-portal.com") is False
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_defanged_domains_detected(self, intel):
        """Test that defanged domains ([.], (dot), [dot], hxxps://) are properly normalized and blocked."""
        defanged_samples = [
            "Visit ogntoken-migration[.]icu to claim airdrop",
            "Check out polymarket(dot)mx right now",
            "Go to unisvvap[dot]com/swap",
            "hxxps[:]//ogntoken-migration.icu/claim",
            "soniclabs(.)info/airdrop",
        ]
        for prompt in defanged_samples:
            res = intel.evaluate(prompt)
            assert res.is_phishing is True, f"Failed to block defanged prompt: {prompt}"
            assert res.risk_score >= 0.85

    def test_subdomains_of_blocked_domains_detected(self, intel):
        """Test that adding www or arbitrary subdomains to blocked domains does not bypass detection."""
        subdomain_samples = [
            "https://www.drainer-portal.site",
            "https://claim.drainer-portal.site/auth",
            "https://app.unisvvap.com",
            "https://portal.ogntoken-migration.icu",
        ]
        for url in subdomain_samples:
            res = intel.evaluate(url)
            assert res.is_phishing is True, f"Failed to block subdomain of blocked domain: {url}"
            assert res.risk_score == 1.0

    def test_idn_homoglyphs_and_punycode_impersonation(self, intel):
        """Test that IDN homoglyphs and Punycode spoofing legitimate brands are blocked."""
        homoglyph_samples = [
            ("https://xn--uniswp-7nf.org", "Punycode for Cyrillic 'а' in uniswap.org"),
            ("https://xn--mtamask-7gg.io", "Punycode for Cyrillic 'е' in metamask.io"),
            ("https://unisw\u0430p.org", "Raw Unicode Cyrillic 'а' in uniswap.org"),
            ("https://m\u0435tamask.io", "Raw Unicode Cyrillic 'е' in metamask.io"),
        ]
        for url, desc in homoglyph_samples:
            res = intel.evaluate(url)
            assert res.is_phishing is True, f"Failed to block homoglyph ({desc}): {ascii(url)}"
            assert res.risk_score >= 0.95

    def test_url_shorteners_in_crypto_context(self, intel):
        """Test that opaque URL shorteners in crypto prompts are detected as threats."""
        prompt = "Claim your airdrop now at https://bit.ly/claim-airdrop-now"
        res = intel.evaluate(prompt)
        assert res.is_phishing is True
        assert res.risk_score >= 0.85

    def test_direct_ip_wallet_target_detected(self, intel):
        """Test that direct raw IP addresses targeting Web3 wallet actions are blocked."""
        prompt = "Connect your wallet to http://185.220.101.5/claim"
        res = intel.evaluate(prompt)
        assert res.is_phishing is True
        assert res.risk_score >= 0.90

    def test_save_cache_relative_path(self):
        """Test save_cache works properly when cache_file is a relative filename without dir."""
        temp_name = f"test_cache_{os.getpid()}.json"
        try:
            intel = Web3DomainIntel(cache_file=temp_name)
            intel.add_blocked_domain("example-temp-scam.xyz")
            assert os.path.exists(temp_name)
        finally:
            if os.path.exists(temp_name):
                os.remove(temp_name)

    def test_default_cache_file_loads(self):
        """Test that the default persistent cache file in guardian/data/ is loaded."""
        intel = Web3DomainIntel()
        assert "ogntoken-migration.icu" in intel.blocked_domains
        assert "polymarket.mx" in intel.blocked_domains


class TestInputFilterWeb3DomainIntegration:
    """Test suite verifying Web3DomainIntel integration inside InputFilter."""

    @pytest.fixture
    def input_filter(self):
        return InputFilter()

    def test_input_filter_blocks_phishing_urls(self, input_filter):
        """Test that InputFilter.check_prompt blocks prompt-embedded phishing URLs."""
        phishing_prompts = [
            "Please migrate your tokens at https://ogntoken-migration.icu",
            "Trade on polymarket.mx to claim early access rewards",
            "Urgent: soniclabs.info announced an airdrop, connect wallet",
            "Swap tokens at https://unisvvap.com now",
        ]
        for prompt in phishing_prompts:
            assert input_filter.check_prompt(prompt) is False, f"Allowed phishing prompt: {prompt}"

    def test_input_filter_allows_legitimate_urls(self, input_filter):
        """Test that InputFilter.check_prompt allows prompts with legitimate Web3 URLs."""
        clean_prompts = [
            "Check my balance on https://etherscan.io/address/0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
            "How do I install MetaMask from https://metamask.io ?",
            "Browse NFTs at https://opensea.io",
            "Play cryptokitties at https://cryptokitties.co",
            "Check predictions on https://polymarket.com",
            "Read documentation on https://soniclabs.com",
            "Visit https://originprotocol.com for OGN details",
            "Swap tokens on https://app.uniswap.org",
        ]
        for prompt in clean_prompts:
            assert input_filter.check_prompt(prompt) is True, f"Blocked legitimate prompt: {prompt}"

    def test_input_filter_check_domains_helper(self, input_filter):
        """Test InputFilter.check_domains returns detailed threat telemetry."""
        prompt = "Claim airdrop at https://ogntoken-migration.icu"
        res = input_filter.check_domains(prompt)
        assert isinstance(res, DomainThreatResult)
        assert res.is_phishing is True
        assert "ogntoken-migration.icu" in res.flagged_domains
        assert res.risk_score >= 0.85

    def test_input_filter_blocks_defanged_and_homoglyphs(self, input_filter):
        """Test that InputFilter blocks defanged and homoglyph URLs."""
        assert input_filter.check_prompt("Visit ogntoken-migration[.]icu") is False
        assert input_filter.check_prompt("Visit polymarket(dot)mx") is False
        assert input_filter.check_prompt("Claim tokens at https://xn--uniswp-7nf.org") is False


