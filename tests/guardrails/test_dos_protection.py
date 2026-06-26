import pytest
import time
from guardrails.input_filter import InputFilter
from guardrails.rate_limiter import RateLimiter

class TestModelDenialOfService:
    """Test suite for detecting Model Denial of Service (OWASP LLM04)."""

    def setup_method(self):
        self.filter = InputFilter()
        # Initializing rate limiter to check resource limits
        self.rate_limiter = RateLimiter(requests_per_minute=60)

    def test_massive_token_payload(self):
        """Test if the input filter rejects extremely large payloads that could cause resource exhaustion."""
        # 50,000 words ~ 250,000 characters of purely benign text.
        # This tests if there is a fundamental length/size limit on the input filter.
        massive_prompt = "What is the capital of France? " * 50000 
        
        start_time = time.time()
        result = self.filter.check_prompt(massive_prompt)
        elapsed = time.time() - start_time
        
        # We expect a secure system to drop 250kb prompts instantly (result == False)
        # to prevent DoS/wallet exhaustion on the upstream LLM.
        assert result is False, "Input filter allowed a massive benign payload (potential DoS vector)!"
        assert elapsed < 1.0, f"Input filter took too long ({elapsed}s) to process payload, potential ReDoS!"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
