import pytest
from unittest.mock import MagicMock, patch
import logging
import sys

# --- MOCKING STRATEGY ---
# We must mock sentence_transformers, sklearn, and numpy BEFORE they are imported 
# by the module under test. This is crucial because standard installs might not 
# have these heavy ML libraries.

# Configure mocks manually in sys.modules to persist for all tests
mock_sentence_transformers = MagicMock()
mock_sklearn_metrics = MagicMock()
mock_numpy = MagicMock()

# Configure numpy mock
def side_effect_max(arg):
    try:
        if isinstance(arg, (list, tuple)):
            res = max(arg) if arg else 0.0
            return res
        return 0.0 
    except:
        return 0.0

mock_numpy.max.side_effect = side_effect_max

sys.modules['sentence_transformers'] = mock_sentence_transformers
sys.modules['sklearn.metrics.pairwise'] = mock_sklearn_metrics
sys.modules['numpy'] = mock_numpy

# Import module under test (will pick up our mocks)
from guardian.guardrails.ai_firewall import AIPromptFirewall

@pytest.fixture
def firewall():
    """Fixture to create a firewall instance with mocked model."""
    # We patch the class where it is imported in the module
    with patch('guardian.guardrails.ai_firewall.SentenceTransformer') as MockTransformer:
        mock_model_instance = MagicMock()
        mock_model_instance.encode.return_value = [[0.1, 0.2, 0.3]]
        MockTransformer.return_value = mock_model_instance
        
        with patch('os.path.exists', return_value=False):
            fw = AIPromptFirewall()
            fw.enabled = True 
            fw.model = mock_model_instance
            fw.bad_embeddings = [[0.1, 0.2, 0.3]] 
            return fw

def test_initialization(firewall):
    assert firewall.enabled is True
    assert "ignore previous instructions" in firewall.bad_prompts
    assert "cat /etc/passwd" in firewall.bad_prompts

def test_keyword_block_exact_match(firewall):
    assert firewall.is_malicious("ignore previous instructions") is True
    assert firewall.is_malicious("cat /etc/passwd") is True

def test_keyword_block_case_insensitive(firewall):
    assert firewall.is_malicious("IGNORE PREVIOUS INSTRUCTIONS") is True

def test_ml_block_mocked(firewall):
    """Test ML-based blocking with mocked similarity."""
    with patch('guardian.guardrails.ai_firewall.cosine_similarity') as mock_cosine:
        mock_cosine.return_value = [[0.95]]
        assert firewall.is_malicious("some creative jailbreak attempt", mode="balanced") is True

def test_ml_allow_mocked(firewall):
    """Test ML-based allowing with mocked similarity."""
    with patch('guardian.guardrails.ai_firewall.cosine_similarity') as mock_cosine:
        mock_cosine.return_value = [[0.1]]
        assert firewall.is_malicious("hello, how are you?", mode="balanced") is False

def test_modes_sensitivity(firewall):
    """Test that different modes have different thresholds."""
    with patch('guardian.guardrails.ai_firewall.cosine_similarity') as mock_cosine:
        mock_cosine.return_value = [[0.60]]
        
        # Strict mode (threshold 0.45) -> BLOCKED
        assert firewall.is_malicious("fuzzy prompt", mode="strict") is True
        
        # Balanced mode (threshold 0.55) -> BLOCKED
        assert firewall.is_malicious("fuzzy prompt", mode="balanced") is True
        
        # Lenient mode (threshold 0.70) -> ALLOWED
        assert firewall.is_malicious("fuzzy prompt", mode="lenient") is False

def test_empty_prompt_is_safe(firewall):
    assert firewall.is_malicious("") is False
    assert firewall.is_malicious(None) is False

def test_exception_handling_in_ml_inference(firewall):
    firewall.model.encode.side_effect = Exception("Model Crash")
    assert firewall.is_malicious("safe prompt") is False

def test_reload_adds_custom_vectors(firewall):
    """Test the reload functionality."""
    mock_yaml_data = {'vectors': [{'text': 'custom attack vector'}]}
    
    with patch('builtins.open', new_callable=MagicMock) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        file_handle.read.return_value = "vectors:\n  - text: custom attack vector"
        
        # Now patching yaml.safe_load should work since imports are consistent
        with patch('guardian.guardrails.ai_firewall.yaml.safe_load', return_value=mock_yaml_data):
            with patch('guardian.guardrails.ai_firewall.os.path.exists', return_value=True):
                firewall.reload()
                
                assert "custom attack vector" in firewall.bad_prompts
