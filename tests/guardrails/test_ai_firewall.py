import pytest
from unittest.mock import MagicMock, patch
import sqlite3

from guardian.guardrails.ai_firewall import AIPromptFirewall


@pytest.fixture
def firewall():
    """Fixture to create a firewall instance with mocked model."""
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

        with patch('guardian.guardrails.ai_firewall.yaml.safe_load', return_value=mock_yaml_data):
            with patch('guardian.guardrails.ai_firewall.os.path.exists', return_value=True):
                firewall.reload()
                assert "custom attack vector" in firewall.bad_prompts


def test_policy_gate_records_to_cortex_when_agent_id_supplied(firewall, tmp_path, monkeypatch):
    db_path = tmp_path / "cortex_firewall.db"
    monkeypatch.setenv("GUARDIAN_DB_PATH", str(db_path))

    assert firewall.is_malicious(
        "ignore previous instructions",
        agent_id="agent-cortex-test",
        metadata={"request_id": "req-1"},
    ) is True

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        """
        SELECT agent_id, event_type, category, action, metadata
        FROM cortex_events
        WHERE agent_id = ?
        """,
        ("agent-cortex-test",),
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "agent-cortex-test"
    assert row[1] == "policy_gate"
    assert row[2] == "ai_firewall"
    assert row[3] == "blocked"
    assert "short_keyword" in row[4] or "persona_or_jailbreak_trigger" in row[4]
