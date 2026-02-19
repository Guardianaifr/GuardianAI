import json
import os
import yaml
import logging
from typing import Dict, Any

logger = logging.getLogger("GuardianAI.adversarial_trainer")

class AdversarialTrainer:
    """
    Automates the 'Self-Correction' loop by converting blocked prompts 
    into semantic vectors for the AI Firewall.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.blocked_log_path = os.path.join(base_dir, "data", "blocked_prompts.json")
        self.vector_path = os.path.join(base_dir, "config", "jailbreak_vectors.yaml")

    def update_vectors(self) -> int:
        """Reads blocked prompts and appends them to jailbreak_vectors.yaml."""
        if not os.path.exists(self.blocked_log_path):
            return 0

        try:
            with open(self.blocked_log_path, "r", encoding="utf-8") as f:
                blocked_prompts = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to read blocked prompts: {e}")
            return 0

        if not blocked_prompts:
            return 0

        # Read existing vectors
        existing_texts = set()
        data = {'vectors': []}
        if os.path.exists(self.vector_path):
            try:
                with open(self.vector_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {'vectors': []}
                    for v in data.get('vectors', []):
                        existing_texts.add(v['text'].lower())
            except Exception as e:
                logger.warning(f"Failed to read jailbreak_vectors.yaml: {e}")

        new_count = 0
        for prompt in blocked_prompts:
            if prompt.lower() not in existing_texts:
                data['vectors'].append({
                    'text': prompt,
                    'category': 'adversarial'
                })
                existing_texts.add(prompt.lower())
                new_count += 1

        if new_count > 0:
            try:
                with open(self.vector_path, "w", encoding="utf-8") as f:
                    yaml.dump(data, f, sort_keys=False, indent=2)
                logger.info(f"🚀 Adversarial Self-Correction: Added {new_count} new patterns to firewall.")
            except Exception as e:
                logger.error(f"Failed to save updated vectors: {e}")
                return 0

        return new_count
