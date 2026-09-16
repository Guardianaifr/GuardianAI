"""Brain orchestrator: CyberOps intel + Red probe + Blue adapt + Purple heal."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import threading
import time
from typing import Any
import logging

logger = logging.getLogger(__name__)

try:
    from guardian.brain.blue_adapt import BlueAdaptAgent
    from guardian.brain.cyberops_intel import CyberOpsIntel
    from guardian.brain.purple_heal import PurpleHealAgent
    from guardian.brain.red_probe import RedProbeAgent
    from guardian.security.idp_revocation import IdpRevocationClient, build_subject
    from guardian.security.purple_governance import PurplePatchGovernance
except ImportError:
    from brain.blue_adapt import BlueAdaptAgent
    from brain.cyberops_intel import CyberOpsIntel
    from brain.purple_heal import PurpleHealAgent
    from brain.red_probe import RedProbeAgent
    from security.idp_revocation import IdpRevocationClient, build_subject
    from security.purple_governance import PurplePatchGovernance


class CyberBrain:
    def __init__(self, config: dict[str, Any], base_dir: Path, input_filter, ai_firewall=None, threat_feed=None):
        brain_cfg = config.get("brain", {}) or {}
        self.enabled = bool(brain_cfg.get("enabled", False))
        self.interval = int(brain_cfg.get("red_probe_interval_seconds", 1800))
        self.auto_heal = bool(brain_cfg.get("auto_heal", True))
        self.auto_patch_firewall = bool(brain_cfg.get("auto_patch_firewall_vectors", True))
        escalation_threshold = int(brain_cfg.get("blue_escalation_threshold", 6))
        strict_score_threshold = float(brain_cfg.get("blue_strict_score_threshold", 0.5))
        honeypot_score_threshold = float(brain_cfg.get("blue_honeypot_score_threshold", 0.6))
        revoke_score_threshold = float(brain_cfg.get("blue_revoke_score_threshold", 0.8))
        profile_ttl_seconds = int(brain_cfg.get("blue_profile_ttl_seconds", 3600))
        max_sessions = int(brain_cfg.get("blue_max_sessions", 5000))
        cleanup_interval_seconds = int(brain_cfg.get("blue_cleanup_interval_seconds", 60))
        # FEAT-BLUE-ADVANCED: velocity + cooldown config
        velocity_window_sec = float(brain_cfg.get("blue_velocity_window_sec", 10.0))
        velocity_max_rps = float(brain_cfg.get("blue_velocity_max_rps", 5.0))
        cooldown_base_seconds = float(brain_cfg.get("blue_cooldown_base_seconds", 5.0))
        cooldown_max_seconds = float(brain_cfg.get("blue_cooldown_max_seconds", 300.0))
        cooldown_multiplier = float(brain_cfg.get("blue_cooldown_multiplier", 2.0))
        self.external_revoke_enabled = bool((brain_cfg.get("external_jwt_revocation") or {}).get("enabled", False))
        revoke_cfg = brain_cfg.get("external_jwt_revocation") or {}

        intel_file = brain_cfg.get("intel_file", "config/cyberops_intel.json")
        vectors_file = brain_cfg.get("probe_vectors_file", "config/brain_red_vectors.yaml")
        heal_store = brain_cfg.get("heal_store_file", "config/brain_hotfix_patterns.json")
        jailbreak_vectors_file = brain_cfg.get("jailbreak_vectors_file", "config/jailbreak_vectors.yaml")
        purple_gov_cfg = brain_cfg.get("purple_governance", {}) or {}
        purple_approval_file = purple_gov_cfg.get("approval_file", "config/purple_patch_approval.yaml")
        purple_evidence_file = purple_gov_cfg.get("evidence_file", "artifacts/evidence/purple_patch_governance.jsonl")
        purple_staging_file = purple_gov_cfg.get("staging_file", "config/purple_patch_staging.yaml")
        # FEAT-RED-LLM: separate red-team LLM target (never the production upstream)
        red_probe_target_url = str(brain_cfg.get("red_probe_target_url", "") or "")
        red_probe_upstream_key = str(brain_cfg.get("red_probe_upstream_key", "") or "")
        red_probe_timeout = float(brain_cfg.get("red_probe_timeout", 15.0))

        self.input_filter = input_filter
        self.ai_firewall = ai_firewall
        self.threat_feed = threat_feed   # ThreatFeed instance for brain auto-patch
        self.jailbreak_vectors_file = self._resolve(base_dir, jailbreak_vectors_file)
        self.intel = CyberOpsIntel(self._resolve(base_dir, intel_file))
        self.red = RedProbeAgent(
            self._resolve(base_dir, vectors_file),
            intel=self.intel,
            target_url=red_probe_target_url,
            upstream_key=red_probe_upstream_key,
            upstream_timeout=red_probe_timeout,
        )
        self.blue = BlueAdaptAgent(
            escalation_threshold=escalation_threshold,
            strict_score_threshold=strict_score_threshold,
            honeypot_score_threshold=honeypot_score_threshold,
            revoke_score_threshold=revoke_score_threshold,
            profile_ttl_seconds=profile_ttl_seconds,
            max_sessions=max_sessions,
            cleanup_interval_seconds=cleanup_interval_seconds,
            # FEAT-BLUE-ADVANCED
            velocity_window_sec=velocity_window_sec,
            velocity_max_rps=velocity_max_rps,
            cooldown_base_seconds=cooldown_base_seconds,
            cooldown_max_seconds=cooldown_max_seconds,
            cooldown_multiplier=cooldown_multiplier,
        )
        self.purple = PurpleHealAgent(self._resolve(base_dir, heal_store))
        self.idp_revocation = IdpRevocationClient(revoke_cfg)
        self.purple_governance = PurplePatchGovernance(
            mode=str(purple_gov_cfg.get("mode", "audit")),
            approval_path=self._resolve(base_dir, purple_approval_file),
            evidence_path=self._resolve(base_dir, purple_evidence_file),
            staging_path=self._resolve(base_dir, purple_staging_file),
        )
        self._session_tokens: dict[str, str] = {}

        self.last_probe_findings: list[dict] = []
        self.last_applied_patterns: list[str] = []

        self._stop = threading.Event()
        self._thread = None

    def _resolve(self, base_dir: Path, maybe_relative: str | None) -> Path | None:
        if not maybe_relative:
            return None
        path = Path(maybe_relative)
        if path.is_absolute():
            return path
        return base_dir / str(path)

    def start(self):
        if not self.enabled or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=3)
        self._thread = None

    def _loop(self):
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.interval)

    def run_once(self):
        try:
            from guardian.brain.red_probe import OUTCOME_FULL_BYPASS
        except ImportError:
            try:
                from .red_probe import OUTCOME_FULL_BYPASS
            except ImportError:
                from brain.red_probe import OUTCOME_FULL_BYPASS
        findings = self.red.run_probe_cycle(self.input_filter)
        self.last_probe_findings = [{
            "payload": f.payload,
            "severity": f.severity,
            "reason": f.reason,
            "outcome": f.outcome,
            "model_response": f.model_response[:200] if f.model_response else "",
            "filter_allowed": f.filter_allowed,
        } for f in findings]
        # Only full_bypass findings indicate a real end-to-end gap worth auto-patching.
        # filter_bypass_model_refused and filter_bypass_only are informational only.
        heal_findings = [f for f in findings if f.outcome == OUTCOME_FULL_BYPASS]
        if self.auto_heal and heal_findings:
            patterns = self.purple.build_hotfix_patterns(heal_findings)
            allowed, decision = self.purple_governance.evaluate(patterns, heal_findings)
            # Only apply patterns that passed the regression safety gate
            clean_patterns = self.purple_governance.get_clean_patterns(decision)
            applied_count = 0
            firewall_patched_count = 0
            threat_feed_patched = 0
            if allowed:
                applied_count = self.purple.apply_hotfixes(self.input_filter, clean_patterns)
                self.last_applied_patterns = clean_patterns if applied_count else []
                if self.auto_patch_firewall:
                    firewall_patched_count = self.purple.patch_firewall_vectors(
                        heal_findings,
                        self.jailbreak_vectors_file,
                        self.ai_firewall,
                    )
                # ── Brain → ThreatFeed auto-patch ──────────────────────
                if self.threat_feed and clean_patterns:
                    for pat in clean_patterns:
                        if self.threat_feed.add_pattern(
                            pat,
                            severity="high",
                            category="brain_autopatch",
                            source="brain",
                            ttl_days=7,
                        ):
                            threat_feed_patched += 1
                    if threat_feed_patched:
                        logger.info(f"[Brain] Auto-patched {threat_feed_patched} patterns to ThreatFeed")
            else:
                self.last_applied_patterns = []
            self.purple_governance.emit_evidence(
                decision=decision,
                applied_count=applied_count,
                firewall_patched_count=firewall_patched_count,
            )
        else:
            self.last_applied_patterns = []

        # ── Hardening cycle checks ────────────────────────────────────────────
        # check_grounded_response and check_excessive_agency run on every probe
        # cycle. They inspect the probe findings themselves (not live user traffic)
        # as a canary: the probe response text and action strings are the closest
        # approximation to "model output under adversarial conditions" we have in
        # the brain loop.  scan_training_data_for_poisoning is offline-only (no
        # live training-data path exists in the current runtime).
        try:
            try:
                from guardian.security.hardening_checks import (
                    check_excessive_agency,
                    check_grounded_response,
                )
            except ImportError:
                from security.hardening_checks import (
                    check_excessive_agency,
                    check_grounded_response,
                )

            _hardening_findings = []
            for _finding in self.last_probe_findings:
                # Each probe finding has a "payload" field which we use as the vector
                # and a "reason" field. We pass payload to the checks.
                _payload = _finding.get("payload", "") or ""
                if _payload:
                    _hardening_findings.extend(
                        check_grounded_response(_payload, [], min_support_ratio=0.2)
                    )
                    _hardening_findings.extend(
                        check_excessive_agency(_payload, confirmed=False)
                    )
            for _hf in _hardening_findings:
                logger.warning(
                    f"[HardeningCycle] {_hf.category}/{_hf.location}: {_hf.detail}"
                )
        except Exception as _hc_err:
            logger.debug(f"[HardeningCycle] Check skipped: {_hc_err}")

    def observe_prompt(self, session_id: str, prompt: str, blocked: bool):
        was_revoked = self.blue.is_revoked(session_id)
        score = self.intel.score_prompt(prompt)
        self.blue.observe_prompt(session_id, prompt, blocked=blocked, intel_score=score)
        if not was_revoked and self.blue.is_revoked(session_id):
            self.enforce_revocation(session_id, reason="adaptive_threshold_exceeded")

    def analyze_request(self, session_id: str, prompt: str, blocked: bool) -> dict[str, Any]:
        was_revoked = self.blue.is_revoked(session_id)
        score = self.intel.score_prompt(prompt)
        result = self.blue.analyze_request(session_id, prompt, blocked=blocked, intel_score=score)
        self._cleanup_session_tokens()
        if not was_revoked and result.get("action") == "revoke":
            self.enforce_revocation(session_id, reason="adaptive_threshold_exceeded")
        return result

    def recommend_mode(self, session_id: str, default_mode: str) -> str:
        return self.blue.recommend_mode(session_id, default_mode=default_mode)

    def should_revoke_session(self, session_id: str) -> bool:
        return self.blue.is_revoked(session_id) or self.blue.should_revoke_session(session_id)

    def session_action(self, session_id: str) -> str:
        return self.blue.get_action(session_id)

    def get_cooldown_seconds(self, session_id: str) -> int:
        """Return Retry-After seconds for a session currently in cooldown."""
        return self.blue.get_cooldown_seconds_remaining(session_id)

    def enforce_revocation(self, session_id: str, reason: str = "adaptive_security"):
        if not self.blue.is_revoked(session_id):
            self.blue.mark_revoked(session_id)
        if self.external_revoke_enabled:
            raw_token = self._session_tokens.get(session_id)
            subject = build_subject(
                session_id=session_id,
                raw_jwt=raw_token,
                include_raw_jwt=self.idp_revocation.include_raw_jwt,
            )
            self.idp_revocation.revoke(subject, reason=reason)

    def bind_session_identity(self, session_id: str, raw_bearer_token: str | None):
        if not session_id:
            return
        # Ensure session is represented so token binding survives cleanup windows.
        profile = self.blue.profiles[session_id]
        now = time.time()
        if profile.first_seen_ts == 0.0:
            profile.first_seen_ts = now
        profile.last_seen_ts = now
        if raw_bearer_token:
            self._session_tokens[session_id] = raw_bearer_token
        self._cleanup_session_tokens()

    def _cleanup_session_tokens(self):
        active_sessions = set(self.blue.profiles.keys())
        for sid in list(self._session_tokens.keys()):
            if sid not in active_sessions:
                self._session_tokens.pop(sid, None)

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "last_probe_findings": list(self.last_probe_findings),
            "last_applied_patterns": list(self.last_applied_patterns),
            "intel": self.intel.as_dict(),
            "purple": self.purple.snapshot(),
        }
