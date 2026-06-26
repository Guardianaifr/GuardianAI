"""
GuardianAI Scan Notification System.
Sends alerts to Slack, Discord, and generic webhooks when scans complete.
"""
import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("guardian.audit.notifications")


class ScanNotifier:
    """Multi-channel notification dispatcher for scan results."""

    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        generic_webhooks: Optional[List[str]] = None,
    ):
        self.slack_webhook = slack_webhook or os.getenv("GUARDIAN_SLACK_WEBHOOK")
        self.discord_webhook = discord_webhook or os.getenv("GUARDIAN_DISCORD_WEBHOOK")
        self.generic_webhooks = generic_webhooks or []
        env_generic = os.getenv("GUARDIAN_WEBHOOKS", "")
        if env_generic:
            self.generic_webhooks.extend(w.strip() for w in env_generic.split(",") if w.strip())

    def _grade_emoji(self, grade: str) -> str:
        if grade.startswith("A"): return "🟢"
        if grade.startswith("B"): return "🔵"
        if grade.startswith("C"): return "🟡"
        return "🔴"

    def _severity_emoji(self, sev: str) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev.lower(), "⚪")

    def notify_scan_complete(self, scan_data: Dict[str, Any]) -> None:
        """Send notifications for a completed scan to all configured channels."""
        if self.slack_webhook:
            self._send_slack(scan_data)
        if self.discord_webhook:
            self._send_discord(scan_data)
        for url in self.generic_webhooks:
            self._send_generic(url, scan_data)

    def notify_critical_finding(self, finding: Dict[str, Any], scan_data: Dict[str, Any]) -> None:
        """Immediately alert on critical/high findings."""
        if self.slack_webhook:
            self._send_slack_critical(finding, scan_data)
        if self.discord_webhook:
            self._send_discord_critical(finding, scan_data)

    def _send_slack(self, data: Dict[str, Any]) -> None:
        """Send scan results to Slack via incoming webhook."""
        import requests

        grade = data.get("grade", "F")
        score = data.get("score", 0)
        target = data.get("target_name") or data.get("target_url", "Unknown")
        vulns = data.get("vulnerabilities_found", 0)
        total = data.get("total_vectors", 0)
        scan_id = data.get("scan_id", "")
        emoji = self._grade_emoji(grade)

        # Build pillar summary
        pillar_lines = []
        for pname, pdata in data.get("pillar_scores", {}).items():
            ps = pdata.get("score", 0)
            vcount = pdata.get("vulnerable", 0)
            icon = "✅" if ps >= 80 else "⚠️" if ps >= 50 else "❌"
            pillar_lines.append(f"{icon} {pname}: {ps}% ({vcount} vuln)")

        pillar_text = "\n".join(pillar_lines) if pillar_lines else "No pillar data"

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} GuardianAI Scan Complete", "emoji": True}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Target:*\n{target}"},
                        {"type": "mrkdwn", "text": f"*Grade:*\n{emoji} {grade} ({score}/100)"},
                        {"type": "mrkdwn", "text": f"*Vulnerabilities:*\n{vulns}/{total} vectors"},
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*6-Pillar Breakdown:*\n```{pillar_text}```"}
                },
            ]
        }

        try:
            resp = requests.post(self.slack_webhook, json=payload, timeout=10)
            logger.info(f"Slack notification sent: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")

    def _send_slack_critical(self, finding: Dict[str, Any], scan_data: Dict[str, Any]) -> None:
        """Urgent Slack alert for critical findings."""
        import requests

        target = scan_data.get("target_name") or scan_data.get("target_url", "Unknown")
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🚨 CRITICAL VULNERABILITY DETECTED", "emoji": True}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Target:*\n{target}"},
                        {"type": "mrkdwn", "text": f"*Vector:*\n{finding.get('vector_name', '')}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{self._severity_emoji(finding.get('severity', ''))} {finding.get('severity', '').upper()}"},
                        {"type": "mrkdwn", "text": f"*Pillar:*\n{finding.get('pillar', '')}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Details:*\n{finding.get('details', 'N/A')[:500]}"}
                },
            ]
        }

        try:
            resp = requests.post(self.slack_webhook, json=payload, timeout=10)
            logger.info(f"Slack critical alert sent: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Slack critical alert failed: {e}")

    def _send_discord(self, data: Dict[str, Any]) -> None:
        """Send scan results to Discord via webhook."""
        import requests

        grade = data.get("grade", "F")
        score = data.get("score", 0)
        target = data.get("target_name") or data.get("target_url", "Unknown")
        vulns = data.get("vulnerabilities_found", 0)
        total = data.get("total_vectors", 0)
        scan_id = data.get("scan_id", "")
        emoji = self._grade_emoji(grade)

        color = 0x10b981 if grade.startswith("A") else 0x22d3ee if grade.startswith("B") else 0xf59e0b if grade.startswith("C") else 0xef4444

        # Build pillar field
        pillar_lines = []
        for pname, pdata in data.get("pillar_scores", {}).items():
            ps = pdata.get("score", 0)
            vcount = pdata.get("vulnerable", 0)
            icon = "✅" if ps >= 80 else "⚠️" if ps >= 50 else "❌"
            pillar_lines.append(f"{icon} **{pname}**: {ps}% ({vcount} vuln)")

        payload = {
            "embeds": [{
                "title": f"{emoji} GuardianAI Audit Complete",
                "description": f"Security scan finished for **{target}**",
                "color": color,
                "fields": [
                    {"name": "Grade", "value": f"{emoji} **{grade}** ({score}/100)", "inline": True},
                    {"name": "Vulnerabilities", "value": f"{vulns}/{total} vectors", "inline": True},
                    {"name": "Scan ID", "value": f"`{scan_id}`", "inline": True},
                    {"name": "6-Pillar Breakdown", "value": "\n".join(pillar_lines) or "N/A", "inline": False},
                ],
                "footer": {"text": "GuardianAI Security Lab"},
                "timestamp": data.get("started_at", ""),
            }]
        }

        try:
            resp = requests.post(self.discord_webhook, json=payload, timeout=10)
            logger.info(f"Discord notification sent: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Discord notification failed: {e}")

    def _send_discord_critical(self, finding: Dict[str, Any], scan_data: Dict[str, Any]) -> None:
        """Urgent Discord alert for critical findings."""
        import requests

        target = scan_data.get("target_name") or scan_data.get("target_url", "Unknown")
        payload = {
            "embeds": [{
                "title": "🚨 CRITICAL VULNERABILITY DETECTED",
                "description": f"**{finding.get('vector_name', '')}** found on **{target}**",
                "color": 0xef4444,
                "fields": [
                    {"name": "Severity", "value": finding.get("severity", "").upper(), "inline": True},
                    {"name": "Pillar", "value": finding.get("pillar", ""), "inline": True},
                    {"name": "Details", "value": finding.get("details", "N/A")[:500], "inline": False},
                ],
                "footer": {"text": "GuardianAI Security Lab — Immediate Action Required"},
            }]
        }

        try:
            resp = requests.post(self.discord_webhook, json=payload, timeout=10)
            logger.info(f"Discord critical alert sent: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Discord critical alert failed: {e}")

    def _send_generic(self, url: str, data: Dict[str, Any]) -> None:
        """Send scan results to a generic webhook URL."""
        import requests

        payload = {
            "event": "guardianai.scan.complete",
            "version": "1.0",
            "data": {
                "scan_id": data.get("scan_id"),
                "target_url": data.get("target_url"),
                "target_name": data.get("target_name"),
                "grade": data.get("grade"),
                "score": data.get("score"),
                "vulnerabilities_found": data.get("vulnerabilities_found"),
                "protected_count": data.get("protected_count"),
                "total_vectors": data.get("total_vectors"),
                "pillar_scores": data.get("pillar_scores", {}),
                "started_at": data.get("started_at"),
                "duration_seconds": data.get("duration_seconds"),
            }
        }

        try:
            resp = requests.post(url, json=payload, timeout=10, headers={"User-Agent": "GuardianAI/1.0"})
            logger.info(f"Webhook notification sent to {url}: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Webhook notification failed for {url}: {e}")


# Global instance — configured from environment variables
_notifier: Optional[ScanNotifier] = None


def get_notifier() -> ScanNotifier:
    """Get or create the global notifier instance."""
    global _notifier
    if _notifier is None:
        _notifier = ScanNotifier()
    return _notifier


def notify_scan_complete(scan_data: Dict[str, Any]) -> None:
    """Convenience function to send scan completion notifications."""
    try:
        get_notifier().notify_scan_complete(scan_data)
    except Exception as e:
        logger.warning(f"Notification dispatch error: {e}")
