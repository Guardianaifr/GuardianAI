"""
SIEM Mapping Packs — Microsoft Sentinel & Elastic (ECS)

Pre-built field mapping classes that translate GuardianAI security events
into vendor-specific schemas:

  - Microsoft Sentinel: CommonSecurityLog schema with DeviceVendor,
    DeviceProduct, Activity, LogSeverity, and SourceHostName fields.
  - Elastic (ECS): Elastic Common Schema with @timestamp, event.kind,
    event.category, event.severity, and guardianai namespace fields.

Each mapper also provides detection rule templates for common attack
patterns (prompt injection, jailbreak, data exfiltration, shadow AI).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Severity Mapping ─────────────────────────────────────────────────────────

class GuardianSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Sentinel severity: 0-10 scale
_SENTINEL_SEVERITY: Dict[str, int] = {
    "info": 1,
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10,
}

# ECS severity: 0-100 scale
_ECS_SEVERITY: Dict[str, int] = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


# ── Microsoft Sentinel Mapper ────────────────────────────────────────────────

@dataclass
class SentinelMappedEvent:
    """A GuardianAI event mapped to Microsoft Sentinel CommonSecurityLog."""
    TimeGenerated: str
    DeviceVendor: str
    DeviceProduct: str
    DeviceVersion: str
    DeviceEventClassID: str
    Activity: str
    LogSeverity: int
    SourceHostName: str
    SourceUserName: str
    Message: str
    ExtID: str
    AdditionalExtensions: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "TimeGenerated": self.TimeGenerated,
            "DeviceVendor": self.DeviceVendor,
            "DeviceProduct": self.DeviceProduct,
            "DeviceVersion": self.DeviceVersion,
            "DeviceEventClassID": self.DeviceEventClassID,
            "Activity": self.Activity,
            "LogSeverity": self.LogSeverity,
            "SourceHostName": self.SourceHostName,
            "SourceUserName": self.SourceUserName,
            "Message": self.Message,
            "ExtID": self.ExtID,
            "AdditionalExtensions": self.AdditionalExtensions,
        }


class MicrosoftSentinelMapper:
    """Maps GuardianAI events to Microsoft Sentinel CommonSecurityLog schema."""

    VENDOR = "GuardianAI"
    PRODUCT = "AISecurityFirewall"
    VERSION = "2.0"

    def map_event(self, event: Dict[str, Any]) -> SentinelMappedEvent:
        """Map a raw GuardianAI event to Sentinel format."""
        severity_str = str(event.get("severity", "medium")).lower()
        severity_num = _SENTINEL_SEVERITY.get(severity_str, 5)

        return SentinelMappedEvent(
            TimeGenerated=event.get("ts_utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            DeviceVendor=self.VENDOR,
            DeviceProduct=self.PRODUCT,
            DeviceVersion=self.VERSION,
            DeviceEventClassID=event.get("event_type", "guardian_alert"),
            Activity=event.get("event_type", "security_event"),
            LogSeverity=severity_num,
            SourceHostName=event.get("source_host", ""),
            SourceUserName=event.get("tenant_id", ""),
            Message=event.get("description", json.dumps(event, default=str)),
            ExtID=event.get("event_id", ""),
            AdditionalExtensions=json.dumps(
                {k: v for k, v in event.items()
                 if k not in ("ts_utc", "severity", "event_type", "source_host",
                              "tenant_id", "description", "event_id")},
                default=str,
            ),
        )

    @staticmethod
    def get_detection_rules() -> List[Dict[str, Any]]:
        """Return pre-built Sentinel KQL detection rule templates."""
        return [
            {
                "name": "GuardianAI - Prompt Injection Detected",
                "severity": "High",
                "query": (
                    'CommonSecurityLog\n'
                    '| where DeviceVendor == "GuardianAI"\n'
                    '| where DeviceEventClassID == "prompt_injection"\n'
                    '| where LogSeverity >= 8\n'
                    '| project TimeGenerated, SourceUserName, Message'
                ),
                "frequency": "PT5M",
                "period": "PT5M",
            },
            {
                "name": "GuardianAI - Jailbreak Attempt",
                "severity": "Critical",
                "query": (
                    'CommonSecurityLog\n'
                    '| where DeviceVendor == "GuardianAI"\n'
                    '| where DeviceEventClassID == "jailbreak"\n'
                    '| project TimeGenerated, SourceUserName, Message, LogSeverity'
                ),
                "frequency": "PT5M",
                "period": "PT5M",
            },
            {
                "name": "GuardianAI - Shadow AI Usage",
                "severity": "Medium",
                "query": (
                    'CommonSecurityLog\n'
                    '| where DeviceVendor == "GuardianAI"\n'
                    '| where DeviceEventClassID == "shadow_ai"\n'
                    '| summarize Count=count() by SourceUserName\n'
                    '| where Count > 5'
                ),
                "frequency": "PT15M",
                "period": "PT1H",
            },
        ]


# ── Elastic (ECS) Mapper ────────────────────────────────────────────────────

@dataclass
class ECSMappedEvent:
    """A GuardianAI event mapped to Elastic Common Schema."""
    timestamp: str
    event_kind: str
    event_category: List[str]
    event_type: List[str]
    event_severity: int
    event_module: str
    event_dataset: str
    event_action: str
    event_outcome: str
    message: str
    source_address: str
    user_name: str
    guardianai: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "@timestamp": self.timestamp,
            "event": {
                "kind": self.event_kind,
                "category": self.event_category,
                "type": self.event_type,
                "severity": self.event_severity,
                "module": self.event_module,
                "dataset": self.event_dataset,
                "action": self.event_action,
                "outcome": self.event_outcome,
            },
            "message": self.message,
            "source": {"address": self.source_address},
            "user": {"name": self.user_name},
            "guardianai": self.guardianai,
        }


class ElasticECSMapper:
    """Maps GuardianAI events to Elastic Common Schema (ECS)."""

    MODULE = "guardianai"
    DATASET = "guardianai.alerts"

    # Map event types to ECS categories
    _CATEGORY_MAP: Dict[str, List[str]] = {
        "prompt_injection": ["intrusion_detection"],
        "jailbreak": ["intrusion_detection"],
        "data_exfiltration": ["intrusion_detection"],
        "shadow_ai": ["network"],
        "trust_exploitation": ["intrusion_detection"],
        "lateral_movement": ["intrusion_detection"],
    }

    def map_event(self, event: Dict[str, Any]) -> ECSMappedEvent:
        """Map a raw GuardianAI event to ECS format."""
        event_type = event.get("event_type", "alert")
        severity_str = str(event.get("severity", "medium")).lower()
        severity_num = _ECS_SEVERITY.get(severity_str, 50)

        categories = self._CATEGORY_MAP.get(event_type, ["host"])

        return ECSMappedEvent(
            timestamp=event.get("ts_utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            event_kind="alert",
            event_category=categories,
            event_type=["info"],
            event_severity=severity_num,
            event_module=self.MODULE,
            event_dataset=self.DATASET,
            event_action=event_type,
            event_outcome=event.get("outcome", "unknown"),
            message=event.get("description", json.dumps(event, default=str)),
            source_address=event.get("source_host", ""),
            user_name=event.get("tenant_id", ""),
            guardianai=event,
        )

    @staticmethod
    def get_detection_rules() -> List[Dict[str, Any]]:
        """Return pre-built Elastic detection rule templates (ESQL/EQL)."""
        return [
            {
                "name": "GuardianAI Prompt Injection Alert",
                "severity": "high",
                "risk_score": 75,
                "type": "query",
                "query": 'event.module:"guardianai" AND event.action:"prompt_injection"',
                "interval": "5m",
                "language": "kuery",
            },
            {
                "name": "GuardianAI Jailbreak Attempt",
                "severity": "critical",
                "risk_score": 99,
                "type": "query",
                "query": 'event.module:"guardianai" AND event.action:"jailbreak"',
                "interval": "5m",
                "language": "kuery",
            },
            {
                "name": "GuardianAI Shadow AI Burst",
                "severity": "medium",
                "risk_score": 50,
                "type": "threshold",
                "query": 'event.module:"guardianai" AND event.action:"shadow_ai"',
                "threshold": {"field": "user.name", "value": 5},
                "interval": "15m",
                "language": "kuery",
            },
        ]
