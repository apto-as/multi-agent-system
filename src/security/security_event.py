"""共通セキュリティイベント定義
Unified Security Event classes for consistent security logging
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from ..models.audit_log import SecurityEventSeverity, SecurityEventType


@dataclass
class SecurityEvent:
    """統一されたセキュリティイベント構造
    Unified security event data structure for consistent logging.
    """

    event_type: SecurityEventType
    severity: SecurityEventSeverity
    timestamp: datetime
    client_ip: str
    user_id: str | None = None
    session_id: str | None = None
    endpoint: str | None = None
    method: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    message: str | None = None
    details: dict[str, Any] | None = None
    location: dict[str, str] | None = None
    risk_score: int = 0
    blocked: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["severity"] = self.severity.value
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)
