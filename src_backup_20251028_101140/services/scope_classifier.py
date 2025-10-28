"""
Intelligent memory scope classification system.

Automatically determines whether a memory should be:
- GLOBAL (cloud): Universal knowledge
- SHARED (cloud): Team/organization knowledge
- PROJECT (local): Project-specific details
- PRIVATE (local): Confidential/sensitive data
"""

import logging
import re
from typing import Any

from ..core.memory_scope import MemoryScope

logger = logging.getLogger(__name__)


class SensitiveDataDetector:
    """Detect sensitive information that must stay local."""

    # Security: Comprehensive patterns for sensitive data
    SENSITIVE_PATTERNS = [
        # Credentials
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", "PASSWORD"),
        (r"(?i)(secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+", "API_KEY"),
        (r"(?i)bearer\s+[a-zA-Z0-9_-]{20,}", "BEARER_TOKEN"),
        (r"(?i)authorization:\s*[a-zA-Z0-9_-]+", "AUTH_HEADER"),
        # Crypto keys
        (r"(?i)private[_-]?key\s*[:=]", "PRIVATE_KEY"),
        (r"-----BEGIN.*PRIVATE KEY-----", "PEM_KEY"),
        (r"[0-9a-fA-F]{64,}", "HEX_KEY"),
        # Personal data
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL"),
        (r"\b\+?\d{10,15}\b", "PHONE"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
        (r"\b\d{16}\b", "CREDIT_CARD"),
        # Database credentials
        (r"(?i)(jdbc|postgresql|mysql|mongodb)://[^:]+:[^@]+@", "DB_CREDENTIALS"),
        # Cloud credentials
        (r"(?i)aws_access_key_id\s*[:=]\s*\S+", "AWS_KEY"),
        (r"(?i)aws_secret_access_key\s*[:=]\s*\S+", "AWS_SECRET"),
        (r"\bAKIA[0-9A-Z]{16}\b", "AWS_ACCESS_KEY"),
        # IP addresses (internal)
        (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "PRIVATE_IP"),
        (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "PRIVATE_IP"),
        (r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "PRIVATE_IP"),
    ]

    @classmethod
    def detect(cls, content: str) -> tuple[bool, list[str]]:
        """
        Detect sensitive information in content.

        Returns:
            Tuple of (has_sensitive_data, list_of_detected_types)
        """
        detected_types = []

        for pattern, data_type in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, content):
                detected_types.append(data_type)
                logger.warning(f"Sensitive data detected: {data_type} - Memory will be kept LOCAL")

        return len(detected_types) > 0, detected_types


class ProjectContextDetector:
    """Detect project-specific context indicators."""

    PROJECT_INDICATORS = [
        # File paths
        r"/src/|/lib/|/tests?/|/app/|/components?/",
        # Import statements
        r"^import\s+|^from\s+\w+\s+import",
        # Function/class definitions
        r"^(def|class|function|const|let|var)\s+\w+",
        # Configuration
        r"config\.|settings\.|\.env|\.config",
        # Project-specific naming
        r"(TODO|FIXME|NOTE):",
        # Code comments
        r"^(#|//|/\*|\*)",
    ]

    @classmethod
    def is_project_specific(cls, content: str) -> bool:
        """Check if content is project-specific."""
        return any(re.search(pattern, content, re.MULTILINE) for pattern in cls.PROJECT_INDICATORS)


class KnowledgeTypeClassifier:
    """Classify knowledge type (universal vs specific)."""

    # Universal knowledge indicators
    UNIVERSAL_INDICATORS = [
        r"(?i)(best practice|design pattern|algorithm)",
        r"(?i)(optimization technique|security guideline)",
        r"(?i)(industry standard|common approach)",
        r"(?i)(general principle|universal rule)",
    ]

    # Team/organization indicators
    TEAM_INDICATORS = [
        r"(?i)(our team|our organization|company policy)",
        r"(?i)(team standard|coding guideline|style guide)",
        r"(?i)(internal process|workflow)",
    ]

    @classmethod
    def classify(cls, content: str) -> str:
        """
        Classify knowledge type.

        Returns:
            'universal', 'team', or 'specific'
        """
        # Check for universal knowledge
        for pattern in cls.UNIVERSAL_INDICATORS:
            if re.search(pattern, content):
                return "universal"

        # Check for team knowledge
        for pattern in cls.TEAM_INDICATORS:
            if re.search(pattern, content):
                return "team"

        return "specific"


class ScopeClassifier:
    """Main scope classification engine."""

    def __init__(self):
        self.sensitive_detector = SensitiveDataDetector()
        self.project_detector = ProjectContextDetector()
        self.knowledge_classifier = KnowledgeTypeClassifier()

    def classify(
        self,
        content: str,
        metadata: dict[str, Any] | None = None,
        user_hint: MemoryScope | None = None,
    ) -> tuple[MemoryScope, dict[str, Any]]:
        """
        Classify memory scope based on content and metadata.

        Args:
            content: Memory content to classify
            metadata: Optional metadata (tags, context)
            user_hint: Optional user-provided scope hint

        Returns:
            Tuple of (classified_scope, classification_details)
        """
        classification_details = {
            "auto_classified": True,
            "user_hint": str(user_hint) if user_hint else None,
            "detected_sensitive": False,
            "sensitive_types": [],
            "knowledge_type": None,
            "project_specific": False,
        }

        # Step 1: Security first - check for sensitive data
        has_sensitive, sensitive_types = self.sensitive_detector.detect(content)
        if has_sensitive:
            classification_details["detected_sensitive"] = True
            classification_details["sensitive_types"] = sensitive_types
            logger.warning(f"Sensitive data detected: {sensitive_types} - Forcing PRIVATE scope")
            return MemoryScope.PRIVATE, classification_details

        # Step 2: Check for project-specific indicators
        is_project_specific = self.project_detector.is_project_specific(content)
        classification_details["project_specific"] = is_project_specific

        if is_project_specific:
            # Project-specific code/config → PROJECT scope (local)
            return MemoryScope.PROJECT, classification_details

        # Step 3: Classify knowledge type
        knowledge_type = self.knowledge_classifier.classify(content)
        classification_details["knowledge_type"] = knowledge_type

        if knowledge_type == "universal":
            # Universal knowledge → GLOBAL (cloud)
            return MemoryScope.GLOBAL, classification_details
        elif knowledge_type == "team":
            # Team knowledge → SHARED (cloud, E2EE)
            return MemoryScope.SHARED, classification_details

        # Step 4: Check metadata for hints
        if metadata:
            tags = metadata.get("tags", [])
            if any(tag in ["global", "public", "universal"] for tag in tags):
                return MemoryScope.GLOBAL, classification_details
            if any(tag in ["team", "shared", "organization"] for tag in tags):
                return MemoryScope.SHARED, classification_details
            if any(tag in ["private", "confidential", "secret"] for tag in tags):
                return MemoryScope.PRIVATE, classification_details

        # Step 5: Use user hint if provided
        if user_hint:
            classification_details["auto_classified"] = False
            logger.info(f"Using user-provided scope hint: {user_hint}")
            return user_hint, classification_details

        # Default: PROJECT (local, safe default)
        logger.debug("No clear indicators - defaulting to PROJECT scope (local)")
        return MemoryScope.PROJECT, classification_details

    def validate_scope_safety(self, scope: MemoryScope, content: str) -> bool:
        """
        Validate that the proposed scope is safe for the content.

        Returns:
            True if safe, False if scope should be downgraded
        """
        has_sensitive, sensitive_types = self.sensitive_detector.detect(content)

        # Never allow sensitive data in cloud
        if has_sensitive and scope.is_cloud():
            logger.error(
                f"SECURITY VIOLATION: Attempted to store sensitive data ({sensitive_types}) in cloud scope {scope}"
            )
            return False

        return True

    def suggest_scope_override(
        self, current_scope: MemoryScope, content: str
    ) -> MemoryScope | None:
        """
        Suggest a safer scope if current one is inappropriate.

        Returns:
            Suggested scope, or None if current scope is appropriate
        """
        has_sensitive, _ = self.sensitive_detector.detect(content)

        if has_sensitive and current_scope.is_cloud():
            # Force PRIVATE for sensitive data
            return MemoryScope.PRIVATE

        return None
