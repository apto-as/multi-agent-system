"""Skill validation service for TMWS v2.4.0 - Production implementation.

This service validates skill data and content for the Progressive Disclosure Skills System.
Extracted from POC implementation and enhanced for production use.

Security:
- S-3-M1: Input length validation (configurable limits)
- S-3-M2: Null byte sanitization (prevents database corruption)
- S-3-M3: Configurable core instructions extraction
- Additional validations for skill name, namespace, version, content format

Performance:
- Validation operations are O(1) or O(n) where n is content length
- No database queries during validation
- Efficient regex pattern matching

Progressive Disclosure:
- Validates 3-layer content structure
- Extracts metadata, core instructions, and auxiliary content
- Enforces token budget limits per layer
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from src.core.config import get_settings
from src.core.exceptions import ValidationError
from src.models.skill import AccessLevel


class SkillValidationService:
    """Production service for skill validation and content parsing.

    This service provides validation for:
    - Skill metadata (name, namespace, tags)
    - Content format (SKILL.md structure)
    - Progressive Disclosure layers (metadata, core, auxiliary)
    - Security constraints (input sanitization, length limits)

    Security Enhancements:
    - S-3-M1: Configurable field length validation
    - S-3-M2: Null byte sanitization
    - S-3-M3: Configurable core instructions length
    - Namespace format validation (prevents path traversal)
    - Tag validation (prevents injection attacks)
    """

    def __init__(self) -> None:
        """Initialize validation service with configuration."""
        self.settings = get_settings()

        # Field length limits (from config)
        self.max_field_length = self.settings.skills_max_field_length  # 255
        self.max_core_instructions_length = self.settings.skills_core_instructions_max_length  # 8000

        # Content layer token budgets (Progressive Disclosure)
        self.layer_1_token_budget = 100  # Metadata
        self.layer_2_token_budget = 2000  # Core instructions
        self.layer_3_token_budget = 10000  # Auxiliary content

        # Validation patterns
        self.skill_name_pattern = re.compile(r"^[a-z][a-z0-9_-]{1,254}$")
        self.namespace_pattern = re.compile(r"^[a-z0-9][a-z0-9_-]{0,254}$")
        self.tag_pattern = re.compile(r"^[a-z0-9][a-z0-9_-]{0,49}$")

    # ===== Core Validation Methods =====

    def validate_skill_name(self, name: str | None) -> str:
        """Validate skill name format.

        Args:
            name: Skill name to validate

        Returns:
            Sanitized skill name

        Raises:
            ValidationError: If name is invalid

        Rules:
        - Must start with lowercase letter
        - Only lowercase letters, numbers, hyphens, underscores
        - 2-255 characters
        - No null bytes
        """
        if not name:
            raise ValidationError(
                "Skill name is required",
                details={"error_code": "SKILL_NAME_REQUIRED"},
            )

        # S-3-M2: Sanitize null bytes
        name = self._sanitize_text_input(name)

        # S-3-M1: Validate length
        self._validate_input_length(name, "skill_name")

        # Format validation
        if not self.skill_name_pattern.match(name):
            # SECURITY: Don't echo user input in error messages (V-SKILL-4 mitigation)
            raise ValidationError(
                "Invalid skill name format",
                details={
                    "error_code": "SKILL_NAME_INVALID_FORMAT",
                    # Removed: "name": name,  # V-SKILL-4: Information disclosure risk
                    "format": "lowercase_alphanumeric_hyphen_underscore",
                    "length": "2-255 characters",
                },
            )

        return name

    def validate_namespace(self, namespace: str | None) -> str:
        """Validate namespace format.

        Args:
            namespace: Namespace to validate

        Returns:
            Sanitized namespace

        Raises:
            ValidationError: If namespace is invalid

        Rules:
        - Must start with lowercase letter or number
        - Only lowercase letters, numbers, hyphens, underscores
        - 1-255 characters
        - No null bytes
        - No path traversal (no dots or slashes)
        """
        if not namespace:
            raise ValidationError(
                "Namespace is required",
                details={"error_code": "NAMESPACE_REQUIRED"},
            )

        # S-3-M2: Sanitize null bytes
        namespace = self._sanitize_text_input(namespace)

        # S-3-M1: Validate length
        self._validate_input_length(namespace, "namespace")

        # Security: Prevent path traversal
        if "." in namespace or "/" in namespace or "\\" in namespace:
            raise ValidationError(
                "Namespace contains invalid characters (path traversal prevention)",
                details={
                    "error_code": "NAMESPACE_PATH_TRAVERSAL",
                    # Removed: "namespace": namespace,  # V-SKILL-4: Information disclosure risk
                    "forbidden_chars": [".", "/", "\\"],
                },
            )

        # Format validation
        if not self.namespace_pattern.match(namespace):
            # SECURITY: Don't echo user input in error messages (V-SKILL-4 mitigation)
            raise ValidationError(
                "Invalid namespace format",
                details={
                    "error_code": "NAMESPACE_INVALID_FORMAT",
                    # Removed: "namespace": namespace,  # V-SKILL-4: Information disclosure risk
                    "format": "lowercase_alphanumeric_hyphen_underscore",
                    "length": "1-255 characters",
                },
            )

        return namespace

    def validate_tags(self, tags: list[str] | None) -> list[str]:
        """Validate skill tags.

        Args:
            tags: List of tags to validate

        Returns:
            Sanitized and validated tags

        Raises:
            ValidationError: If any tag is invalid

        Rules:
        - Each tag: lowercase letter/number start
        - Only lowercase letters, numbers, hyphens, underscores
        - 1-50 characters per tag
        - No null bytes
        - Maximum 20 tags
        """
        if tags is None:
            return []

        if len(tags) > 20:
            raise ValidationError(
                "Too many tags",
                details={
                    "error_code": "TOO_MANY_TAGS",
                    "count": len(tags),
                    "max": 20,
                },
            )

        validated_tags = []
        for tag in tags:
            # S-3-M2: Sanitize null bytes
            tag = self._sanitize_text_input(tag)

            # Format validation
            if not self.tag_pattern.match(tag):
                # SECURITY: Don't echo user input in error messages (V-SKILL-4 mitigation)
                raise ValidationError(
                    "Invalid tag format",
                    details={
                        "error_code": "TAG_INVALID_FORMAT",
                        # Removed: "tag": tag,  # V-SKILL-4: Information disclosure risk
                        "format": "lowercase_alphanumeric_hyphen_underscore",
                        "length": "1-50 characters",
                    },
                )

            validated_tags.append(tag)

        return validated_tags

    def validate_access_level(self, access_level: str | AccessLevel) -> AccessLevel:
        """Validate access level.

        Args:
            access_level: Access level to validate (string or enum)

        Returns:
            Validated AccessLevel enum

        Raises:
            ValidationError: If access level is invalid
        """
        if isinstance(access_level, AccessLevel):
            return access_level

        try:
            return AccessLevel(access_level)
        except ValueError:
            valid_levels = [level.value for level in AccessLevel]
            raise ValidationError(
                f"Invalid access level: {access_level}",
                details={
                    "error_code": "INVALID_ACCESS_LEVEL",
                    "provided": access_level,
                    "valid_levels": valid_levels,
                },
            )

    def validate_content(self, content: str | None) -> str:
        """Validate skill content.

        Args:
            content: SKILL.md content to validate

        Returns:
            Sanitized content

        Raises:
            ValidationError: If content is invalid

        Rules:
        - Required (non-empty)
        - No null bytes
        - Maximum 50,000 characters (configurable)
        """
        if not content or not content.strip():
            raise ValidationError(
                "Skill content is required",
                details={"error_code": "CONTENT_REQUIRED"},
            )

        # S-3-M2: Sanitize null bytes
        content = self._sanitize_text_input(content)

        # Length validation (50KB max)
        max_content_length = 50000
        if len(content) > max_content_length:
            raise ValidationError(
                "Content exceeds maximum length",
                details={
                    "error_code": "CONTENT_TOO_LONG",
                    "length": len(content),
                    "max": max_content_length,
                },
            )

        return content

    # ===== Progressive Disclosure Parsing =====

    def parse_progressive_disclosure_layers(self, content: str) -> dict[str, Any]:
        """Parse content into Progressive Disclosure layers.

        Args:
            content: Full SKILL.md content

        Returns:
            Dictionary with:
            - metadata: Layer 1 (dict, ~100 tokens)
            - core_instructions: Layer 2 (str, ~2,000 tokens)
            - auxiliary_content: Layer 3 (str, ~10,000 tokens)
            - content_hash: SHA256 hash of content

        Layer Structure:
        - Layer 1: Frontmatter metadata (YAML/JSON)
        - Layer 2: ## Core Instructions section
        - Layer 3: Everything else (examples, references, etc.)
        """
        # Validate content first
        content = self.validate_content(content)

        # Extract metadata (Layer 1)
        metadata = self._extract_metadata(content)

        # Extract core instructions (Layer 2)
        core_instructions = self._extract_core_instructions(content)

        # Extract auxiliary content (Layer 3)
        auxiliary_content = self._extract_auxiliary_content(content)

        # Compute content hash
        content_hash = self._compute_content_hash(content)

        return {
            "metadata": metadata,
            "core_instructions": core_instructions,
            "auxiliary_content": auxiliary_content,
            "content_hash": content_hash,
        }

    def _extract_metadata(self, content: str) -> dict[str, Any]:
        """Extract metadata from content (Layer 1).

        SECURITY NOTE (V-SKILL-2):
        YAML support has been REMOVED due to YAML bomb vulnerability (CVSS 7.5).
        Only JSON frontmatter is supported for security reasons.

        Looks for frontmatter in JSON format at the beginning of the file.

        Args:
            content: Full skill content

        Returns:
            Metadata dictionary (empty if no frontmatter found)
        """
        # Only support JSON frontmatter (SECURITY: V-SKILL-2 mitigation)
        json_pattern = r"^```json\s*\n(\{.*?\})\s*\n```\s*\n"
        json_match = re.match(json_pattern, content, re.DOTALL)

        if json_match:
            json_content = json_match.group(1)

            # SECURITY: Limit JSON size to prevent DoS (V-SKILL-2)
            max_json_size = 10000  # 10KB limit for metadata
            if len(json_content) > max_json_size:
                raise ValidationError(
                    "JSON frontmatter exceeds maximum size",
                    details={
                        "error_code": "JSON_TOO_LARGE",
                        "size": len(json_content),
                        "max": max_json_size,
                    },
                )

            try:
                metadata = json.loads(json_content)
                return metadata if isinstance(metadata, dict) else {}
            except json.JSONDecodeError:
                # JSON parsing failed, return empty dict (metadata is optional)
                return {}

        # No frontmatter found
        return {}

    def _extract_core_instructions(self, content: str) -> str:
        """Extract core instructions from content (Layer 2).

        Looks for the ## Core Instructions section.
        Falls back to first N characters if section not found.

        Args:
            content: Full skill content

        Returns:
            Core instructions text (truncated to max_core_instructions_length)
        """
        # Try to find "## Core Instructions" section
        pattern = r"##\s+Core\s+Instructions\s*\n(.*?)(?=\n##|\Z)"
        match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)

        # Use ternary operator for simpler code (SIM108)
        core = match.group(1).strip() if match else content

        # S-3-M3: Truncate to configured length
        return core[: self.max_core_instructions_length]

    def _extract_auxiliary_content(self, content: str) -> str:
        """Extract auxiliary content from content (Layer 3).

        Everything except core instructions (examples, references, etc.).

        Args:
            content: Full skill content

        Returns:
            Auxiliary content (everything not in core instructions)
        """
        # For now, return full content (Layer 3 includes everything)
        # Future: Extract only non-core sections
        return content

    def _compute_content_hash(self, content: str) -> str:
        """Compute SHA256 hash of content for integrity verification.

        Args:
            content: Content to hash

        Returns:
            64-character hex string (SHA256 hash)
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ===== Security Helpers (from POC) =====

    def _sanitize_text_input(self, text: str | None) -> str:
        """S-3-M2: Remove null bytes from text input.

        Null bytes can cause data corruption in SQLite and other databases.

        Args:
            text: Input text to sanitize

        Returns:
            Sanitized text with null bytes removed, or empty string if input is None
        """
        if text is None:
            return ""
        return text.replace("\x00", "")

    def _validate_input_length(
        self, value: str | None, field_name: str, max_length: int | None = None
    ) -> None:
        """S-3-M1: Validate input length against configured maximum.

        Args:
            value: Input value to validate
            field_name: Name of the field (for error messages)
            max_length: Maximum allowed length (defaults to skills_max_field_length from settings)

        Raises:
            ValidationError: If input exceeds maximum length
        """
        if value is None:
            return

        max_len = max_length or self.max_field_length

        if len(value) > max_len:
            raise ValidationError(
                f"Input validation failed: {field_name} exceeds maximum length",
                details={
                    "field": field_name,
                    "max_length": max_len,
                    "actual_length": len(value),
                    "error_code": "S-3-M1",
                },
            )

    # ===== Utility Methods =====

    def estimate_token_count(self, text: str) -> int:
        """Estimate token count for text (rough approximation).

        Uses character count / 4 as a rough estimate.
        For production, consider using tiktoken library.

        Args:
            text: Text to estimate tokens for

        Returns:
            Estimated token count
        """
        return len(text) // 4

    def validate_token_budget(self, text: str, layer: int) -> None:
        """Validate that text fits within token budget for layer.

        Args:
            text: Text to validate
            layer: Layer number (1, 2, or 3)

        Raises:
            ValidationError: If text exceeds token budget
        """
        token_count = self.estimate_token_count(text)

        budget_map = {
            1: self.layer_1_token_budget,
            2: self.layer_2_token_budget,
            3: self.layer_3_token_budget,
        }

        budget = budget_map.get(layer)
        if budget is None:
            raise ValidationError(
                f"Invalid layer number: {layer}",
                details={"error_code": "INVALID_LAYER", "layer": layer},
            )

        if token_count > budget:
            raise ValidationError(
                f"Layer {layer} exceeds token budget",
                details={
                    "error_code": "TOKEN_BUDGET_EXCEEDED",
                    "layer": layer,
                    "token_count": token_count,
                    "budget": budget,
                },
            )
