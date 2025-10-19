"""
Security Remediation Code Examples for TMWS v2.2.0 Pattern Execution Service
Hestia's Security Hardening Guide

This file contains production-ready code examples for fixing the identified vulnerabilities.
"""

import asyncio
import hashlib
import logging
import re
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Pattern
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ============================================================================
# CRITICAL-001: Pattern Execution Authorization
# ============================================================================

class SecurePatternExecutionEngine:
    """Pattern execution engine with comprehensive authorization"""

    def __init__(self, session: AsyncSession, cache_manager, registry):
        self.session = session
        self.cache_manager = cache_manager
        self.registry = registry
        self.audit_logger = None  # Initialize in production

    async def execute(
        self,
        query: str,
        agent_id: str,  # REQUIRED - no more anonymous execution
        execution_mode: str = "BALANCED",
        context: Optional[Dict[str, Any]] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Execute pattern with full authorization checks.

        Security measures:
        1. Mandatory agent authentication
        2. Pattern-level permission checks
        3. Audit logging of all attempts
        4. Resource quota enforcement
        """
        start_time = time.perf_counter()

        # 1. Validate agent identity
        if not agent_id:
            raise ValidationError("Agent ID required for pattern execution")

        from ..security.validators import validate_agent_id
        validate_agent_id(agent_id)

        # 2. Check agent exists and is active
        agent = await self._get_and_validate_agent(agent_id)
        if not agent or not agent.is_active:
            await self._audit_log_denied_access(
                agent_id, query, "Agent inactive or not found"
            )
            raise PermissionError("Agent not authorized")

        # 3. Find matching pattern
        pattern = self.registry.find_matching_pattern(query)
        if not pattern:
            raise NotFoundError("No matching pattern found")

        # 4. Check pattern execution permission
        if not await self._check_pattern_permission(agent_id, pattern, "execute"):
            await self._audit_log_denied_access(
                agent_id, query, f"No execute permission for pattern {pattern.name}"
            )
            raise PermissionError(
                f"Agent {agent_id} not authorized to execute pattern {pattern.name}"
            )

        # 5. Check resource quota
        quota_ok = await self._check_resource_quota(agent_id, pattern)
        if not quota_ok:
            await self._audit_log_denied_access(
                agent_id, query, "Resource quota exceeded"
            )
            raise QuotaExceededError("Agent resource quota exceeded")

        # 6. Audit log execution attempt
        await self._audit_log_execution_attempt(agent_id, pattern, query)

        # 7. Execute pattern (existing logic)
        try:
            result = await self._execute_pattern(pattern, query, context)

            # 8. Audit log success
            await self._audit_log_execution_success(
                agent_id, pattern, result, time.perf_counter() - start_time
            )

            return result

        except Exception as e:
            # 9. Audit log failure
            await self._audit_log_execution_failure(agent_id, pattern, str(e))
            raise

    async def _get_and_validate_agent(self, agent_id: str):
        """Get agent and validate status"""
        from ..models.agent import Agent

        stmt = select(Agent).where(Agent.agent_id == agent_id)
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()

        return agent

    async def _check_pattern_permission(
        self, agent_id: str, pattern, action: str
    ) -> bool:
        """
        Check if agent has permission to perform action on pattern.

        Permission hierarchy:
        1. Pattern owner - all permissions
        2. Shared access - read + execute
        3. Public patterns - read only
        4. System patterns - requires special capability
        """
        # Owner has all permissions
        if hasattr(pattern, 'agent_id') and pattern.agent_id == agent_id:
            return True

        # System patterns require special capability
        if hasattr(pattern, 'access_level') and pattern.access_level == "system":
            agent = await self._get_and_validate_agent(agent_id)
            return 'system_pattern_access' in agent.capabilities

        # Public patterns - read and execute only
        if hasattr(pattern, 'access_level') and pattern.access_level == "public":
            return action in ["read", "execute"]

        # Shared patterns - check share list
        if hasattr(pattern, 'access_level') and pattern.access_level == "shared" and hasattr(pattern, 'shared_with_agents'):
            return agent_id in (pattern.shared_with_agents or [])

        # Default deny
        return False

    async def _check_resource_quota(self, agent_id: str, pattern) -> bool:
        """Check if agent has not exceeded resource quota"""
        # Get agent's usage in last hour
        from ..models.learning_pattern import PatternUsageHistory

        one_hour_ago = datetime.utcnow() - timedelta(hours=1)

        stmt = select(
            func.count(PatternUsageHistory.id)
        ).where(
            PatternUsageHistory.agent_id == agent_id,
            PatternUsageHistory.used_at >= one_hour_ago
        )

        result = await self.session.execute(stmt)
        usage_count = result.scalar() or 0

        # Quota: 1000 executions per hour
        return usage_count < 1000

    async def _audit_log_execution_attempt(self, agent_id: str, pattern, query: str):
        """Log pattern execution attempt"""
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="PATTERN_EXECUTION_ATTEMPT",
                severity="LOW",
                client_ip="unknown",
                user_id=agent_id,
                message=f"Pattern execution: {pattern.name}",
                details={
                    'pattern_name': pattern.name,
                    'pattern_type': str(pattern.pattern_type),
                    'query_hash': hashlib.md5(query.encode()).hexdigest()[:16]
                }
            )

    async def _audit_log_denied_access(self, agent_id: str, query: str, reason: str):
        """Log denied access attempt"""
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="UNAUTHORIZED_ACCESS",
                severity="HIGH",
                client_ip="unknown",
                user_id=agent_id,
                message=f"Pattern execution denied: {reason}",
                details={
                    'query_hash': hashlib.md5(query.encode()).hexdigest()[:16],
                    'denial_reason': reason
                },
                blocked=True
            )

    async def _audit_log_execution_success(
        self, agent_id: str, pattern, result, execution_time: float
    ):
        """Log successful execution"""
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="PATTERN_EXECUTION_SUCCESS",
                severity="LOW",
                client_ip="unknown",
                user_id=agent_id,
                message=f"Pattern executed successfully: {pattern.name}",
                details={
                    'pattern_name': pattern.name,
                    'execution_time_ms': execution_time * 1000,
                    'result_size': len(str(result))
                }
            )

    async def _audit_log_execution_failure(self, agent_id: str, pattern, error: str):
        """Log execution failure"""
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type="PATTERN_EXECUTION_FAILED",
                severity="MEDIUM",
                client_ip="unknown",
                user_id=agent_id,
                message=f"Pattern execution failed: {pattern.name}",
                details={
                    'pattern_name': pattern.name,
                    'error': error[:200]  # Truncate error
                }
            )


# ============================================================================
# CRITICAL-002: Pattern Data Validation
# ============================================================================

class SecurePatternDataValidator:
    """Validate pattern data for security threats"""

    # Dangerous keys that should never appear in pattern data
    DANGEROUS_KEYS = [
        'exec', 'eval', 'compile', '__import__', 'import',
        'subprocess', 'system', 'popen', 'shell', 'os',
        'query_template', 'sql_template', 'raw_sql', 'sql_command',
        '__code__', '__globals__', '__builtins__'
    ]

    MAX_DEPTH = 5
    MAX_STRING_LENGTH = 10000
    MAX_LIST_SIZE = 1000

    def validate_pattern_data(self, pattern_data: dict[str, Any]) -> dict[str, Any]:
        """
        Comprehensive validation of pattern data.

        Checks:
        1. Structure depth (prevent DoS)
        2. Dangerous keys (prevent code injection)
        3. SQL injection patterns
        4. String length limits
        5. Collection size limits
        """
        if not isinstance(pattern_data, dict):
            raise ValidationError("Pattern data must be a dictionary")

        # Check depth
        depth = self._get_dict_depth(pattern_data)
        if depth > self.MAX_DEPTH:
            raise ValidationError(
                f"Pattern data exceeds maximum depth of {self.MAX_DEPTH}"
            )

        # Check for dangerous keys and values
        self._check_dangerous_content(pattern_data)

        # Sanitize all string values
        sanitized = self._sanitize_values(pattern_data)

        return sanitized

    def _get_dict_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth"""
        if not isinstance(obj, (dict, list)):
            return current_depth

        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(
                self._get_dict_depth(value, current_depth + 1)
                for value in obj.values()
            )
        else:  # list
            if not obj:
                return current_depth
            return max(
                self._get_dict_depth(item, current_depth + 1)
                for item in obj
            )

    def _check_dangerous_content(self, obj: Any, path: str = ""):
        """Recursively check for dangerous keys and values"""
        if isinstance(obj, dict):
            # Check keys
            for key in obj.keys():
                full_path = f"{path}.{key}" if path else key

                # Check for dangerous key names
                if any(dangerous in str(key).lower() for dangerous in self.DANGEROUS_KEYS):
                    logger.critical(f"Dangerous key detected: {full_path}")
                    raise ValidationError(
                        f"Pattern data contains prohibited key: {key}"
                    )

            # Check values recursively
            for key, value in obj.items():
                full_path = f"{path}.{key}" if path else key
                self._check_dangerous_content(value, full_path)

        elif isinstance(obj, list):
            # Check list size
            if len(obj) > self.MAX_LIST_SIZE:
                raise ValidationError(
                    f"List at {path} exceeds maximum size of {self.MAX_LIST_SIZE}"
                )

            # Check each item
            for i, item in enumerate(obj):
                self._check_dangerous_content(item, f"{path}[{i}]")

        elif isinstance(obj, str):
            # Check string length
            if len(obj) > self.MAX_STRING_LENGTH:
                raise ValidationError(
                    f"String at {path} exceeds maximum length of {self.MAX_STRING_LENGTH}"
                )

            # Check for SQL injection patterns
            from ..security.validators import SQLInjectionValidator
            sql_validator = SQLInjectionValidator()

            try:
                sql_validator.validate_query_parameter(obj, path)
            except Exception:
                logger.critical(f"SQL injection pattern detected at {path}: {obj[:100]}")
                raise ValidationError(
                    f"Pattern data contains SQL injection pattern at {path}"
                )

    def _sanitize_values(self, obj: Any) -> Any:
        """Recursively sanitize all string values"""
        if isinstance(obj, dict):
            return {k: self._sanitize_values(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_values(item) for item in obj]
        elif isinstance(obj, str):
            from ..security.validators import sanitize_input
            return sanitize_input(obj, "pattern_data", allow_html=False)
        return obj


# ============================================================================
# CRITICAL-004: SQL Injection Protection
# ============================================================================

class SecureMemoryQuery:
    """SQL injection-safe memory queries"""

    @staticmethod
    async def search_memories(
        session: AsyncSession,
        query: str,
        agent_id: str,
        limit: int = 10
    ) -> List:
        """
        Search memories with SQL injection protection.

        Security measures:
        1. Input validation
        2. Parameterized queries
        3. LIKE clause escaping
        4. Agent-level access control
        """
        from ..security.validators import SQLInjectionValidator
        from ..models import Memory

        # 1. Validate query
        sql_validator = SQLInjectionValidator()
        try:
            validated_query = sql_validator.validate_query_parameter(query, "memory_query")
        except Exception as e:
            logger.critical(f"SQL injection attempt blocked: {query}")
            raise SecurityError(f"Invalid query: {e}")

        # 2. Escape LIKE special characters
        # PostgreSQL: % and _ need escaping
        escaped_query = validated_query.replace('\\', '\\\\')  # Escape backslash first
        escaped_query = escaped_query.replace('%', r'\%')
        escaped_query = escaped_query.replace('_', r'\_')

        # 3. Use parameterized query with escape clause
        stmt = select(Memory).where(
            text("content ILIKE :query_pattern ESCAPE '\\\\'")
        ).where(
            # Add agent-level access control
            text("(agent_id = :agent_id OR access_level = 'public')")
        ).order_by(
            Memory.importance.desc()
        ).limit(limit).params(
            query_pattern=f"%{escaped_query}%",
            agent_id=agent_id
        )

        # 4. Execute safe query
        result = await session.execute(stmt)
        memories = result.scalars().all()

        # 5. Filter by detailed access control
        accessible_memories = [
            m for m in memories
            if await SecureMemoryQuery._check_memory_access(agent_id, m)
        ]

        return accessible_memories

    @staticmethod
    async def _check_memory_access(agent_id: str, memory) -> bool:
        """Check if agent can access memory"""
        # Owner can access
        if memory.agent_id == agent_id:
            return True

        # Public memories
        if memory.access_level == "public":
            return True

        # Shared memories
        if memory.access_level == "shared" and hasattr(memory, 'shared_with_agents'):
            return agent_id in (memory.shared_with_agents or [])

        # Default deny
        return False


# ============================================================================
# HIGH-005: ReDoS Protection
# ============================================================================

class SafeRegexCompiler:
    """Compile regex patterns with ReDoS protection"""

    # Patterns that indicate potential ReDoS
    REDOS_PATTERNS = [
        r'\(\w\+\)\+',      # (a+)+
        r'\(\w\*\)\+',      # (a*)+
        r'\(\w\+\)\*',      # (a+)*
        r'\(\.\*\)\+',      # (.*)+
        r'\(\.\+\)\+',      # (.+)+
        r'\(\w\+\)\{2,\}',  # (a+){2,}
        r'\(\.\*\)\{2,\}',  # (.*){2,}
    ]

    MAX_PATTERN_LENGTH = 500
    MAX_NESTING_DEPTH = 10
    MAX_UNBOUNDED_REPETITIONS = 5
    COMPILE_TIMEOUT_SECONDS = 1

    @classmethod
    def compile_safe_regex(cls, pattern: str, flags: int = 0) -> Pattern:
        """
        Compile regex with comprehensive ReDoS protection.

        Raises:
            ValidationError: If pattern is unsafe
            TimeoutError: If compilation takes too long
        """
        # 1. Validate pattern safety
        if not cls._is_safe_pattern(pattern):
            raise ValidationError(f"Unsafe regex pattern detected: {pattern}")

        # 2. Compile with timeout
        try:
            compiled = cls._compile_with_timeout(pattern, flags)
            return compiled
        except TimeoutError:
            logger.critical(f"Regex compilation timeout: {pattern}")
            raise ValidationError("Regex pattern too complex (compilation timeout)")

    @classmethod
    def _is_safe_pattern(cls, pattern: str) -> bool:
        """Check if pattern is safe from ReDoS"""
        # Check length
        if len(pattern) > cls.MAX_PATTERN_LENGTH:
            logger.warning(f"Regex pattern too long: {len(pattern)} chars")
            return False

        # Check for known ReDoS patterns
        for redos_pattern in cls.REDOS_PATTERNS:
            if re.search(redos_pattern, pattern):
                logger.critical(f"ReDoS pattern detected: {pattern}")
                return False

        # Check nesting depth
        nesting_depth = pattern.count('(') - pattern.count(r'\(')
        if nesting_depth > cls.MAX_NESTING_DEPTH:
            logger.warning(f"Regex nesting too deep: {nesting_depth}")
            return False

        # Check unbounded repetitions
        unbounded_count = sum([
            len(re.findall(r'(?<!\\)\*', pattern)),
            len(re.findall(r'(?<!\\)\+', pattern)),
            len(re.findall(r'(?<!\\)\{\\d+,\}', pattern))
        ])

        if unbounded_count > cls.MAX_UNBOUNDED_REPETITIONS:
            logger.warning(f"Too many unbounded repetitions: {unbounded_count}")
            return False

        return True

    @classmethod
    def _compile_with_timeout(cls, pattern: str, flags: int) -> Pattern:
        """Compile regex with timeout using thread"""
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(re.compile, pattern, flags)
            try:
                compiled = future.result(timeout=cls.COMPILE_TIMEOUT_SECONDS)
                return compiled
            except concurrent.futures.TimeoutError:
                raise TimeoutError(f"Regex compilation timeout after {cls.COMPILE_TIMEOUT_SECONDS}s")


# ============================================================================
# Exceptions
# ============================================================================

class ValidationError(Exception):
    """Validation error"""
    pass


class SecurityError(Exception):
    """Security violation"""
    pass


class QuotaExceededError(Exception):
    """Resource quota exceeded"""
    pass


# ============================================================================
# Usage Examples
# ============================================================================

async def example_secure_pattern_execution():
    """Example of secure pattern execution"""
    from ..core.database import get_db_session

    async with get_db_session() as session:
        engine = SecurePatternExecutionEngine(
            session=session,
            cache_manager=None,
            registry=None
        )

        # Execute pattern with authentication
        try:
            result = await engine.execute(
                query="analyze codebase",
                agent_id="artemis-optimizer",  # REQUIRED
                execution_mode="BALANCED",
                context={"client_ip": "127.0.0.1"},
                use_cache=True
            )
            print(f"Success: {result}")
        except PermissionError as e:
            print(f"Access denied: {e}")
        except QuotaExceededError as e:
            print(f"Quota exceeded: {e}")


async def example_pattern_data_validation():
    """Example of pattern data validation"""
    validator = SecurePatternDataValidator()

    # Safe pattern data
    safe_data = {
        "type": "optimization",
        "parameters": {
            "threshold": 0.8,
            "mode": "aggressive"
        },
        "metadata": {
            "description": "Performance optimization pattern"
        }
    }

    try:
        validated = validator.validate_pattern_data(safe_data)
        print(f"Validation passed: {validated}")
    except ValidationError as e:
        print(f"Validation failed: {e}")

    # Malicious pattern data
    malicious_data = {
        "type": "malicious",
        "exec": "import os; os.system('rm -rf /')",  # Dangerous key
        "sql_template": "SELECT * FROM users WHERE id = ? OR 1=1--"  # SQL injection
    }

    try:
        validated = validator.validate_pattern_data(malicious_data)
        print("ERROR: Should have been blocked!")
    except ValidationError as e:
        print(f"Attack blocked: {e}")


async def example_safe_memory_search():
    """Example of SQL injection-safe memory search"""
    from ..core.database import get_db_session

    async with get_db_session() as session:
        # Safe search
        results = await SecureMemoryQuery.search_memories(
            session=session,
            query="optimization patterns",
            agent_id="artemis-optimizer",
            limit=10
        )
        print(f"Found {len(results)} memories")

        # SQL injection attempt (will be blocked)
        try:
            malicious_query = "' OR 1=1 UNION SELECT * FROM memories--"
            results = await SecureMemoryQuery.search_memories(
                session=session,
                query=malicious_query,
                agent_id="malicious-agent",
                limit=10
            )
            print("ERROR: SQL injection should have been blocked!")
        except SecurityError as e:
            print(f"SQL injection blocked: {e}")


def example_safe_regex_compilation():
    """Example of safe regex compilation"""
    compiler = SafeRegexCompiler()

    # Safe pattern
    safe_pattern = r'(analyze|search|find)\s+\w+'
    try:
        regex = compiler.compile_safe_regex(safe_pattern, re.IGNORECASE)
        print(f"Compiled successfully: {regex.pattern}")
    except ValidationError as e:
        print(f"Pattern rejected: {e}")

    # ReDoS pattern (will be rejected)
    redos_pattern = r'(a+)+'
    try:
        regex = compiler.compile_safe_regex(redos_pattern)
        print("ERROR: ReDoS pattern should have been rejected!")
    except ValidationError as e:
        print(f"ReDoS attack blocked: {e}")


if __name__ == "__main__":
    """Run examples"""
    print("=== TMWS Security Remediation Examples ===\n")

    # Run async examples
    asyncio.run(example_secure_pattern_execution())
    asyncio.run(example_pattern_data_validation())
    asyncio.run(example_safe_memory_search())

    # Run sync examples
    example_safe_regex_compilation()
