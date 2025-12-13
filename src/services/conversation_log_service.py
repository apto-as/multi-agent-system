"""Conversation log service for SubAgent communication tracking.

Provides services for:
1. Logging SubAgent messages with TMWS memory integration
2. Retrieving conversation history and sessions
3. Searching conversations for pattern learning
4. Exporting data for Skills auto-generation
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import NotFoundError, ValidationError
from ..models.conversation_log import ConversationLog, ConversationSession
from ..models.memory import Memory
from .base_service import BaseService

logger = logging.getLogger(__name__)


class ConversationLogService(BaseService):
    """Service for managing SubAgent conversation logs."""

    CONVERSATION_NAMESPACE = "subagent-conversations"

    def __init__(self, session: AsyncSession):
        """Initialize conversation log service.

        Args:
            session: Database session

        """
        super().__init__(session)
        self.logger = logging.getLogger(self.__class__.__name__)

    def _sanitize_content(self, content: str) -> str:
        """Sanitize content to remove potential sensitive data before logging.

        HIGH-3 (Partial): Content sanitization to prevent credential leakage.

        Args:
            content: Raw message content

        Returns:
            Sanitized content with secrets redacted
        """
        # API keys and secrets (generic patterns)
        content = re.sub(
            r"(?i)(api[_-]?key|token|password|secret|credential)\s*[:=]\s*['\"]?\S+['\"]?",
            r"\1: [REDACTED]",
            content,
        )
        # AWS Access Keys (AKIA pattern)
        content = re.sub(r"AKIA[0-9A-Z]{16}", "[AWS_KEY_REDACTED]", content)
        # AWS Secret Keys (40 char base64-like)
        content = re.sub(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", "[AWS_SECRET_REDACTED]", content)
        # JWT tokens (eyJ pattern)
        content = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[JWT_REDACTED]",
            content,
        )
        # GitHub tokens
        content = re.sub(r"gh[pousr]_[A-Za-z0-9_]{36,}", "[GITHUB_TOKEN_REDACTED]", content)
        # Generic bearer tokens
        content = re.sub(r"(?i)bearer\s+[A-Za-z0-9_-]+", "Bearer [TOKEN_REDACTED]", content)
        return content

    async def log_message(
        self,
        agent_id: str,
        session_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        parent_message_id: str | None = None,
        response_time_ms: int | None = None,
    ) -> ConversationLog:
        """Log a SubAgent conversation message.

        Args:
            agent_id: Agent identifier (e.g., 'artemis-optimizer')
            session_id: Session identifier for grouping
            role: Message role ('user' or 'assistant')
            content: Message content
            metadata: Additional context (task_type, phase, etc.)
            parent_message_id: Parent message ID for threading
            response_time_ms: Response time in milliseconds

        Returns:
            Created ConversationLog instance

        Raises:
            ValidationError: If parameters are invalid

        """
        # Validate role
        if role not in ["user", "assistant"]:
            raise ValidationError(f"Invalid role: {role}. Must be 'user' or 'assistant'")

        # HIGH-3: Sanitize content to remove sensitive data
        sanitized_content = self._sanitize_content(content)

        # Create log entry
        log_entry = ConversationLog(
            id=str(uuid4()),
            agent_id=agent_id,
            session_id=session_id,
            role=role,
            content=sanitized_content,
            context_metadata=metadata or {},
            parent_message_id=parent_message_id,
            response_time_ms=response_time_ms,
            timestamp=datetime.now(timezone.utc),
            pattern_extracted=False,
            skill_candidate=False,
        )

        self.session.add(log_entry)
        await self.session.flush()
        await self.session.refresh(log_entry)

        self.logger.debug(
            f"Logged message for agent={agent_id}, session={session_id}, role={role}",
            extra={
                "agent_id": agent_id,
                "session_id": session_id,
                "role": role,
                "content_length": len(content),
            },
        )

        return log_entry

    async def log_message_with_memory(
        self,
        agent_id: str,
        session_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        parent_message_id: str | None = None,
        response_time_ms: int | None = None,
        store_in_memory: bool = True,
    ) -> tuple[ConversationLog, Memory | None]:
        """Log a message and optionally store in TMWS memory.

        Args:
            agent_id: Agent identifier
            session_id: Session identifier
            role: Message role
            content: Message content
            metadata: Additional context
            parent_message_id: Parent message ID
            response_time_ms: Response time
            store_in_memory: Whether to also store in TMWS memory

        Returns:
            Tuple of (ConversationLog, Memory or None)

        """
        # HIGH-3: Sanitize content before any storage
        sanitized_content = self._sanitize_content(content)

        # Create log entry (will also sanitize internally, but we pre-sanitize for memory)
        log_entry = await self.log_message(
            agent_id=agent_id,
            session_id=session_id,
            role=role,
            content=content,  # log_message will sanitize internally
            metadata=metadata,
            parent_message_id=parent_message_id,
            response_time_ms=response_time_ms,
        )

        memory_entry = None
        if store_in_memory:
            # Store in TMWS memory for semantic search (using sanitized content)
            memory_entry = Memory(
                id=str(uuid4()),
                content=sanitized_content,
                summary=f"[{role.upper()}] {agent_id}: {sanitized_content[:100]}...",
                agent_id=agent_id,
                namespace=self.CONVERSATION_NAMESPACE,
                tags=["conversation", agent_id, session_id, role],
                context={
                    "conversation_log_id": str(log_entry.id),
                    "session_id": session_id,
                    "role": role,
                    "timestamp": log_entry.timestamp.isoformat(),
                    **(metadata or {}),
                },
                importance_score=0.6,  # Moderate importance by default
            )
            self.session.add(memory_entry)
            await self.session.flush()
            await self.session.refresh(memory_entry)

            self.logger.debug(
                f"Stored conversation in memory: {memory_entry.id}",
                extra={"memory_id": str(memory_entry.id), "log_id": str(log_entry.id)},
            )

        return log_entry, memory_entry

    async def get_session_logs(
        self,
        session_id: str,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[ConversationLog]:
        """Get all logs for a conversation session.

        Args:
            session_id: Session identifier
            agent_id: Optional filter by agent
            limit: Maximum number of logs to return

        Returns:
            List of ConversationLog instances ordered by timestamp

        """
        query = select(ConversationLog).where(ConversationLog.session_id == session_id)

        if agent_id:
            query = query.where(ConversationLog.agent_id == agent_id)

        query = query.order_by(ConversationLog.timestamp).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def search_logs(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        role: str | None = None,
        content_contains: str | None = None,
        metadata_filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        pattern_extracted: bool | None = None,
        skill_candidate: bool | None = None,
        limit: int = 100,
    ) -> list[ConversationLog]:
        """Search conversation logs with flexible filters.

        Args:
            agent_id: Filter by agent
            session_id: Filter by session
            role: Filter by role
            content_contains: Search content (case-insensitive)
            metadata_filters: Key-value filters for metadata JSON
            start_time: Filter by timestamp >= start_time
            end_time: Filter by timestamp <= end_time
            pattern_extracted: Filter by pattern extraction status
            skill_candidate: Filter by skill candidate status
            limit: Maximum results

        Returns:
            List of matching ConversationLog instances

        """
        query = select(ConversationLog)

        # Build filters
        filters = []
        if agent_id:
            filters.append(ConversationLog.agent_id == agent_id)
        if session_id:
            filters.append(ConversationLog.session_id == session_id)
        if role:
            filters.append(ConversationLog.role == role)
        if content_contains:
            # CRITICAL-1 FIX: Escape SQL LIKE special characters to prevent injection
            escaped = (
                content_contains.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            filters.append(ConversationLog.content.ilike(f"%{escaped}%", escape="\\"))
        if start_time:
            filters.append(ConversationLog.timestamp >= start_time)
        if end_time:
            filters.append(ConversationLog.timestamp <= end_time)
        if pattern_extracted is not None:
            filters.append(ConversationLog.pattern_extracted == pattern_extracted)
        if skill_candidate is not None:
            filters.append(ConversationLog.skill_candidate == skill_candidate)

        if filters:
            query = query.where(and_(*filters))

        # Order and limit
        query = query.order_by(desc(ConversationLog.timestamp)).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def create_session(
        self,
        session_id: str,
        agent_id: str,
        task_type: str | None = None,
        phase: str | None = None,
    ) -> ConversationSession:
        """Create a new conversation session.

        Args:
            session_id: Unique session identifier
            agent_id: Primary agent for this session
            task_type: Type of task
            phase: Trinitas phase

        Returns:
            Created ConversationSession instance

        """
        session = ConversationSession(
            id=str(uuid4()),
            session_id=session_id,
            agent_id=agent_id,
            task_type=task_type,
            phase=phase,
            started_at=datetime.now(timezone.utc),
            success=None,
            outcome={},
            learning_patterns=[],
            skills_generated=[],
        )

        self.session.add(session)
        await self.session.flush()
        await self.session.refresh(session)

        self.logger.info(
            f"Created session: {session_id} for agent={agent_id}",
            extra={"session_id": session_id, "agent_id": agent_id, "task_type": task_type},
        )

        return session

    async def complete_session(
        self,
        session_id: str,
        success: bool,
        outcome: dict[str, Any] | None = None,
    ) -> ConversationSession:
        """Mark a conversation session as completed.

        Args:
            session_id: Session identifier
            success: Whether the session completed successfully
            outcome: Session outcome data

        Returns:
            Updated ConversationSession instance

        Raises:
            NotFoundError: If session not found

        """
        query = select(ConversationSession).where(ConversationSession.session_id == session_id)
        result = await self.session.execute(query)
        session = result.scalar_one_or_none()

        if not session:
            raise NotFoundError(f"Session not found: {session_id}")

        session.completed_at = datetime.now(timezone.utc)
        session.success = success
        if outcome:
            session.outcome.update(outcome)

        await self.session.flush()
        await self.session.refresh(session)

        self.logger.info(
            f"Completed session: {session_id}, success={success}",
            extra={"session_id": session_id, "success": success},
        )

        return session

    async def get_session(self, session_id: str) -> ConversationSession:
        """Get a conversation session by ID.

        Args:
            session_id: Session identifier

        Returns:
            ConversationSession instance

        Raises:
            NotFoundError: If session not found

        """
        query = select(ConversationSession).where(ConversationSession.session_id == session_id)
        result = await self.session.execute(query)
        session = result.scalar_one_or_none()

        if not session:
            raise NotFoundError(f"Session not found: {session_id}")

        return session

    async def export_for_learning(
        self,
        agent_id: str | None = None,
        task_type: str | None = None,
        success_only: bool = True,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Export conversation data for pattern learning and Skills generation.

        Args:
            agent_id: Filter by agent
            task_type: Filter by task type
            success_only: Only export successful sessions
            limit: Maximum sessions to export

        Returns:
            List of session data dictionaries with messages

        """
        # Query sessions
        query = select(ConversationSession)

        filters = []
        if agent_id:
            filters.append(ConversationSession.agent_id == agent_id)
        if task_type:
            filters.append(ConversationSession.task_type == task_type)
        if success_only:
            filters.append(ConversationSession.success == True)  # noqa: E712

        if filters:
            query = query.where(and_(*filters))

        query = query.order_by(desc(ConversationSession.started_at)).limit(limit)

        result = await self.session.execute(query)
        sessions = list(result.scalars().all())

        # Build export data
        export_data = []
        for session in sessions:
            # Get all logs for this session
            logs = await self.get_session_logs(session.session_id)

            export_data.append(
                {
                    "session": session.to_dict(),
                    "messages": [log.to_dict() for log in logs],
                    "message_count": len(logs),
                    "duration_seconds": (
                        (session.completed_at - session.started_at).total_seconds()
                        if session.completed_at
                        else None
                    ),
                }
            )

        self.logger.info(
            f"Exported {len(export_data)} sessions for learning",
            extra={
                "agent_id": agent_id,
                "task_type": task_type,
                "session_count": len(export_data),
            },
        )

        return export_data

    async def mark_for_pattern_extraction(self, log_ids: list[UUID]) -> int:
        """Mark conversation logs for pattern extraction.

        Args:
            log_ids: List of log UUIDs

        Returns:
            Number of logs updated

        """
        query = (
            select(ConversationLog)
            .where(ConversationLog.id.in_(log_ids))
            .where(ConversationLog.pattern_extracted == False)  # noqa: E712
        )

        result = await self.session.execute(query)
        logs = list(result.scalars().all())

        for log in logs:
            log.pattern_extracted = True

        await self.session.flush()

        self.logger.info(f"Marked {len(logs)} logs for pattern extraction")
        return len(logs)

    async def mark_as_skill_candidate(self, session_id: str) -> int:
        """Mark all logs in a session as skill candidates.

        Args:
            session_id: Session identifier

        Returns:
            Number of logs marked

        """
        query = select(ConversationLog).where(
            and_(
                ConversationLog.session_id == session_id,
                ConversationLog.skill_candidate == False,  # noqa: E712
            )
        )

        result = await self.session.execute(query)
        logs = list(result.scalars().all())

        for log in logs:
            log.skill_candidate = True

        await self.session.flush()

        self.logger.info(
            f"Marked {len(logs)} logs as skill candidates for session={session_id}",
            extra={"session_id": session_id, "count": len(logs)},
        )
        return len(logs)

    async def get_statistics(
        self,
        agent_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Get conversation log statistics.

        Args:
            agent_id: Filter by agent
            start_time: Start time filter
            end_time: End time filter

        Returns:
            Statistics dictionary

        """
        # Build base filters
        log_filters = []
        session_filters = []

        if agent_id:
            log_filters.append(ConversationLog.agent_id == agent_id)
            session_filters.append(ConversationSession.agent_id == agent_id)
        if start_time:
            log_filters.append(ConversationLog.timestamp >= start_time)
            session_filters.append(ConversationSession.started_at >= start_time)
        if end_time:
            log_filters.append(ConversationLog.timestamp <= end_time)
            session_filters.append(ConversationSession.started_at <= end_time)

        # Count total logs
        query = select(func.count(ConversationLog.id))
        if log_filters:
            query = query.where(and_(*log_filters))
        result = await self.session.execute(query)
        total_logs = result.scalar_one()

        # Count total sessions
        query = select(func.count(ConversationSession.id))
        if session_filters:
            query = query.where(and_(*session_filters))
        result = await self.session.execute(query)
        total_sessions = result.scalar_one()

        # Count by agent
        query = (
            select(ConversationLog.agent_id, func.count(ConversationLog.id))
            .group_by(ConversationLog.agent_id)
            .order_by(desc(func.count(ConversationLog.id)))
            .limit(10)
        )
        if log_filters:
            query = query.where(and_(*log_filters))
        result = await self.session.execute(query)
        by_agent = {agent: count for agent, count in result.all()}

        # Count skill candidates
        query = select(func.count(ConversationLog.id)).where(
            ConversationLog.skill_candidate == True  # noqa: E712
        )
        if log_filters:
            query = query.where(and_(*log_filters))
        result = await self.session.execute(query)
        skill_candidates = result.scalar_one()

        return {
            "total_logs": total_logs,
            "total_sessions": total_sessions,
            "logs_by_agent": by_agent,
            "skill_candidates": skill_candidates,
            "filters": {
                "agent_id": agent_id,
                "start_time": start_time.isoformat() if start_time else None,
                "end_time": end_time.isoformat() if end_time else None,
            },
        }
