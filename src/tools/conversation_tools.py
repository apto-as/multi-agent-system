"""Conversation logging tools for TMWS MCP Server.

Provides tools for logging and retrieving SubAgent conversation data.
"""

from datetime import datetime
from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from .base_tool import BaseTool


class ConversationLogRequest(BaseModel):
    """Request to log a conversation message."""

    agent_id: str = Field(..., description="Agent identifier (e.g., 'artemis-optimizer')")
    session_id: str = Field(..., description="Session identifier for grouping messages")
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional context (task_type, phase, etc.)"
    )
    parent_message_id: str | None = Field(None, description="Parent message ID for threading")
    response_time_ms: int | None = Field(None, description="Response time in milliseconds")
    store_in_memory: bool = Field(
        default=True, description="Whether to also store in TMWS memory"
    )


class ConversationSearchRequest(BaseModel):
    """Request to search conversation logs."""

    agent_id: str | None = Field(None, description="Filter by agent")
    session_id: str | None = Field(None, description="Filter by session")
    role: str | None = Field(None, description="Filter by role")
    content_contains: str | None = Field(None, description="Search content (case-insensitive)")
    start_time: str | None = Field(None, description="Filter by timestamp >= start_time (ISO)")
    end_time: str | None = Field(None, description="Filter by timestamp <= end_time (ISO)")
    pattern_extracted: bool | None = Field(None, description="Filter by pattern extraction status")
    skill_candidate: bool | None = Field(None, description="Filter by skill candidate status")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum results")


class ConversationTools(BaseTool):
    """Conversation logging tools for TMWS MCP server."""

    async def register_tools(self, mcp: FastMCP) -> None:
        """Register conversation tools with FastMCP instance."""

        @mcp.tool()
        async def log_subagent_message(
            agent_id: str,
            session_id: str,
            role: str,
            content: str,
            metadata: dict[str, Any] = None,
            parent_message_id: str | None = None,
            response_time_ms: int | None = None,
            store_in_memory: bool = True,
        ) -> dict[str, Any]:
            """Log a SubAgent conversation message.

            Records SubAgent (Hera, Athena, Artemis, etc.) conversation messages
            for pattern learning and Skills auto-generation. Optionally stores
            in TMWS memory for semantic search.

            Args:
                agent_id: Agent identifier (e.g., 'artemis-optimizer')
                session_id: Session identifier for grouping messages
                role: Message role ('user' or 'assistant')
                content: Message content
                metadata: Additional context (task_type, phase, success_status, etc.)
                parent_message_id: Parent message ID for threading
                response_time_ms: Response time in milliseconds
                store_in_memory: Whether to also store in TMWS memory

            Returns:
                Dict containing log entry details and memory ID if stored

            """
            request = ConversationLogRequest(
                agent_id=agent_id,
                session_id=session_id,
                role=role,
                content=content,
                metadata=metadata or {},
                parent_message_id=parent_message_id,
                response_time_ms=response_time_ms,
                store_in_memory=store_in_memory,
            )

            async def _log_message(_session, services):
                conversation_service = services["conversation_log_service"]

                log_entry, memory_entry = await conversation_service.log_message_with_memory(
                    agent_id=request.agent_id,
                    session_id=request.session_id,
                    role=request.role,
                    content=request.content,
                    metadata=request.metadata,
                    parent_message_id=request.parent_message_id,
                    response_time_ms=request.response_time_ms,
                    store_in_memory=request.store_in_memory,
                )

                return {
                    "log_id": str(log_entry.id),
                    "agent_id": log_entry.agent_id,
                    "session_id": log_entry.session_id,
                    "role": log_entry.role,
                    "timestamp": log_entry.timestamp.isoformat(),
                    "memory_id": str(memory_entry.id) if memory_entry else None,
                    "stored_in_memory": memory_entry is not None,
                }

            result = await self.execute_with_session(_log_message)
            return self.format_success(result, "Message logged successfully")

        @mcp.tool()
        async def get_subagent_conversation(
            session_id: str,
            agent_id: str | None = None,
            limit: int = 100,
        ) -> dict[str, Any]:
            """Get all messages for a SubAgent conversation session.

            Retrieves the complete conversation history for a session,
            ordered by timestamp.

            Args:
                session_id: Session identifier
                agent_id: Optional filter by agent
                limit: Maximum number of messages to return

            Returns:
                Dict containing session metadata and message list

            """

            async def _get_conversation(_session, services):
                conversation_service = services["conversation_log_service"]

                # Get session metadata
                try:
                    session = await conversation_service.get_session(session_id)
                    session_data = session.to_dict()
                except Exception:
                    session_data = None

                # Get logs
                logs = await conversation_service.get_session_logs(
                    session_id=session_id, agent_id=agent_id, limit=limit
                )

                return {
                    "session_id": session_id,
                    "session": session_data,
                    "message_count": len(logs),
                    "messages": [log.to_dict() for log in logs],
                }

            result = await self.execute_with_session(_get_conversation)
            return self.format_success(
                result, f"Retrieved {result.get('message_count', 0)} messages"
            )

        @mcp.tool()
        async def search_subagent_conversations(
            agent_id: str | None = None,
            session_id: str | None = None,
            role: str | None = None,
            content_contains: str | None = None,
            start_time: str | None = None,
            end_time: str | None = None,
            pattern_extracted: bool | None = None,
            skill_candidate: bool | None = None,
            limit: int = 100,
        ) -> dict[str, Any]:
            """Search SubAgent conversation logs.

            Flexible search across conversation logs with multiple filter options.
            Useful for finding patterns, analyzing agent performance, and
            identifying skill candidates.

            Args:
                agent_id: Filter by agent
                session_id: Filter by session
                role: Filter by role ('user' or 'assistant')
                content_contains: Search content (case-insensitive)
                start_time: Filter by timestamp >= start_time (ISO format)
                end_time: Filter by timestamp <= end_time (ISO format)
                pattern_extracted: Filter by pattern extraction status
                skill_candidate: Filter by skill candidate status
                limit: Maximum results

            Returns:
                Dict containing search results

            """
            request = ConversationSearchRequest(
                agent_id=agent_id,
                session_id=session_id,
                role=role,
                content_contains=content_contains,
                start_time=start_time,
                end_time=end_time,
                pattern_extracted=pattern_extracted,
                skill_candidate=skill_candidate,
                limit=limit,
            )

            async def _search_conversations(_session, services):
                conversation_service = services["conversation_log_service"]

                # Parse datetime filters
                start_dt = datetime.fromisoformat(request.start_time) if request.start_time else None
                end_dt = datetime.fromisoformat(request.end_time) if request.end_time else None

                logs = await conversation_service.search_logs(
                    agent_id=request.agent_id,
                    session_id=request.session_id,
                    role=request.role,
                    content_contains=request.content_contains,
                    start_time=start_dt,
                    end_time=end_dt,
                    pattern_extracted=request.pattern_extracted,
                    skill_candidate=request.skill_candidate,
                    limit=request.limit,
                )

                return {
                    "count": len(logs),
                    "filters": request.model_dump(exclude_none=True),
                    "results": [log.to_dict() for log in logs],
                }

            result = await self.execute_with_session(_search_conversations)
            return self.format_success(result, f"Found {result.get('count', 0)} matching logs")

        @mcp.tool()
        async def create_conversation_session(
            session_id: str,
            agent_id: str,
            task_type: str | None = None,
            phase: str | None = None,
        ) -> dict[str, Any]:
            """Create a new SubAgent conversation session.

            Initializes a session for tracking a complete SubAgent interaction.
            Should be called at the start of each SubAgent invocation.

            Args:
                session_id: Unique session identifier
                agent_id: Primary agent for this session
                task_type: Type of task (e.g., 'optimization', 'security_audit')
                phase: Trinitas phase (e.g., 'phase_1_strategic')

            Returns:
                Dict containing session details

            """

            async def _create_session(_session, services):
                conversation_service = services["conversation_log_service"]

                session = await conversation_service.create_session(
                    session_id=session_id, agent_id=agent_id, task_type=task_type, phase=phase
                )

                return session.to_dict()

            result = await self.execute_with_session(_create_session)
            return self.format_success(result, "Session created successfully")

        @mcp.tool()
        async def complete_conversation_session(
            session_id: str,
            success: bool,
            outcome: dict[str, Any] = None,
        ) -> dict[str, Any]:
            """Mark a SubAgent conversation session as completed.

            Records the final outcome of a session. Should be called at the
            end of each SubAgent invocation.

            Args:
                session_id: Session identifier
                success: Whether the session completed successfully
                outcome: Session outcome data (results, metrics, artifacts)

            Returns:
                Dict containing updated session details

            """

            async def _complete_session(_session, services):
                conversation_service = services["conversation_log_service"]

                session = await conversation_service.complete_session(
                    session_id=session_id, success=success, outcome=outcome or {}
                )

                return session.to_dict()

            result = await self.execute_with_session(_complete_session)
            return self.format_success(result, "Session completed successfully")

        @mcp.tool()
        async def export_conversations_for_learning(
            agent_id: str | None = None,
            task_type: str | None = None,
            success_only: bool = True,
            limit: int = 100,
        ) -> dict[str, Any]:
            """Export conversation data for pattern learning and Skills generation.

            Retrieves conversation sessions with all messages for analysis.
            Used by the autonomous learning system to identify patterns and
            auto-generate Skills.

            Args:
                agent_id: Filter by agent
                task_type: Filter by task type
                success_only: Only export successful sessions
                limit: Maximum sessions to export

            Returns:
                Dict containing exported session data

            """

            async def _export_conversations(_session, services):
                conversation_service = services["conversation_log_service"]

                export_data = await conversation_service.export_for_learning(
                    agent_id=agent_id, task_type=task_type, success_only=success_only, limit=limit
                )

                return {
                    "session_count": len(export_data),
                    "sessions": export_data,
                    "filters": {
                        "agent_id": agent_id,
                        "task_type": task_type,
                        "success_only": success_only,
                    },
                }

            result = await self.execute_with_session(_export_conversations)
            return self.format_success(
                result, f"Exported {result.get('session_count', 0)} sessions"
            )

        @mcp.tool()
        async def mark_conversation_as_skill_candidate(session_id: str) -> dict[str, Any]:
            """Mark all logs in a session as skill candidates.

            Flags a successful conversation session for potential conversion
            into a reusable Skill.

            Args:
                session_id: Session identifier

            Returns:
                Dict containing count of logs marked

            """

            async def _mark_skill_candidate(_session, services):
                conversation_service = services["conversation_log_service"]

                count = await conversation_service.mark_as_skill_candidate(session_id=session_id)

                return {"session_id": session_id, "logs_marked": count}

            result = await self.execute_with_session(_mark_skill_candidate)
            return self.format_success(
                result, f"Marked {result.get('logs_marked', 0)} logs as skill candidates"
            )

        @mcp.tool()
        async def get_conversation_statistics(
            agent_id: str | None = None,
            start_time: str | None = None,
            end_time: str | None = None,
        ) -> dict[str, Any]:
            """Get statistics about SubAgent conversations.

            Provides analytics on conversation volume, agent usage, and
            skill candidates.

            Args:
                agent_id: Filter by agent
                start_time: Start time filter (ISO format)
                end_time: End time filter (ISO format)

            Returns:
                Dict containing conversation statistics

            """

            async def _get_statistics(_session, services):
                conversation_service = services["conversation_log_service"]

                # Parse datetime filters
                start_dt = datetime.fromisoformat(start_time) if start_time else None
                end_dt = datetime.fromisoformat(end_time) if end_time else None

                stats = await conversation_service.get_statistics(
                    agent_id=agent_id, start_time=start_dt, end_time=end_dt
                )

                return stats

            result = await self.execute_with_session(_get_statistics)
            return self.format_success(result, "Statistics retrieved successfully")
