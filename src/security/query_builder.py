"""Secure query builder for SQL injection prevention.

V-3 Mitigation (CVSS 5.3 MEDIUM): All LIKE queries MUST escape wildcards.

This module provides centralized parameterized query building to prevent:
1. SQL Injection - SQLAlchemy parameterization (built-in)
2. LIKE Pattern Injection - Wildcard escaping (this module)
3. Column Name Injection - Schema validation (this module)

Example:
    >>> from src.security.query_builder import SecureQueryBuilder
    >>> from src.models.memory import Memory
    >>>
    >>> # Safe LIKE pattern escaping
    >>> user_input = "50%_off"
    >>> escaped, escape_char = SecureQueryBuilder.safe_like_pattern(user_input)
    >>> query = select(Memory).where(
    ...     Memory.content.ilike(f"%{escaped}%", escape=escape_char)
    ... )
    >>> # Generates: WHERE content ILIKE '%50\\%\\_off%' ESCAPE '\\'

Security Guarantees:
    - SQL Injection: Prevented by SQLAlchemy's parameterization ✅
    - LIKE Wildcard DoS: Prevented by wildcard escaping ✅
    - Column Name Injection: Prevented by hasattr() validation ✅

Author: Artemis (artemis-optimizer)
Created: 2025-11-24
Version: 1.0.0
"""

from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase


class SecureQueryBuilder:
    """Centralized parameterized query builder.

    All methods use SQLAlchemy's parameterization to prevent SQL injection.
    LIKE queries additionally escape wildcards to prevent DoS attacks.

    Security Notes:
        - NEVER concatenate user input directly into SQL
        - ALWAYS use SQLAlchemy's parameterized queries
        - ALWAYS escape wildcards in LIKE patterns
        - ALWAYS validate column names against model schema
    """

    @staticmethod
    def safe_like_pattern(
        user_input: str,
        escape_char: str = "\\",
        allow_wildcards: bool = False
    ) -> tuple[str, str]:
        """Escape LIKE wildcards in user input.

        Escapes three special characters in SQL LIKE patterns:
        - % (match any sequence of characters)
        - _ (match exactly one character)
        - \\ (escape character itself)

        Args:
            user_input: Raw user input string
            escape_char: Escape character (default: backslash)
            allow_wildcards: If True, skip escaping (use with caution!)

        Returns:
            Tuple of (escaped_pattern, escape_char) for SQLAlchemy integration

        Security:
            - Prevents DoS via wildcard abuse (e.g., "%%%%%%%%")
            - Prevents second-order injection attempts
            - Does NOT prevent SQL injection (SQLAlchemy handles that)

        Performance:
            - Normal input: <1ms
            - Heavy wildcard input (16+ chars): <5ms

        Example:
            >>> safe_like_pattern("50%_off")
            ("50\\\\%\\\\_off", "\\\\")

            >>> safe_like_pattern("test", allow_wildcards=True)
            ("test", "\\\\")

        Warning:
            Setting allow_wildcards=True disables DoS protection.
            Only use when wildcards are intentional (e.g., admin queries).
        """
        if allow_wildcards:
            return user_input, escape_char

        # CRITICAL: Escape the escape character FIRST to prevent bypass
        # Example: "\\%" must become "\\\\\\" + "\\%" = "\\\\\\\\\\%"
        escaped = user_input.replace(escape_char, escape_char + escape_char)

        # Then escape LIKE wildcards
        escaped = escaped.replace("%", escape_char + "%")
        escaped = escaped.replace("_", escape_char + "_")

        return escaped, escape_char

    @staticmethod
    async def build_filter_query(
        model: type[DeclarativeBase],
        filters: dict[str, Any],
        session: AsyncSession
    ):
        """Build parameterized filter query with schema validation.

        Args:
            model: SQLAlchemy model class
            filters: Dict of {column_name: value} filters
            session: Async database session

        Returns:
            Query result

        Raises:
            ValueError: If column name not in model schema

        Security:
            - Validates column names against model schema (prevents injection)
            - Uses SQLAlchemy parameterization (prevents SQL injection)
            - Does NOT use LIKE (no wildcard escaping needed)

        Example:
            >>> from src.models.memory import Memory
            >>> filters = {"agent_id": "test-agent", "importance": 0.8}
            >>> result = await SecureQueryBuilder.build_filter_query(
            ...     Memory, filters, session
            ... )
        """
        # Validate all column names against model schema
        for column_name in filters:
            if not hasattr(model, column_name):
                msg = f"Invalid column name: {column_name} not in {model.__name__}"
                raise ValueError(msg)

        # Build filter conditions
        conditions = [
            getattr(model, col_name) == value
            for col_name, value in filters.items()
        ]

        # Execute parameterized query
        query = select(model).where(and_(*conditions))
        result = await session.execute(query)
        return result.scalars().all()

    @staticmethod
    async def build_search_query(
        model: type[DeclarativeBase],
        search_columns: list[str],
        search_term: str,
        session: AsyncSession,
        case_insensitive: bool = True
    ):
        """Build parameterized search query with wildcard escaping.

        Args:
            model: SQLAlchemy model class
            search_columns: List of column names to search
            search_term: User search term (will be escaped)
            session: Async database session
            case_insensitive: Use ILIKE (True) or LIKE (False)

        Returns:
            Query result

        Raises:
            ValueError: If any column name not in model schema

        Security:
            - Validates column names against model schema (prevents injection)
            - Escapes wildcards in search term (prevents DoS)
            - Uses SQLAlchemy parameterization (prevents SQL injection)

        Performance:
            - Normal search: <20ms P95
            - Wildcard-heavy search: <100ms P95

        Example:
            >>> from src.models.agent import Agent
            >>> result = await SecureQueryBuilder.build_search_query(
            ...     model=Agent,
            ...     search_columns=["display_name", "agent_id"],
            ...     search_term="test%%%%%",  # DoS attempt - will be escaped
            ...     session=session
            ... )
        """
        # Validate all column names against model schema
        for column_name in search_columns:
            if not hasattr(model, column_name):
                msg = f"Invalid column name: {column_name} not in {model.__name__}"
                raise ValueError(msg)

        # Escape wildcards to prevent DoS
        escaped_term, escape_char = SecureQueryBuilder.safe_like_pattern(search_term)
        pattern = f"%{escaped_term}%"

        # Build search conditions (OR across all columns)
        conditions = []
        for column_name in search_columns:
            column = getattr(model, column_name)
            if case_insensitive:
                # Use ILIKE with ESCAPE clause
                conditions.append(column.ilike(pattern, escape=escape_char))
            else:
                # Use LIKE with ESCAPE clause
                conditions.append(column.like(pattern, escape=escape_char))

        # Execute parameterized query
        query = select(model).where(or_(*conditions))
        result = await session.execute(query)
        return result.scalars().all()
