"""Synchronous Event Dispatcher

Phase 1-2 implementation with error isolation.

Critical Rules:
1. Must be called AFTER transaction commit
2. Handler failures must NOT rollback main transaction
3. Handlers must be idempotent (may be called multiple times)
"""

import asyncio
import logging
from typing import Callable, Dict, List

from src.application.events.dispatcher import EventDispatcher
from src.domain.events import DomainEvent

logger = logging.getLogger(__name__)


class SynchronousEventDispatcher(EventDispatcher):
    """Synchronous event dispatcher for Phase 1-2"""

    def __init__(self):
        self._handlers: Dict[type[DomainEvent], List[Callable]] = {}

    def register(
        self,
        event_type: type[DomainEvent],
        handler: Callable,
    ):
        """Register event handler for specific event type"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []

        self._handlers[event_type].append(handler)

        handler_name = getattr(handler, "__name__", repr(handler))
        logger.info(
            f"Registered handler {handler_name} " f"for event {event_type.__name__}"
        )

    async def dispatch_all(self, events: List[DomainEvent]):
        """
        Dispatch all events to registered handlers

        Critical Rules:
        1. Must be called AFTER transaction commit
        2. Handler failures must NOT rollback main transaction
        3. Handlers must be idempotent (may be called multiple times)
        """
        for event in events:
            await self._dispatch_single(event)

    async def _dispatch_single(self, event: DomainEvent):
        """Dispatch single event to all registered handlers"""
        event_type = type(event)
        handlers = self._handlers.get(event_type, [])

        if not handlers:
            logger.debug(f"No handlers registered for {event_type.__name__}")
            return

        logger.info(
            f"Dispatching {event_type.__name__} to {len(handlers)} handlers"
        )

        for handler in handlers:
            await self._execute_handler(handler, event)

    async def _execute_handler(self, handler: Callable, event: DomainEvent):
        """Execute single event handler with error isolation"""
        handler_name = getattr(handler, "__name__", repr(handler))

        try:
            # Support both sync and async handlers
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                # Run sync handler in thread pool to avoid blocking
                await asyncio.to_thread(handler, event)

            logger.debug(f"Handler {handler_name} completed successfully")

        except Exception as e:
            # CRITICAL: Handler failure must NOT affect main transaction
            logger.error(
                f"Event handler {handler_name} failed for "
                f"{type(event).__name__}: {e}",
                exc_info=True,
            )
            # Error is logged but NOT raised - error isolation
