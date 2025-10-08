"""
PostgreSQL LISTEN/NOTIFY coordinator for real-time synchronization
TMWS v2.2.0
"""

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)


class NotificationCoordinator:
    """
    Manages PostgreSQL LISTEN/NOTIFY for real-time synchronization
    between multiple MCP server instances
    """

    def __init__(self, db_pool: asyncpg.Pool):
        """
        Initialize notification coordinator

        Args:
            db_pool: AsyncPG connection pool
        """
        self.db_pool = db_pool
        self.listeners: dict[str, list[Callable]] = {}
        self.active_channels: list[str] = []
        self.notification_conn: asyncpg.Connection | None = None
        self.running = False

        # Statistics
        self.stats = {
            "notifications_received": 0,
            "notifications_sent": 0,
            "errors": 0,
            "active_listeners": 0,
        }

    async def initialize(self):
        """Initialize notification system"""
        try:
            # Get dedicated connection for notifications
            self.notification_conn = await self.db_pool.acquire()

            # Start notification processor
            self.running = True
            asyncio.create_task(self._process_notifications())

            logger.info("Notification coordinator initialized")

        except Exception as e:
            logger.error(f"Failed to initialize notifications: {e}")
            raise

    async def subscribe(self, channel: str, callback: Callable[[dict], None]):
        """
        Subscribe to a notification channel

        Args:
            channel: PostgreSQL notification channel
            callback: Async function to call when notification received
        """
        if channel not in self.listeners:
            self.listeners[channel] = []
            # Start listening on new channel
            await self._listen_channel(channel)

        self.listeners[channel].append(callback)
        self.stats["active_listeners"] += 1

        logger.info(f"Subscribed to channel: {channel}")

    async def unsubscribe(self, channel: str, callback: Callable[[dict], None]):
        """
        Unsubscribe from a notification channel

        Args:
            channel: PostgreSQL notification channel
            callback: Callback to remove
        """
        if channel in self.listeners:
            try:
                self.listeners[channel].remove(callback)
                self.stats["active_listeners"] -= 1

                # If no more listeners, stop listening
                if not self.listeners[channel]:
                    await self._unlisten_channel(channel)
                    del self.listeners[channel]

            except ValueError:
                logger.warning(f"Callback not found for channel: {channel}")

    async def notify(self, channel: str, payload: dict[str, Any]):
        """
        Send notification to a channel

        Args:
            channel: PostgreSQL notification channel
            payload: Data to send
        """
        try:
            json_payload = json.dumps(payload)

            async with self.db_pool.acquire() as conn:
                await conn.execute(f"NOTIFY {channel}, $1", json_payload)

            self.stats["notifications_sent"] += 1

            logger.debug(f"Sent notification to {channel}: {payload}")

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Failed to send notification: {e}")

    async def _listen_channel(self, channel: str):
        """Start listening on a channel"""
        if self.notification_conn and channel not in self.active_channels:
            await self.notification_conn.execute(f"LISTEN {channel}")
            self.active_channels.append(channel)
            logger.info(f"Started listening on channel: {channel}")

    async def _unlisten_channel(self, channel: str):
        """Stop listening on a channel"""
        if self.notification_conn and channel in self.active_channels:
            await self.notification_conn.execute(f"UNLISTEN {channel}")
            self.active_channels.remove(channel)
            logger.info(f"Stopped listening on channel: {channel}")

    async def _process_notifications(self):
        """Process incoming notifications"""
        while self.running:
            try:
                if not self.notification_conn:
                    await asyncio.sleep(1)
                    continue

                # Wait for notification with timeout
                msg = await asyncio.wait_for(
                    self.notification_conn.wait_for_notification(), timeout=1.0
                )

                if msg:
                    self.stats["notifications_received"] += 1

                    # Parse payload
                    try:
                        payload = json.loads(msg.payload)
                    except json.JSONDecodeError:
                        payload = {"raw": msg.payload}

                    # Call listeners for this channel
                    channel = msg.channel
                    if channel in self.listeners:
                        for callback in self.listeners[channel]:
                            try:
                                # Run callback in background
                                asyncio.create_task(callback(payload))
                            except Exception as e:
                                logger.error(f"Callback error: {e}")
                                self.stats["errors"] += 1

            except asyncio.TimeoutError:
                # Timeout is normal, continue loop
                continue

            except Exception as e:
                logger.error(f"Notification processing error: {e}")
                self.stats["errors"] += 1
                await asyncio.sleep(1)

    async def cleanup(self):
        """Cleanup notification system"""
        self.running = False

        # Unlisten all channels
        for channel in list(self.active_channels):
            await self._unlisten_channel(channel)

        # Release connection
        if self.notification_conn:
            await self.db_pool.release(self.notification_conn)
            self.notification_conn = None

        logger.info("Notification coordinator cleaned up")

    def get_stats(self) -> dict[str, Any]:
        """Get notification statistics"""
        return {
            **self.stats,
            "active_channels": len(self.active_channels),
            "listener_count": sum(len(listeners) for listeners in self.listeners.values()),
        }


class ChangeNotifier:
    """
    Helper class for notifying changes to specific entities
    """

    def __init__(self, coordinator: NotificationCoordinator):
        """
        Initialize change notifier

        Args:
            coordinator: Notification coordinator
        """
        self.coordinator = coordinator

    async def notify_memory_change(
        self,
        operation: str,
        memory_id: str,
        agent_id: str,
        instance_id: str,
        visibility: str = "shared",
    ):
        """Notify memory change"""
        await self.coordinator.notify(
            "memory_changes",
            {
                "operation": operation,
                "memory_id": memory_id,
                "agent_id": agent_id,
                "instance_id": instance_id,
                "visibility": visibility,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    async def notify_task_change(
        self, operation: str, task_id: str, assigned_agent: str, status: str
    ):
        """Notify task change"""
        await self.coordinator.notify(
            "task_changes",
            {
                "operation": operation,
                "task_id": task_id,
                "assigned_agent": assigned_agent,
                "status": status,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    async def notify_agent_status(
        self, agent_id: str, instance_id: str, status: str, metadata: dict = None
    ):
        """Notify agent status change"""
        await self.coordinator.notify(
            "agent_status",
            {
                "agent_id": agent_id,
                "instance_id": instance_id,
                "status": status,
                "metadata": metadata or {},
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    async def broadcast_cache_invalidation(self, pattern: str, reason: str = None):
        """Broadcast cache invalidation to all instances"""
        await self.coordinator.notify(
            "cache_invalidation",
            {"pattern": pattern, "reason": reason, "timestamp": datetime.utcnow().isoformat()},
        )


class SyncHandler:
    """
    Handles synchronization events from other instances
    """

    def __init__(self, coordinator: NotificationCoordinator, cache_manager=None):
        """
        Initialize sync handler

        Args:
            coordinator: Notification coordinator
            cache_manager: Optional cache manager for invalidation
        """
        self.coordinator = coordinator
        self.cache_manager = cache_manager

    async def setup_handlers(self):
        """Setup default sync handlers"""

        # Memory change handler
        async def handle_memory_change(payload: dict):
            """Handle memory change notification"""
            logger.debug(f"Memory change: {payload}")

            # Invalidate cache if available
            if self.cache_manager and payload.get("visibility") == "shared":
                # Invalidate search cache
                await self.cache_manager.clear("search")

        # Task change handler
        async def handle_task_change(payload: dict):
            """Handle task change notification"""
            logger.debug(f"Task change: {payload}")

            # Invalidate task cache if available
            if self.cache_manager:
                await self.cache_manager.delete(payload["task_id"], namespace="tasks")

        # Cache invalidation handler
        async def handle_cache_invalidation(payload: dict):
            """Handle cache invalidation notification"""
            logger.info(f"Cache invalidation: {payload}")

            if self.cache_manager:
                pattern = payload.get("pattern", "*")
                if pattern == "*":
                    await self.cache_manager.clear()
                else:
                    # Pattern-based invalidation
                    await self._invalidate_pattern(pattern)

        # Agent status handler
        async def handle_agent_status(payload: dict):
            """Handle agent status notification"""
            logger.info(f"Agent status change: {payload}")

        # Subscribe to channels
        await self.coordinator.subscribe("memory_changes", handle_memory_change)
        await self.coordinator.subscribe("task_changes", handle_task_change)
        await self.coordinator.subscribe("cache_invalidation", handle_cache_invalidation)
        await self.coordinator.subscribe("agent_status", handle_agent_status)

        logger.info("Sync handlers setup complete")

    async def _invalidate_pattern(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        # Simple pattern matching implementation
        import fnmatch

        if self.cache_manager:
            # Get all keys from local cache
            for key in list(self.cache_manager.local_cache.keys()):
                if fnmatch.fnmatch(key, pattern):
                    await self.cache_manager.delete(key)
