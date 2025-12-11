"""Cache management for TMWS v2.4.3
Provides local memory caching with TTL and invalidation support.

v2.4.3: Redis removed - using local cache only (SQLite + ChromaDB architecture)
"""

import asyncio
import hashlib
import logging
import time
from functools import wraps
from typing import Any

logger = logging.getLogger(__name__)


class CacheManager:
    """Local memory cache manager with TTL and LRU eviction.

    v2.4.3: Simplified to local-only caching (Redis removed).
    """

    def __init__(
        self,
        local_ttl: int = 60,
        max_local_size: int = 1000,
    ):
        """Initialize cache manager.

        Args:
            local_ttl: TTL for local cache in seconds
            max_local_size: Maximum size of local cache

        """
        self.local_ttl = local_ttl
        self.max_local_size = max_local_size

        # Local cache storage
        self.local_cache: dict[str, tuple[Any, float]] = {}
        self.access_count: dict[str, int] = {}

        # Cache statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "local_hits": 0,
            "evictions": 0,
            "invalidations": 0,
        }

    async def initialize(self):
        """Initialize cache (no-op for local cache, kept for API compatibility)."""
        logger.info("Local cache initialized")

    async def get(self, key: str, namespace: str = "default") -> Any | None:
        """Get value from cache.

        Args:
            key: Cache key
            namespace: Cache namespace

        Returns:
            Cached value or None if not found

        """
        full_key = self._make_key(namespace, key)

        # Check local cache
        local_value = self._get_local(full_key)
        if local_value is not None:
            self.stats["hits"] += 1
            self.stats["local_hits"] += 1
            return local_value

        self.stats["misses"] += 1
        return None

    async def set(
        self,
        key: str,
        value: Any,
        namespace: str = "default",
        ttl: int = None,  # noqa: ARG002 - API compatibility, not used in local cache
    ):
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            namespace: Cache namespace
            ttl: Optional TTL override (not used in local cache, kept for API compatibility)

        """
        full_key = self._make_key(namespace, key)

        # Set in local cache
        self._set_local(full_key, value)

    async def delete(self, key: str, namespace: str = "default"):
        """Delete value from cache."""
        full_key = self._make_key(namespace, key)

        # Delete from local cache
        self.local_cache.pop(full_key, None)
        self.access_count.pop(full_key, None)

        self.stats["invalidations"] += 1

    async def clear(self, namespace: str = None):
        """Clear cache by namespace or all."""
        if namespace:
            # Clear specific namespace
            prefix = f"{namespace}:"
            keys_to_delete = [k for k in self.local_cache if k.startswith(prefix)]
            for key in keys_to_delete:
                self.local_cache.pop(key, None)
                self.access_count.pop(key, None)
        else:
            # Clear all
            self.local_cache.clear()
            self.access_count.clear()

        self.stats["invalidations"] += 1

    def _make_key(self, namespace: str, key: str) -> str:
        """Create full cache key."""
        return f"{namespace}:{key}"

    def _get_local(self, key: str) -> Any | None:
        """Get from local cache with TTL check."""
        if key in self.local_cache:
            value, expiry = self.local_cache[key]
            if time.time() < expiry:
                self.access_count[key] = self.access_count.get(key, 0) + 1
                return value
            else:
                # Expired
                self.local_cache.pop(key, None)
                self.access_count.pop(key, None)
        return None

    def _set_local(self, key: str, value: Any):
        """Set in local cache with LRU eviction."""
        # Check cache size
        if len(self.local_cache) >= self.max_local_size:
            self._evict_lru()

        expiry = time.time() + self.local_ttl
        self.local_cache[key] = (value, expiry)
        self.access_count[key] = 0

    def _evict_lru(self):
        """Evict least recently used item."""
        if not self.local_cache:
            return

        # Find LRU key
        lru_key = min(self.access_count.keys(), key=lambda k: self.access_count[k])

        self.local_cache.pop(lru_key, None)
        self.access_count.pop(lru_key, None)
        self.stats["evictions"] += 1

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_hits = self.stats["hits"]
        total_requests = total_hits + self.stats["misses"]

        return {
            **self.stats,
            "hit_rate": (total_hits / total_requests) if total_requests > 0 else 0,
            "local_cache_size": len(self.local_cache),
        }


class CacheDecorator:
    """Decorator for caching function results."""

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager

    def cached(self, namespace: str = "function", ttl: int = None, key_prefix: str = None):
        """Decorator for caching function results.

        Args:
            namespace: Cache namespace
            ttl: TTL override (not used, kept for API compatibility)
            key_prefix: Optional key prefix

        """

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                key_parts = [key_prefix or func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5(":".join(key_parts).encode(), usedforsecurity=False).hexdigest()

                # Check cache
                cached_value = await self.cache_manager.get(cache_key, namespace)
                if cached_value is not None:
                    return cached_value

                # Execute function
                result = await func(*args, **kwargs)

                # Cache result
                await self.cache_manager.set(cache_key, result, namespace, ttl)

                return result

            return wrapper

        return decorator


class InvalidationManager:
    """Manages cache invalidation."""

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.invalidation_queue = asyncio.Queue()

    async def invalidate_pattern(
        self,
        pattern: str,
        reason: str = None,  # noqa: ARG002 - Reserved for future logging/audit
    ):
        """Invalidate cache entries matching pattern."""
        # Local invalidation
        keys_to_delete = [
            k for k in self.cache_manager.local_cache if self._match_pattern(k, pattern)
        ]

        for key in keys_to_delete:
            await self.cache_manager.delete(key)

        logger.info(f"Invalidated {len(keys_to_delete)} cache entries for pattern: {pattern}")

    def _match_pattern(self, key: str, pattern: str) -> bool:
        """Simple pattern matching with * wildcard."""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)

    async def process_invalidations(self):
        """Process queued invalidations."""
        while True:
            try:
                invalidation = await self.invalidation_queue.get()
                await self.invalidate_pattern(invalidation["pattern"], invalidation.get("reason"))
            except (KeyboardInterrupt, SystemExit):
                logger.critical("🚨 User interrupt during invalidation processing")
                raise
            except Exception as e:
                logger.error(
                    f"Invalidation processing error: {e}",
                    exc_info=True,
                    extra={"queue_size": self.invalidation_queue.qsize()},
                )
            await asyncio.sleep(0.1)
