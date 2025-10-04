"""
Cache management for TMWS v2.2.0
Provides multi-layer caching with TTL and invalidation support
"""

import asyncio
import hashlib
import json
import logging
import time
from functools import wraps
from typing import Any

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Multi-layer cache manager with local memory and Redis support
    """

    def __init__(
        self,
        redis_url: str = None,
        local_ttl: int = 60,
        redis_ttl: int = 300,
        max_local_size: int = 1000,
    ):
        """
        Initialize cache manager

        Args:
            redis_url: Redis connection URL (optional)
            local_ttl: TTL for local cache in seconds
            redis_ttl: TTL for Redis cache in seconds
            max_local_size: Maximum size of local cache
        """
        self.redis_client = None
        self.redis_url = redis_url
        self.local_ttl = local_ttl
        self.redis_ttl = redis_ttl
        self.max_local_size = max_local_size

        # Local cache storage
        self.local_cache: dict[str, tuple[Any, float]] = {}
        self.access_count: dict[str, int] = {}

        # Cache statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "local_hits": 0,
            "redis_hits": 0,
            "evictions": 0,
            "invalidations": 0,
        }

    async def initialize(self):
        """Initialize Redis connection if URL provided"""
        if self.redis_url:
            try:
                self.redis_client = await redis.from_url(self.redis_url)
                await self.redis_client.ping()
                logger.info("Redis cache initialized")
            except Exception as e:
                logger.warning(f"Redis unavailable, using local cache only: {e}")
                self.redis_client = None

    async def get(self, key: str, namespace: str = "default") -> Any | None:
        """
        Get value from cache

        Args:
            key: Cache key
            namespace: Cache namespace

        Returns:
            Cached value or None if not found
        """
        full_key = self._make_key(namespace, key)

        # Check local cache first
        local_value = self._get_local(full_key)
        if local_value is not None:
            self.stats["hits"] += 1
            self.stats["local_hits"] += 1
            return local_value

        # Check Redis if available
        if self.redis_client:
            redis_value = await self._get_redis(full_key)
            if redis_value is not None:
                self.stats["hits"] += 1
                self.stats["redis_hits"] += 1
                # Store in local cache
                self._set_local(full_key, redis_value)
                return redis_value

        self.stats["misses"] += 1
        return None

    async def set(self, key: str, value: Any, namespace: str = "default", ttl: int = None):
        """
        Set value in cache

        Args:
            key: Cache key
            value: Value to cache
            namespace: Cache namespace
            ttl: Optional TTL override
        """
        full_key = self._make_key(namespace, key)

        # Set in local cache
        self._set_local(full_key, value)

        # Set in Redis if available
        if self.redis_client:
            await self._set_redis(full_key, value, ttl or self.redis_ttl)

    async def delete(self, key: str, namespace: str = "default"):
        """Delete value from cache"""
        full_key = self._make_key(namespace, key)

        # Delete from local cache
        self.local_cache.pop(full_key, None)
        self.access_count.pop(full_key, None)

        # Delete from Redis
        if self.redis_client:
            await self.redis_client.delete(full_key)

        self.stats["invalidations"] += 1

    async def clear(self, namespace: str = None):
        """Clear cache by namespace or all"""
        if namespace:
            # Clear specific namespace
            prefix = f"{namespace}:"
            keys_to_delete = [k for k in self.local_cache if k.startswith(prefix)]
            for key in keys_to_delete:
                self.local_cache.pop(key, None)
                self.access_count.pop(key, None)

            # Clear from Redis
            if self.redis_client:
                pattern = f"{namespace}:*"
                cursor = 0
                while True:
                    cursor, keys = await self.redis_client.scan(cursor, match=pattern, count=100)
                    if keys:
                        await self.redis_client.delete(*keys)
                    if cursor == 0:
                        break
        else:
            # Clear all
            self.local_cache.clear()
            self.access_count.clear()

            if self.redis_client:
                await self.redis_client.flushdb()

        self.stats["invalidations"] += 1

    def _make_key(self, namespace: str, key: str) -> str:
        """Create full cache key"""
        return f"{namespace}:{key}"

    def _get_local(self, key: str) -> Any | None:
        """Get from local cache with TTL check"""
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
        """Set in local cache with LRU eviction"""
        # Check cache size
        if len(self.local_cache) >= self.max_local_size:
            self._evict_lru()

        expiry = time.time() + self.local_ttl
        self.local_cache[key] = (value, expiry)
        self.access_count[key] = 0

    def _evict_lru(self):
        """Evict least recently used item"""
        if not self.local_cache:
            return

        # Find LRU key
        lru_key = min(self.access_count.keys(), key=lambda k: self.access_count[k])

        self.local_cache.pop(lru_key, None)
        self.access_count.pop(lru_key, None)
        self.stats["evictions"] += 1

    async def _get_redis(self, key: str) -> Any | None:
        """Get from Redis cache"""
        try:
            data = await self.redis_client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Redis get error: {e}")
        return None

    async def _set_redis(self, key: str, value: Any, ttl: int):
        """Set in Redis cache"""
        try:
            data = json.dumps(value)
            await self.redis_client.setex(key, ttl, data)
        except Exception as e:
            logger.error(f"Redis set error: {e}")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics"""
        total_hits = self.stats["hits"]
        total_requests = total_hits + self.stats["misses"]

        return {
            **self.stats,
            "hit_rate": (total_hits / total_requests) if total_requests > 0 else 0,
            "local_cache_size": len(self.local_cache),
            "redis_available": self.redis_client is not None,
        }


class CacheDecorator:
    """
    Decorator for caching function results
    """

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager

    def cached(self, namespace: str = "function", ttl: int = None, key_prefix: str = None):
        """
        Decorator for caching function results

        Args:
            namespace: Cache namespace
            ttl: TTL override
            key_prefix: Optional key prefix
        """

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                key_parts = [key_prefix or func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()

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
    """
    Manages cache invalidation across instances
    """

    def __init__(self, cache_manager: CacheManager, db_pool):
        self.cache_manager = cache_manager
        self.db_pool = db_pool
        self.invalidation_queue = asyncio.Queue()

    async def invalidate_pattern(self, pattern: str, reason: str = None):
        """Invalidate cache entries matching pattern"""
        # Local invalidation
        keys_to_delete = [
            k for k in self.cache_manager.local_cache if self._match_pattern(k, pattern)
        ]

        for key in keys_to_delete:
            await self.cache_manager.delete(key)

        # Log invalidation
        if self.db_pool:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO cache_invalidations (
                        cache_key, invalidated_by, reason
                    )
                    VALUES ($1, $2, $3)
                """,
                    pattern,
                    "system",
                    reason,
                )

        logger.info(f"Invalidated {len(keys_to_delete)} cache entries for pattern: {pattern}")

    def _match_pattern(self, key: str, pattern: str) -> bool:
        """Simple pattern matching with * wildcard"""
        import fnmatch

        return fnmatch.fnmatch(key, pattern)

    async def process_invalidations(self):
        """Process queued invalidations"""
        while True:
            try:
                invalidation = await self.invalidation_queue.get()
                await self.invalidate_pattern(invalidation["pattern"], invalidation.get("reason"))
            except Exception as e:
                logger.error(f"Invalidation processing error: {e}")
            await asyncio.sleep(0.1)
