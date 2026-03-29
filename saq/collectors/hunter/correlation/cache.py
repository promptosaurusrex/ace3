import hashlib
import json
import logging
from typing import Optional

from saq.constants import REDIS_DB_HUNT_CACHE
from saq.redis_client import get_redis_connection


def _make_cache_key(command_args: dict) -> str:
    """Generate a cache key from command arguments."""
    serialized = json.dumps(command_args, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode()).hexdigest()
    return f"hunt_cache:{digest}"


def get_cached_result(command_args: dict) -> Optional[str]:
    """Get a cached command result."""
    try:
        r = get_redis_connection(REDIS_DB_HUNT_CACHE)
        key = _make_cache_key(command_args)
        result = r.get(key)
        if result:
            logging.info(f"cache hit for {key}")

        return result

    except Exception:
        logging.warning("failed to read from hunt cache", exc_info=True)
        return None


def set_cached_result(command_args: dict, value: str, ttl_seconds: int):
    """Cache a command result with a TTL."""
    try:
        r = get_redis_connection(REDIS_DB_HUNT_CACHE)
        key = _make_cache_key(command_args)
        r.setex(key, ttl_seconds, value)
        logging.info(f"cached result with key {key} for {ttl_seconds} seconds")
    except Exception:
        logging.warning("failed to write to hunt cache", exc_info=True)
