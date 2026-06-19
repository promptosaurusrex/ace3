"""Observable type router for ACE API v2."""

from fastapi import APIRouter, Response, Security

from aceapi_v2.cache import TTLCache
from aceapi_v2.dependencies import get_current_auth
from aceapi_v2.observable_types import service
from aceapi_v2.observable_types.schemas import ObservableTypeRead
from aceapi_v2.schemas import ListResponse

# All routes in this router require authentication
router = APIRouter(dependencies=[Security(get_current_auth)])

# 60s aligns with the registry's mtime-based reload window
# (observable_types.reload_check_interval_seconds in saq.default.yaml), so
# worst-case GUI staleness when an analyst adds a type to the YAML is
# ~2 min rather than the previous 5–6.
_cache = TTLCache(ttl=60)


@router.get("/", response_model=ListResponse[ObservableTypeRead])
async def list_observable_types(
    response: Response,
) -> ListResponse[ObservableTypeRead]:
    """Return the list of valid observable types from the configured registry.

    Requires authentication (API key or JWT token).
    """
    cached = _cache.get("observable_types")
    if cached is not None:
        _cache.set_cache_headers(response)
        return cached

    types = await service.get_observable_types()
    data = ListResponse(data=[ObservableTypeRead(name=t) for t in types])
    _cache.set("observable_types", data)
    _cache.set_cache_headers(response)
    return data
