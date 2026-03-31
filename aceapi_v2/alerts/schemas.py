"""Alert schemas for ACE API v2."""

from pydantic import BaseModel


class BulkAddObservableRequest(BaseModel):
    alert_uuids: list[str]
    observable_type: str
    observable_value: str
    observable_time: str | None = None
    directives: list[str] = []


class BulkAddObservableResult(BaseModel):
    success_count: int
    failed_count: int
    failed_uuids: list[str]
    failed_details: dict[str, str] = {}
