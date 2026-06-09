"""Event schemas for ACE API v2."""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class EventRead(BaseModel):
    """An event serialized from ``Event.json``.

    ``Event.json`` produces a wide, semi-dynamic dict (nested malware/threats,
    list-valued tags/companies/alerts, an ``owner`` sub-object, etc.). Rather
    than re-enumerate every field — and risk drifting from the source of truth —
    this model declares the stable scalar fields and allows the remainder
    through unchanged.
    """

    model_config = ConfigDict(extra="allow")

    id: int
    uuid: str
    name: str


class StatusUpdate(BaseModel):
    """Body for updating an event's status."""

    status: str


class ExportFormat(str, Enum):
    """Supported event export formats. Add new formats here without a new route."""

    csv = "csv"
