"""Observable schemas for ACE API v2."""

from pydantic import BaseModel


class SetInterestingRequest(BaseModel):
    observable_type: str
    observable_value: str
    is_interesting: bool
