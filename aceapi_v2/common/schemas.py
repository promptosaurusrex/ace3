"""Common schemas for ACE API v2."""

from pydantic import BaseModel, ConfigDict


class PingResponse(BaseModel):
    result: str


class SupportedApiVersionResponse(BaseModel):
    result: int


class CompanyRead(BaseModel):
    id: int
    name: str

    model_config = ConfigDict(from_attributes=True)


class NamedDescriptionRead(BaseModel):
    name: str
    description: str
