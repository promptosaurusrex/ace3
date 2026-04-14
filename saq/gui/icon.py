from typing import Optional
from pydantic import BaseModel

class BlueprintFileLocation(BaseModel):
    model_config = {"extra": "forbid"}

    name: str
    path: str

class IconConfiguration(BaseModel):
    model_config = {"extra": "forbid"}

    blueprint_file_location: Optional[BlueprintFileLocation] = None
    url: Optional[str] = None