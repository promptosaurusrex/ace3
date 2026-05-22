from typing import Optional
from pydantic import BaseModel

# key used to store the icon configuration in the root analysis extensions
KEY_ICON_CONFIGURATION = "icon_configuration"

class BlueprintFileLocation(BaseModel):
    model_config = {"extra": "forbid"}

    name: str
    path: str

class IconConfiguration(BaseModel):
    model_config = {"extra": "forbid"}

    blueprint_file_location: Optional[BlueprintFileLocation] = None
    url: Optional[str] = None