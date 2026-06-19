from enum import Enum


class ExportFormat(str, Enum):
    CSV = "csv"

    def __str__(self) -> str:
        return str(self.value)
