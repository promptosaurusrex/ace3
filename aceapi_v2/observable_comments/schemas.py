"""Observable comment schemas for ACE API v2."""

from datetime import datetime

from pydantic import BaseModel


class ObservableCommentRead(BaseModel):
    id: int
    insert_date: datetime
    user_id: int
    user_display_name: str
    observable_id: int
    comment: str


class ObservableCommentCreate(BaseModel):
    observable_type: str
    observable_value: str
    comment: str


class ObservableCommentUpdate(BaseModel):
    comment: str
