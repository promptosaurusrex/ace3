"""Node schemas for ACE API v2."""

from datetime import datetime

from pydantic import BaseModel


class CollectorStatusRead(BaseModel):
    name: str
    status: str
    backlog_count: int
    last_update: datetime


class NodeRead(BaseModel):
    id: int
    name: str
    location: str
    company_id: int
    status: str
    last_update: datetime
    is_primary: bool
    any_mode: bool
    # outstanding work counts -- used to watch drain progress
    # note that a node can be drained with delayed_analysis_count > 0 when no
    # compatible node exists to transfer the delayed work to (that work resumes
    # when the node starts back up)
    workload_count: int
    delayed_analysis_count: int
    collectors: list[CollectorStatusRead] = []
