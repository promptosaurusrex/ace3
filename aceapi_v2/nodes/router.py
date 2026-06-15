"""Node management router for ACE API v2.

Supports draining a node. The drain happens in two phases: the node first
enters draining_collectors, where its collectors stop collecting new work and
flush their delivery backlog while the node still accepts new work (so
collectors whose only eligible target is this node can flush). Once every
collector has flushed, the node advances to draining: it receives no new work
and completes the work it already has. When nothing is outstanding the engine
marks the node as drained and it is safe to shut down.

Notes for operators:
- treat drained as safe once it has persisted for one node status update cycle
  (a submission can race the drained check; the node self-heals by reverting
  to draining)
- restarting a node cancels a drain (the node returns to running)
- a node can report drained with delayed_analysis_count > 0 when no compatible
  node exists to transfer the delayed work to; that work resumes when the node
  starts back up
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import require_permission
from aceapi_v2.nodes import service
from aceapi_v2.nodes.schemas import NodeRead
from aceapi_v2.schemas import ListResponse

router = APIRouter()


@router.get("/", response_model=ListResponse[NodeRead])
async def list_nodes(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("node", "read"))],
) -> ListResponse[NodeRead]:
    return ListResponse(data=await service.get_nodes(session))


@router.get("/{node_id}", response_model=NodeRead)
async def get_node(
    node_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("node", "read"))],
) -> NodeRead:
    node = await service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


async def _transition_or_error(session: AsyncSession, node_id: int, transition, action: str) -> NodeRead:
    if not await transition(session, node_id):
        # the transition did not occur -- figure out why
        status = await service.get_node_status(session, node_id)
        if status is None:
            raise HTTPException(status_code=404, detail="Node not found")

        raise HTTPException(status_code=409, detail=f"cannot {action} node with status {status}")

    node = await service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")

    return node


@router.post("/{node_id}/drain", response_model=NodeRead)
async def drain_node(
    node_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("node", "manage"))],
) -> NodeRead:
    """Starts draining the node. Only a running node can start draining.
    Poll GET /nodes/{node_id} until the status changes to drained."""
    return await _transition_or_error(session, node_id, service.drain_node, "drain")


@router.post("/{node_id}/resume", response_model=NodeRead)
async def resume_node(
    node_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("node", "manage"))],
) -> NodeRead:
    """Returns a node in any drain phase back to running."""
    return await _transition_or_error(session, node_id, service.resume_node, "resume")
