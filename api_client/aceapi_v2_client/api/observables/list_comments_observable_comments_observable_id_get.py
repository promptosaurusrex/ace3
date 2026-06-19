from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_response_observable_comment_read import (
    ListResponseObservableCommentRead,
)
from ...types import Response


def _get_kwargs(
    observable_id: int,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/observable-comments/{observable_id}".format(
            observable_id=quote(str(observable_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListResponseObservableCommentRead | None:
    if response.status_code == 200:
        response_200 = ListResponseObservableCommentRead.from_dict(response.json())

        return response_200

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[HTTPValidationError | ListResponseObservableCommentRead]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    observable_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | ListResponseObservableCommentRead]:
    """List Comments

    Args:
        observable_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListResponseObservableCommentRead]
    """

    kwargs = _get_kwargs(
        observable_id=observable_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    observable_id: int,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | ListResponseObservableCommentRead | None:
    """List Comments

    Args:
        observable_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListResponseObservableCommentRead
    """

    return sync_detailed(
        observable_id=observable_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    observable_id: int,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | ListResponseObservableCommentRead]:
    """List Comments

    Args:
        observable_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListResponseObservableCommentRead]
    """

    kwargs = _get_kwargs(
        observable_id=observable_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    observable_id: int,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | ListResponseObservableCommentRead | None:
    """List Comments

    Args:
        observable_id (int):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListResponseObservableCommentRead
    """

    return (
        await asyncio_detailed(
            observable_id=observable_id,
            client=client,
        )
    ).parsed
