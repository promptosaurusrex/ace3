from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.export_format import ExportFormat
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    type_: ExportFormat | Unset = UNSET,
    checked_events: list[int] | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_type_: str | Unset = UNSET
    if not isinstance(type_, Unset):
        json_type_ = type_.value

    params["type"] = json_type_

    json_checked_events: list[int] | Unset = UNSET
    if not isinstance(checked_events, Unset):
        json_checked_events = checked_events

    params["checked_events[]"] = json_checked_events

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/events/export",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = response.json()
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
) -> Response[Any | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    type_: ExportFormat | Unset = UNSET,
    checked_events: list[int] | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Export Events

    Args:
        type_ (ExportFormat | Unset): Supported event export formats. Add new formats here without
            a new route.
        checked_events (list[int] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        type_=type_,
        checked_events=checked_events,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    type_: ExportFormat | Unset = UNSET,
    checked_events: list[int] | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Export Events

    Args:
        type_ (ExportFormat | Unset): Supported event export formats. Add new formats here without
            a new route.
        checked_events (list[int] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        type_=type_,
        checked_events=checked_events,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    type_: ExportFormat | Unset = UNSET,
    checked_events: list[int] | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Export Events

    Args:
        type_ (ExportFormat | Unset): Supported event export formats. Add new formats here without
            a new route.
        checked_events (list[int] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        type_=type_,
        checked_events=checked_events,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    type_: ExportFormat | Unset = UNSET,
    checked_events: list[int] | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Export Events

    Args:
        type_ (ExportFormat | Unset): Supported event export formats. Add new formats here without
            a new route.
        checked_events (list[int] | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            type_=type_,
            checked_events=checked_events,
        )
    ).parsed
