from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_response_threat_read import ListResponseThreatRead
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    malware_id: int | None | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_malware_id: int | None | Unset
    if isinstance(malware_id, Unset):
        json_malware_id = UNSET
    else:
        json_malware_id = malware_id
    params["malware_id"] = json_malware_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/threats/",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListResponseThreatRead | None:
    if response.status_code == 200:
        response_200 = ListResponseThreatRead.from_dict(response.json())

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
) -> Response[HTTPValidationError | ListResponseThreatRead]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    malware_id: int | None | Unset = UNSET,
) -> Response[HTTPValidationError | ListResponseThreatRead]:
    """List Threats

    Args:
        malware_id (int | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListResponseThreatRead]
    """

    kwargs = _get_kwargs(
        malware_id=malware_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    malware_id: int | None | Unset = UNSET,
) -> HTTPValidationError | ListResponseThreatRead | None:
    """List Threats

    Args:
        malware_id (int | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListResponseThreatRead
    """

    return sync_detailed(
        client=client,
        malware_id=malware_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    malware_id: int | None | Unset = UNSET,
) -> Response[HTTPValidationError | ListResponseThreatRead]:
    """List Threats

    Args:
        malware_id (int | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListResponseThreatRead]
    """

    kwargs = _get_kwargs(
        malware_id=malware_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    malware_id: int | None | Unset = UNSET,
) -> HTTPValidationError | ListResponseThreatRead | None:
    """List Threats

    Args:
        malware_id (int | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListResponseThreatRead
    """

    return (
        await asyncio_detailed(
            client=client,
            malware_id=malware_id,
        )
    ).parsed
