from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    alert_uuid: str,
    *,
    download: bool | Unset = False,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["download"] = download

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/alerts/{alert_uuid}/logs".format(
            alert_uuid=quote(str(alert_uuid), safe=""),
        ),
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
    alert_uuid: str,
    *,
    client: AuthenticatedClient,
    download: bool | Unset = False,
) -> Response[Any | HTTPValidationError]:
    """View Alert Logs

     Return the alert's raw saq.log file.

    Default: text/plain with inline disposition (renders in browser).
    With ?download=true, served as an attachment download.

    Args:
        alert_uuid (str):
        download (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        alert_uuid=alert_uuid,
        download=download,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    alert_uuid: str,
    *,
    client: AuthenticatedClient,
    download: bool | Unset = False,
) -> Any | HTTPValidationError | None:
    """View Alert Logs

     Return the alert's raw saq.log file.

    Default: text/plain with inline disposition (renders in browser).
    With ?download=true, served as an attachment download.

    Args:
        alert_uuid (str):
        download (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        alert_uuid=alert_uuid,
        client=client,
        download=download,
    ).parsed


async def asyncio_detailed(
    alert_uuid: str,
    *,
    client: AuthenticatedClient,
    download: bool | Unset = False,
) -> Response[Any | HTTPValidationError]:
    """View Alert Logs

     Return the alert's raw saq.log file.

    Default: text/plain with inline disposition (renders in browser).
    With ?download=true, served as an attachment download.

    Args:
        alert_uuid (str):
        download (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        alert_uuid=alert_uuid,
        download=download,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    alert_uuid: str,
    *,
    client: AuthenticatedClient,
    download: bool | Unset = False,
) -> Any | HTTPValidationError | None:
    """View Alert Logs

     Return the alert's raw saq.log file.

    Default: text/plain with inline disposition (renders in browser).
    With ?download=true, served as an attachment download.

    Args:
        alert_uuid (str):
        download (bool | Unset):  Default: False.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            alert_uuid=alert_uuid,
            client=client,
            download=download,
        )
    ).parsed
