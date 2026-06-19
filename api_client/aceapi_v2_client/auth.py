"""convenience helpers for authenticating against the ACE API v2

this module is hand-maintained and is NOT overwritten when the rest of the
package is regenerated from the openapi schema (see ../scripts/regenerate.sh).

the generated ``AuthenticatedClient`` only knows how to send ``Authorization:
Bearer <token>``. the ACE API v2 primary auth is an api key sent in the custom
``x-ace-auth`` header, so the helpers below build a plain ``Client`` with that
header pre-populated.
"""

from .client import AuthenticatedClient, Client

# header name the ACE API v2 expects for machine-to-machine api key auth
API_KEY_HEADER = "x-ace-auth"


def authenticated_client(base_url, api_key, *, verify_ssl=True, **kwargs):
    """build a ``Client`` that authenticates with an ACE api key

    args:
        base_url: full base url including the ``/api/v2`` prefix, e.g.
            ``https://localhost:8443/api/v2``
        api_key: the ACE api key (sent in the ``x-ace-auth`` header)
        verify_ssl: verify the server tls certificate. set to ``False`` when
            talking to a development instance using a self-signed certificate.
        **kwargs: any other keyword argument accepted by ``Client`` (``timeout``,
            ``headers``, ``httpx_args``, etc). extra ``headers`` are merged with
            the api key header.

    returns:
        a configured ``Client`` ready to pass to the functions under
        ``aceapi_v2_client.api``.
    """
    headers = {API_KEY_HEADER: api_key, **kwargs.pop("headers", {})}
    return Client(base_url=base_url, headers=headers, verify_ssl=verify_ssl, **kwargs)


def token_client(base_url, access_token, *, verify_ssl=True, **kwargs):
    """build an ``AuthenticatedClient`` that authenticates with a jwt access token

    use this after obtaining a token from the ``/auth/token`` endpoint. the token
    is sent as ``Authorization: Bearer <access_token>``.

    args:
        base_url: full base url including the ``/api/v2`` prefix
        access_token: a jwt access token issued by the api
        verify_ssl: verify the server tls certificate (``False`` for dev)
        **kwargs: any other keyword argument accepted by ``AuthenticatedClient``

    returns:
        a configured ``AuthenticatedClient``.
    """
    return AuthenticatedClient(
        base_url=base_url, token=access_token, verify_ssl=verify_ssl, **kwargs
    )
