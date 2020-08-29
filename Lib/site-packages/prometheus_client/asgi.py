from urllib.parse import parse_qs

from .exposition import _bake_output
from .registry import REGISTRY


def make_asgi_app(registry=REGISTRY):
    """Create a ASGI app which serves the metrics from a registry."""

    async def prometheus_app(scope, receive, send):
        assert scope.get("type") == "http"
        # Prepare parameters
        params = parse_qs(scope.get('query_string', b''))
        accept_header = "Accept: " + ",".join([
            value.decode("utf8") for (name, value) in scope.get('headers')
            if name.decode("utf8") == 'accept'
        ])
        # Bake output
        status, header, output = _bake_output(registry, accept_header, params)
        # Return output
        payload = await receive()
        if payload.get("type") == "http.request":
            await send(
                {
                    "type": "http.response.start",
                    "status": int(status.split(' ')[0]),
                    "headers": [
                        tuple(x.encode('utf8') for x in header)
                    ]
                }
            )
            await send({"type": "http.response.body", "body": output})

    return prometheus_app
