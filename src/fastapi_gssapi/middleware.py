import base64
from typing import Union

from gssapi.names import Name
from gssapi.creds import Credentials
from gssapi.sec_contexts import SecurityContext
from starlette.types import ASGIApp, Scope, Receive, Send, Message
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import Response


class GSSAPIMiddleware:
    def __init__(self, app: ASGIApp, *, spn: Union[str, Name, None] = None) -> None:
        if isinstance(spn, str):
            spn = Name(spn)

        self.app = app
        self.creds = Credentials(usage="accept", name=spn)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        auth = headers.get("Authorization", "")
        if auth:
            ctx = SecurityContext(creds=self.creds)
            token = base64.b64decode(auth.split(" ")[1])
            gssresp = ctx.step(token)
            if ctx.complete:
                username = str(ctx.initiator_name)
                if username:
                    scope["username"] = username

                async def send_gss(message: Message) -> None:
                    if message["type"] == "http.response.start" and gssresp:
                        message.setdefault("headers", [])
                        headers = MutableHeaders(scope=message)
                        headers["WWW-Authenticate"] = base64.b64encode(gssresp).decode(
                            "utf-8"
                        )
                    await send(message)

                return await self.app(scope, receive, send_gss)

        resp = Response(
            status_code=401, headers=Headers({"WWW-Authenticate": "Negotiate"})
        )
        return await resp(scope, receive, send)
