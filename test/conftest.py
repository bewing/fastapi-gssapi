import base64
import os
import pytest
from typing import Annotated, Union
import random

from fastapi import FastAPI, Request, Depends, Response
from fastapi.testclient import TestClient
from gssapi.names import Name
from gssapi.sec_contexts import SecurityContext
from gssapi import raw as gb
from k5test.realm import MITRealm

from fastapi_gssapi.middleware import GSSAPIMiddleware
from fastapi_gssapi.dependency import GSSAPIAuth


@pytest.fixture(scope="session", autouse=True)
def k5realm():
    k5realm = MITRealm(
        krb5_conf={"libdefaults": {"rdns": "false"}},
        portbase=random.randint(1000, 6000) * 10,  # For tox parallel
    )
    os.environ.update(k5realm.env)
    yield k5realm
    for k in k5realm.env.keys():
        del os.environ[k]
    k5realm.stop()
    del k5realm


@pytest.fixture
def app():
    app = FastAPI()

    @app.get("/")
    def homepage(request: Request):
        assert request.scope["username"]
        return {"hello": "world"}

    @app.get("/login")
    def login(
        response: Response,
        auth: Annotated[tuple[str, Union[bytes, None]], Depends(GSSAPIAuth())],
    ):
        if auth[1]:
            response.headers["WWW-Authenticate"] = base64.b64encode(auth[1]).decode(
                "utf-8"
            )

        return {"username": auth[0]}

    yield app


@pytest.fixture
def client(app):
    yield TestClient(app)


@pytest.fixture
def middleware_client(app):
    app.add_middleware(GSSAPIMiddleware)
    yield TestClient(app)


@pytest.fixture(
    params=[
        [gb.RequirementFlag.out_of_sequence_detection],
        [
            gb.RequirementFlag.out_of_sequence_detection,
            gb.RequirementFlag.mutual_authentication,
        ],
    ]
)
def k5ctx(k5realm, request):
    spn = Name("host/{}".format(k5realm.hostname), gb.NameType.kerberos_principal)
    ctx = SecurityContext(name=spn, usage="initiate", flags=request.param)
    yield ctx
    del ctx
