import os
import pytest
import random

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import gssapi
from gssapi import raw as gb
import k5test

from fastapi_gssapi.middleware import GSSAPIMiddleWare


@pytest.fixture(scope="session", autouse=True)
def k5realm():
    k5realm = k5test.K5Realm(
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
    app.add_middleware(GSSAPIMiddleWare)

    @app.get("/")
    def homepage(request: Request):
        assert request.scope["username"]
        return {"hello": "world"}

    yield app


@pytest.fixture
def client(app):
    yield TestClient(app)


@pytest.fixture(
    params=[
        [gssapi.RequirementFlag.out_of_sequence_detection],
        [
            gssapi.RequirementFlag.out_of_sequence_detection,
            gssapi.RequirementFlag.mutual_authentication,
        ],
    ]
)
def k5ctx(k5realm, request):
    spn = gssapi.Name(
        "host/{}".format(k5realm.hostname), gb.NameType.kerberos_principal
    )
    ctx = gssapi.SecurityContext(name=spn, usage="initiate", flags=request.param)
    yield ctx
    del ctx
