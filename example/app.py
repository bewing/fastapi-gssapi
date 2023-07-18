import base64
from datetime import datetime, timedelta
from typing import Annotated, Union
import os

from fastapi import FastAPI, Response, Depends
from jose import jwt
from k5test.realm import MITRealm

from pydantic import BaseModel

from fastapi_gssapi import GSSAPIAuth

SECRET_KEY = "ff0d69562f59c8063554d63e190411ac7a78c1322c6cf5e864a6b7b0d9f756b7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

k5realm = MITRealm(
    krb5_conf={"libdefaults": {"rdns": "false"}},
)
k5realm.addprinc("HTTP/localhost@KRBTEST.COM")
k5realm.extract_keytab("HTTP/localhost@KRBTEST.COM", k5realm.keytab)
os.environ.update(k5realm.env)

app = FastAPI(debug=True)
gssapi_auth = GSSAPIAuth()


class Token(BaseModel):
    access_token: str
    token_type: str


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.get("/")
async def hello():
    return " ".join([f"{k}={v}" for k, v in k5realm.env.items()])


@app.get("/token", response_model=Token)
async def token(
    response: Response,
    auth: Annotated[tuple[str, Union[bytes, None]], Depends(gssapi_auth)],
):
    if auth[1]:
        response.headers["WWW-Authenticate"] = base64.b64encode(auth[1]).decode("utf-8")

    access_token = create_access_token(
        data={"iss": "HTTP/localhost@KRBTEST.COM", "sub": auth[0]}
    )

    return {"access_token": access_token, "token_type": "bearer"}
