import base64


def test_auth_request(middleware_client):
    response = middleware_client.get("/")

    assert response.status_code == 401


def test_auth(middleware_client, k5ctx):
    token = base64.b64encode(k5ctx.step()).decode("utf-8")
    middleware_client.headers = {"Authorization": f"Negotiate: {token}"}
    response = middleware_client.get("/")
    assert response.status_code == 200
    if gssresp := response.headers.get("WWW-Authenticate", ""):
        k5ctx.step(base64.b64decode(gssresp))
    assert k5ctx.complete
