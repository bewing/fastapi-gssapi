import base64


def test_login_request(client):
    response = client.get("/login")
    assert response.status_code == 401


def test_login_auth(client, k5ctx):
    token = base64.b64encode(k5ctx.step()).decode("utf-8")
    client.headers = {"Authorization": f"Negotiate: {token}"}
    response = client.get("/login")
    assert response.status_code == 200
    if gssresp := response.headers.get("WWW-Authenticate", ""):
        k5ctx.step(base64.b64decode(gssresp))
    assert k5ctx.complete
    assert "username" in response.json()
