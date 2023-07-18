fastapi-gssapi
==============

ASGI Middleware and FastAPI Dependency for adding Kerberos/GSS authentication
to FastAPI

Installation
============
TBD on packaging

Usage
=====

Middleware
----------
See the [FastAPI Advanced Middleware](https://fastapi.tiangolo.com/advanced/middleware/) documentation

basic:

```python
from fastapi import FastAPI
from fastapi_gssapi import GSSAPIMiddleware
app = FastAPI()
app.add_middleware(GSSAPIMiddleware)
```

Dependency
----------
See the [example app](example/app.py)
