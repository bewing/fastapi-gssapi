fastapi-gssapi
==============

ASGI Middleware and FastAPI Dependency for adding Kerberos/GSS authentication
to FastAPI

Installation
============
Use your favorite package manager to install from PyPI

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
See the [example app](https://github.com/bewing/fastapi-gssapi/blob/main/example/app.py)
