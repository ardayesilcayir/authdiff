from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import init_db
from .routers import admin, invoices, orders, products, users


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        init_db()
        yield

    app = FastAPI(title="vuln-lab", version="1.0.0", lifespan=lifespan)
    # users first: /users/me must be declared before /users/{userId}
    for r in (users, orders, invoices, admin, products):
        app.include_router(r.router)
    return app


app = create_app()
