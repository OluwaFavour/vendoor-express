from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.db.init_db import init_db, dispose_db
from app.routers import users


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Asynchronous context manager for managing the lifespan of the FastAPI application.

    Parameters:
    - app (FastAPI): The FastAPI application.

    Yields:
    None

    Usage:
    ```
    async with lifespan(app):
        # Code to be executed within the lifespan of the application
    ```
    """
    await init_db()
    yield
    await dispose_db()


app = FastAPI(
    debug=get_settings().debug,
    title=get_settings().app_name,
    version=get_settings().app_version,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    root_path="/api/v1",
)

# ADD MIDDLEWARES
## ADD SESSION MIDDLEWARE
app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().session_secret_key,
    same_site=get_settings().session_same_site,
    https_only=get_settings().session_secure,
)

## ADD CORS MIDDLEWARE
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_origins,
    allow_credentials=get_settings().allow_credentials,
    allow_methods=get_settings().allowed_methods,
    allow_headers=["*"],
)


# ADD ROUTERS
app.include_router(users.router)


@app.get("/", include_in_schema=False)
@app.head("/", include_in_schema=False)
async def read_root(request: Request):
    base_url = request.base_url._url.rstrip("/")
    return {
        "message": "Welcome to the Vendoor Express API",
        "version": get_settings().app_version,
        "docs": {
            "redoc": f"{base_url}/api/redoc",
            "swagger": f"{base_url}/api/docs",
            "openapi": f"{base_url}/api/openapi.json",
        },
    }
