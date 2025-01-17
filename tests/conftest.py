import asyncio
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.config import get_async_session
from app.db.models import Base


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
def event_loop():
    """
    Create an event loop for the session.
    pytest-asyncio requires this fixture to run async tests.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture(name="async_session")
async def session_fixture():
    # Create an async engine with SQLite in-memory
    async_engine: AsyncEngine = create_async_engine(
        "sqlite+aiosqlite://",  # Use aiosqlite for async SQLite support
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Create database schema
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create a sessionmaker for the AsyncSession
    async_session_maker = async_sessionmaker(
        bind=async_engine, autoflush=False, expire_on_commit=False
    )

    # Provide a session instance for the tests
    async with async_session_maker() as async_session:
        yield async_session

    # Dispose of the engine after all tests are complete
    await async_engine.dispose()


@pytest.fixture(name="client")
async def client_fixture(async_session: AsyncSession):
    async def override_get_async_session():
        yield async_session

    app.dependency_overrides[get_async_session] = override_get_async_session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client
    app.dependency_overrides.clear()
