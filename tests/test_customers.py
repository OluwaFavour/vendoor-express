from httpx import AsyncClient
import pytest


# Test the register_user endpoint
@pytest.mark.anyio
async def test_register_user_success(client: AsyncClient):
    response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert response.status_code == 201


@pytest.mark.anyio
async def test_register_user_invalid_password(client: AsyncClient):
    response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "password",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_register_user_no_duplicate_email(client: AsyncClient):
    response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert response.status_code == 201

    duplicate_response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert duplicate_response.status_code == 422


@pytest.mark.anyio
async def test_register_user_no_duplicate_phone(client: AsyncClient):
    response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert response.status_code == 201

    duplicate_response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo1.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )

    assert duplicate_response.status_code == 422


# Test the login_user endpoint
@pytest.mark.anyio
async def test_login_user_with_email(client: AsyncClient):
    # Register a user
    register_response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert register_response.status_code == 201

    # Login the user
    response = await client.post(
        "/users/auth/login",
        data={
            "email": "foo@foo.com",
            "password": "pAssword123$",
        },
    )
    user = response.json()
    assert client.cookies["session"] is not None
    assert response.status_code == 200


@pytest.mark.anyio
async def test_login_user_invalid_password(client: AsyncClient):
    # Register a user
    register_response = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert register_response.status_code == 201

    # Login the user
    response = await client.post(
        "/users/auth/login",
        data={
            "email": "foo@foo.com",
            "password": "pAssword13$",
        },
    )

    assert response.status_code == 401


@pytest.mark.anyio
async def test_logout_user(client: AsyncClient):
    # Register a user
    user = await client.post(
        "/users/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "user",
        },
    )
    assert user.status_code == 201

    # Login the user
    login_response = await client.post(
        "/users/auth/login",
        data={
            "email": "foo@foo.com",
            "password": "pAssword123$",
        },
    )
    assert login_response.status_code == 200

    assert "session" in client.cookies

    # Logout the user
    response = await client.post("/users/auth/logout")
    assert response.status_code == 200
    assert "session" not in client.cookies
