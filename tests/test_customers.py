from httpx import AsyncClient
import pytest


# Test the register_customer endpoint
@pytest.mark.anyio
async def test_register_customer_success(client: AsyncClient):
    response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert response.status_code == 201


@pytest.mark.anyio
async def test_register_customer_invalid_password(client: AsyncClient):
    response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "password",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_register_customer_no_duplicate_email(client: AsyncClient):
    response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert response.status_code == 201

    duplicate_response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert duplicate_response.status_code == 422


@pytest.mark.anyio
async def test_register_customer_no_duplicate_phone(client: AsyncClient):
    response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert response.status_code == 201

    duplicate_response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo1.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )

    assert duplicate_response.status_code == 422


# Test the login_customer endpoint
@pytest.mark.anyio
async def test_login_customer_with_email(client: AsyncClient):
    # Register a customer
    register_response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert register_response.status_code == 201

    # Login the customer
    response = await client.post(
        "/customers/auth/login",
        data={
            "email": "foo@foo.com",
            "password": "pAssword123$",
        },
    )
    customer = response.json()
    assert client.cookies["session"] is not None
    assert response.status_code == 200


@pytest.mark.anyio
async def test_login_customer_invalid_password(client: AsyncClient):
    # Register a customer
    register_response = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert register_response.status_code == 201

    # Login the customer
    response = await client.post(
        "/customers/auth/login",
        data={
            "email": "foo@foo.com",
            "password": "pAssword13$",
        },
    )

    assert response.status_code == 401


@pytest.mark.anyio
async def test_logout_customer(client: AsyncClient):
    # Register a customer
    customer = await client.post(
        "/customers/auth/register",
        data={
            "email": "foo@foo.com",
            "first_name": "Foo",
            "last_name": "Bar",
            "password": "pAssword123$",
            "phone": "+2348123456789",
            "role": "customer",
        },
    )
    assert customer.status_code == 201

    # Login the customer
    login_response = await client.post(
        "/customers/auth/login",
        data={
            "email": "foo@foo.com",
            "password": "pAssword123$",
        },
    )
    assert login_response.status_code == 200

    assert "session" in client.cookies

    # Logout the customer
    response = await client.post("/customers/auth/logout")
    assert response.status_code == 200
    assert "session" not in client.cookies
