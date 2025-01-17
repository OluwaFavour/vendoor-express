from datetime import datetime
from typing import Union
from uuid import UUID, uuid4

from app.core.utils import hash_password, verify_password
from app.core.config import db_logger
from app.db.config import Base

from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


# Create models here
class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    first_name: Mapped[str] = mapped_column(nullable=False)
    last_name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, index=True, unique=True)
    phone: Mapped[str] = mapped_column(nullable=False, index=True, unique=True)
    hashed_password: Mapped[str] = mapped_column(nullable=False)
    is_deleted: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(), onupdate=func.now(), nullable=False, index=True
    )

    @classmethod
    async def get(cls, session: AsyncSession, **kwargs) -> Union["Customer", None]:
        """
        Retrieve a Customer record from the database based on provided filter arguments.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the query.
            **kwargs: Arbitrary keyword arguments representing the filter conditions.
        Returns:
            Union["Customer", None]: The Customer object if found, otherwise None.
        Raises:
            ValueError: If no filter arguments are provided or if invalid filter arguments are given.
        Example:
            customer = await Customer.get(session, id=1)
        """
        if not kwargs:
            db_logger.warning("No filter arguments provided to fetch a Customer.")
            raise ValueError("No filter arguments provided")

        valid_keys = {column.key for column in cls.__table__.columns}
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid filter keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid filter arguments: {', '.join(invalid_keys)}")

        conditions = [getattr(cls, key) == value for key, value in kwargs.items()]
        db_logger.info(f"Fetching Customer with conditions: {kwargs}")
        result = await session.execute(select(cls).where(and_(*conditions)))
        customer = result.scalar_one_or_none()

        if customer:
            db_logger.info(f"Customer found: {customer}")
        else:
            db_logger.info(f"No Customer found for conditions: {kwargs}")

        return customer

    @classmethod
    async def filter(
        cls,
        session: AsyncSession,
        op: str = "and",
        limit: int = 10,
        offset: int = 0,
        **kwargs,
    ) -> list["Customer"]:
        """
        Filters and retrieves a list of Customer records from the database based on the provided conditions.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the query.
            op (str, optional): The logical operator to use for combining conditions. Defaults to "and".
                Must be either "and" or "or".
            limit (int, optional): The maximum number of records to return. Defaults to 10.
            offset (int, optional): The number of records to skip before starting to return records. Defaults to 0.
            **kwargs: Arbitrary keyword arguments representing the filter conditions. The keys must match the column names
                of the Customer model.
        Returns:
            list[Customer]: A list of Customer objects that match the filter conditions.
        Raises:
            ValueError: If an invalid operator is provided, no filter arguments are provided, or invalid filter keys are provided.
        Logs:
            - Warnings for invalid operators, no filter arguments, and invalid filter keys.
            - Info for the conditions used to fetch Customers and the result of the query.
        """
        if op not in ["and", "or"]:
            db_logger.warning(f"Invalid operator: {op}")
            raise ValueError(f"Invalid operator: {op}")
        if not kwargs:
            db_logger.warning("No filter arguments provided to fetch Customers.")
            raise ValueError("No filter arguments provided")

        valid_keys = {column.key for column in cls.__table__.columns}
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid filter keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid filter arguments: {', '.join(invalid_keys)}")

        conditions = [getattr(cls, key) == value for key, value in kwargs.items()]
        db_logger.info(f"Fetching Customers with conditions: {kwargs}")
        query = select(cls).where(
            and_(*conditions) if op == "and" else or_(*conditions)
        )
        query = query.limit(limit).offset(offset)

        result = await session.execute(query)
        customers = result.scalars().all()

        if customers:
            db_logger.info(f"Customers found: {customers}")
        else:
            db_logger.info(f"No Customers found for conditions: {kwargs}")

        return customers

    @classmethod
    async def create(cls, session: AsyncSession, **kwargs) -> "Customer":
        """
        Asynchronously creates a new Customer record in the database.
        This method performs several tasks:
        - Logs the creation action (excluding sensitive information).
        - Validates required fields.
        - Validates field keys against model columns.
        - Hashes the password.
        - Checks for unique constraints (email, phone).
        - Creates and saves the new Customer record.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for database operations.
            **kwargs: Arbitrary keyword arguments containing the fields for the new Customer record.
        Returns:
            Customer: The newly created Customer object.
        Raises:
            ValueError: If required fields are missing, invalid keys are provided, or unique constraints are violated.
        """
        # Log action (excluding sensitive information)
        log_data = {key: value for key, value in kwargs.items() if key != "password"}
        db_logger.info(f"Creating new Customer with data: {log_data}")

        # Validate required fields
        required_fields = {"first_name", "last_name", "email", "phone"}
        missing_fields = required_fields - kwargs.keys()
        if missing_fields:
            db_logger.warning(f"Missing required fields: {', '.join(missing_fields)}")
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

        # Validate field keys against model columns
        valid_keys = {
            column.key
            for column in cls.__table__.columns
            if column.key != "hashed_password"
        }
        valid_keys.add("password")  # Allow password for hashing
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid arguments: {', '.join(invalid_keys)}")

        # Hash password early
        kwargs["hashed_password"] = hash_password(kwargs.pop("password"))

        # Check for unique constraints (email, phone) in a single query
        filters = []
        # Add filters for email and phone
        filters.append(cls.email == kwargs["email"])
        filters.append(cls.phone == kwargs["phone"])

        if filters:
            result = await session.execute(select(cls).where(or_(*filters)))
            existing_customer = result.scalar_one_or_none()
            if existing_customer:
                conflict_field = next(
                    key
                    for key in ["email", "phone"]
                    if key in kwargs and getattr(existing_customer, key) == kwargs[key]
                )
                db_logger.warning(
                    f"{conflict_field} already exists: {kwargs[conflict_field]}"
                )
                raise ValueError(f"{conflict_field} already exists")

        # Create and save the new Customer
        customer = cls(**kwargs)
        session.add(customer)
        await session.commit()
        await session.refresh(customer)
        db_logger.info(f"Successfully created Customer(id={customer.id})")
        return customer

    async def update(self, session: AsyncSession, **kwargs) -> "Customer":
        """
        Asynchronously updates the current Customer instance with the provided keyword arguments.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the update.
            **kwargs: Arbitrary keyword arguments representing the fields to update and their new values.
        Returns:
            Customer: The updated Customer instance.
        Raises:
            ValueError: If any of the provided keyword arguments are not valid column names for the Customer model.
        Logs:
            - A warning if any invalid update keys are provided.
            - An info message before updating the Customer instance.
            - An info message after successfully updating the Customer instance.
        """
        valid_keys = {column.key for column in self.__table__.columns}
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid update keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid update arguments: {', '.join(invalid_keys)}")

        db_logger.info(f"Updating Customer(id={self.id}) with {kwargs}")
        for key, value in kwargs.items():
            setattr(self, key, value)

        await session.commit()
        await session.refresh(self)
        db_logger.info(f"Successfully updated Customer(id={self.id})")
        return self

    async def delete(self, session: AsyncSession, mode: str = "soft") -> None:
        """
        Deletes the current instance of the Customer model.
        Args:
            session (AsyncSession): The SQLAlchemy async session to use for the operation.
            mode (str, optional): The mode of deletion. Can be either "soft" or "hard". Defaults to "soft".
        Raises:
            ValueError: If the provided mode is not "soft" or "hard".
        Returns:
            None
        """
        if mode not in ["soft", "hard"]:
            db_logger.warning(f"Invalid delete mode: {mode}")
            raise ValueError(f"Invalid delete mode: {mode}")

        if mode == "soft":
            db_logger.info(f"Soft deleting Customer(id={self.id})")
            self.is_deleted = True
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully soft deleted Customer(id={self.id})")
            return None
        else:
            db_logger.info(f"Deleting Customer(id={self.id})")
            session.delete(self)
            await session.commit()
            db_logger.info(f"Successfully deleted Customer(id={self.id})")
            return None

    async def deactivate(self, session: AsyncSession) -> "Customer":
        """
        Deactivates the customer by setting the `is_active` attribute to False and commits the change to the database.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for committing the change.

        Returns:
            Customer: The updated customer instance with `is_active` set to False.
        """
        db_logger.info(f"Deactivating Customer(id={self.id})")
        self.is_active = False
        await session.commit()
        await session.refresh(self)
        db_logger.info(f"Successfully deactivated Customer(id={self.id})")
        return self

    async def authenticate(
        self, password: str, return_object: bool = False
    ) -> Union["Customer", bool]:
        """
        Authenticate the user by verifying the provided password.

        Args:
            password (str): The password to verify.
            return_object (bool, optional): If True, return the user object on successful authentication.
                                            If False, return a boolean indicating success. Defaults to False.

        Returns:
            Union["Customer", bool]: The user object if return_object is True and authentication is successful,
                                    otherwise a boolean indicating the success of the authentication.
                                    Returns None if return_object is True and authentication fails.
        """
        if verify_password(password, self.hashed_password):
            return self if return_object else True
        return None if return_object else False

    async def change_password(
        self, session: AsyncSession, new_password: str
    ) -> "Customer":
        """
        Change the password for the customer.

        Args:
            session (AsyncSession): The database session to use for committing the changes.
            new_password (str): The new password to set for the customer.

        Returns:
            Customer: The updated customer object with the new hashed password.

        Logs:
            Logs the process of changing the password, including success messages.
        """
        db_logger.info(f"Changing password for Customer(id={self.id})")
        self.hashed_password = hash_password(new_password)
        await session.commit()
        await session.refresh(self)
        db_logger.info(f"Successfully changed password for Customer(id={self.id})")
        return self
