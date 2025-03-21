from datetime import datetime, timedelta
from decimal import Decimal
from typing import Union
from uuid import UUID, uuid4

from app.core.config import db_logger, get_settings
from app.core.enums import DeliveryStatus, Role
from app.core.utils.security import hash_password, verify_password, generate_otp
from app.db.config import Base

from sqlalchemy import func, and_, or_, ForeignKey, Text, Numeric
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


# Create models here
class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    first_name: Mapped[str] = mapped_column(nullable=False)
    last_name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, index=True, unique=True)
    phone: Mapped[str] = mapped_column(nullable=False, index=True, unique=True)
    hashed_password: Mapped[str] = mapped_column(nullable=False)
    role: Mapped[Role] = mapped_column(nullable=False)
    is_deleted: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=False)
    is_verified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(), onupdate=func.now(), nullable=False, index=True
    )

    otps: Mapped[list["OTP"]] = relationship("OTP", back_populates="user")
    products: Mapped[list["Product"]] = relationship("Product", back_populates="vendor")

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".title()

    @classmethod
    async def get(cls, session: AsyncSession, **kwargs) -> Union["User", None]:
        """
        Retrieve a User record from the database based on provided filter arguments.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the query.
            **kwargs: Arbitrary keyword arguments representing the filter conditions.
        Returns:
            Union["User", None]: The User object if found, otherwise None.
        Raises:
            ValueError: If no filter arguments are provided or if invalid filter arguments are given.
        Example:
            user = await User.get(session, id=1)
        """
        if not kwargs:
            db_logger.warning("No filter arguments provided to fetch a User.")
            raise ValueError("No filter arguments provided")

        valid_keys = {column.key for column in cls.__table__.columns}
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid filter keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid filter arguments: {', '.join(invalid_keys)}")

        conditions = [getattr(cls, key) == value for key, value in kwargs.items()]
        db_logger.info(f"Fetching User with conditions: {kwargs}")
        result = await session.execute(select(cls).where(and_(*conditions)))
        user = result.scalar_one_or_none()

        if user:
            db_logger.info(f"User found: {user}")
        else:
            db_logger.info(f"No User found for conditions: {kwargs}")

        return user

    @classmethod
    async def filter(
        cls,
        session: AsyncSession,
        op: str = "and",
        limit: int = 10,
        offset: int = 0,
        **kwargs,
    ) -> list["User"]:
        """
        Filters and retrieves a list of User records from the database based on the provided conditions.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the query.
            op (str, optional): The logical operator to use for combining conditions. Defaults to "and".
                Must be either "and" or "or".
            limit (int, optional): The maximum number of records to return. Defaults to 10.
            offset (int, optional): The number of records to skip before starting to return records. Defaults to 0.
            **kwargs: Arbitrary keyword arguments representing the filter conditions. The keys must match the column names
                of the User model.
        Returns:
            list[User]: A list of User objects that match the filter conditions.
        Raises:
            ValueError: If an invalid operator is provided, no filter arguments are provided, or invalid filter keys are provided.
        Logs:
            - Warnings for invalid operators, no filter arguments, and invalid filter keys.
            - Info for the conditions used to fetch Users and the result of the query.
        """
        if op not in ["and", "or"]:
            db_logger.warning(f"Invalid operator: {op}")
            raise ValueError(f"Invalid operator: {op}")
        if not kwargs:
            db_logger.warning("No filter arguments provided to fetch Users.")
            raise ValueError("No filter arguments provided")

        valid_keys = {column.key for column in cls.__table__.columns}
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid filter keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid filter arguments: {', '.join(invalid_keys)}")

        conditions = [getattr(cls, key) == value for key, value in kwargs.items()]
        db_logger.info(f"Fetching Users with conditions: {kwargs}")
        query = select(cls).where(
            and_(*conditions) if op == "and" else or_(*conditions)
        )
        query = query.limit(limit).offset(offset)

        result = await session.execute(query)
        users = result.scalars().all()

        if users:
            db_logger.info(f"Users found: {users}")
        else:
            db_logger.info(f"No Users found for conditions: {kwargs}")

        return users

    @classmethod
    def validate_model(cls, **kwargs) -> None:
        """
        Validates the User model.
        Args:
            **kwargs: Arbitrary keyword arguments containing the fields to validate.
        Raises:
            ValueError: If any of the fields are invalid.
        """
        # Log action (excluding sensitive information)
        log_data = {key: value for key, value in kwargs.items() if key != "password"}
        db_logger.info(f"Validating User data: {log_data}")

        # Validate required fields
        required_fields = {
            "first_name",
            "last_name",
            "email",
            "phone",
            "password",
            "role",
        }
        missing_fields = required_fields - kwargs.keys()
        if missing_fields:
            db_logger.warning(f"Missing required fields: {', '.join(missing_fields)}")
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

        # Validate field keys
        valid_keys = {
            "first_name",
            "last_name",
            "email",
            "phone",
            "password",
            "role",
        }
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid arguments: {', '.join(invalid_keys)}")

    @classmethod
    async def create(
        cls, session: AsyncSession, commit_self: bool = True, **kwargs
    ) -> "User":
        """
        Asynchronously creates a new User record in the database.
        This method performs several tasks:
        - Logs the creation action (excluding sensitive information).
        - Validates required fields.
        - Validates field keys against model columns.
        - Hashes the password.
        - Checks for unique constraints (email, phone).
        - Creates and saves the new User record.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for database operations.
            commit_self (bool, optional): If True, commit the User instance to the database. Defaults to True.
            **kwargs: Arbitrary keyword arguments containing the fields for the new User record.
        Returns:
            User: The newly created User object.
        Raises:
            ValueError: If required fields are missing, invalid keys are provided.
        """
        # Log action (excluding sensitive information)
        log_data = {key: value for key, value in kwargs.items() if key != "password"}
        db_logger.info(f"Creating new User with data: {log_data}")

        # Validate the User model
        cls.validate_model(**kwargs)

        # Hash password early
        kwargs["hashed_password"] = hash_password(kwargs.pop("password"))
        user = cls(**kwargs)
        session.add(user)

        if commit_self:
            try:
                await session.commit()
                await session.refresh(user)
                db_logger.info(f"Successfully created User(id={user.id})")
            except Exception as e:
                db_logger.error(f"Failed to create User: {str(e)}")
                raise
        else:
            await session.flush()  # Ensure ID is assigned for later use
            db_logger.info(f"User prepared for creation(id={user.id})")

        return user

    @classmethod
    async def create_admin(
        cls,
        session: AsyncSession,
        first_name: str,
        last_name: str,
        email: str,
        phone: str,
        password: str,
        commit_self: bool = True,
    ) -> "User":
        """
        Creates a new admin user in the database.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            first_name (str): The first name of the admin user.
            last_name (str): The last name of the admin user.
            email (str): The email of the admin user.
            phone (str): The phone number of the admin user.
            password (str): The password of the admin user.
            commit_self (bool, optional): If True, commit the User instance to the database. Defaults to True.

        Returns:
            User: The newly created admin user.
        """
        try:
            return await cls.create(
                session,
                commit_self=commit_self,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                password=password,
                role=Role.ADMIN,
            )
        except Exception as e:
            db_logger.error(f"Failed to create admin user: {str(e)}")
            raise

    async def update(
        self, session: AsyncSession, commit_self: bool = True, **kwargs
    ) -> "User":
        """
        Asynchronously updates the current User instance with the provided keyword arguments.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the update.
            commit_self (bool, optional): If True, commit the User instance to the database. Defaults to True.
            **kwargs: Arbitrary keyword arguments representing the fields to update and their new values.
        Returns:
            User: The updated User instance.
        Raises:
            ValueError: If any of the provided keyword arguments are not valid column names for the User model.
        Logs:
            - A warning if any invalid update keys are provided.
            - An info message before updating the User instance.
            - An info message after successfully updating the User instance.
        """
        valid_keys = {column.key for column in self.__table__.columns}
        read_only_keys = {
            "id",
            "created_at",
            "updated_at",
            "hashed_password",
            "is_deleted",
            "is_active",
            "is_verified",
            "role",
        }
        valid_keys -= read_only_keys
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid update keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid update arguments: {', '.join(invalid_keys)}")

        db_logger.info(f"Updating User(id={self.id}) with {kwargs}")
        for key, value in kwargs.items():
            setattr(self, key, value)

        session.add(self)  # Ensure the object is tracked by the session

        if commit_self:
            try:
                await session.commit()
                await session.refresh(self)
                db_logger.info(f"Successfully updated User(id={self.id})")
            except Exception as e:
                db_logger.error(f"Failed to update User(id={self.id}): {str(e)}")
                raise
        else:
            await session.flush()  # Sync changes to the session without committing
            db_logger.info(f"User update prepared(id={self.id})")

        return self

    async def delete(
        self, session: AsyncSession, mode: str = "soft", commit_self: bool = True
    ) -> None:
        """
        Deletes the current instance of the User model.

        Args:
            session (AsyncSession): The SQLAlchemy async session to use for the operation.
            mode (str, optional): The mode of deletion. Can be either "soft" or "hard". Defaults to "soft".
            commit_self (bool, optional): If True, commit the deletion to the database. Defaults to True.

        Raises:
            ValueError: If the provided mode is not "soft" or "hard".

        Returns:
            None
        """
        if mode not in ["soft", "hard"]:
            db_logger.warning(f"Invalid delete mode: {mode}")
            raise ValueError(f"Invalid delete mode: {mode}")

        if mode == "soft":
            db_logger.info(f"Soft deleting User(id={self.id})")
            self.is_deleted = True
            session.add(self)  # Ensure the object is tracked
            if commit_self:
                await session.commit()
                await session.refresh(self)
                db_logger.info(f"Successfully soft deleted User(id={self.id})")
            else:
                await session.flush()
                db_logger.info(f"Soft deletion prepared for User(id={self.id})")
        else:
            db_logger.info(f"Deleting User(id={self.id})")
            await session.delete(self)
            if commit_self:
                await session.commit()
                db_logger.info(f"Successfully deleted User(id={self.id})")
            else:
                await session.flush()
                db_logger.info(f"Deletion prepared for User(id={self.id})")

        return None

    async def deactivate(
        self, session: AsyncSession, commit_self: bool = True
    ) -> "User":
        """
        Deactivates the user by setting the `is_active` attribute to False.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            commit_self (bool, optional): If True, commit the change to the database. Defaults to True.

        Returns:
            User: The updated user instance with `is_active` set to False.
        """
        db_logger.info(f"Deactivating User(id={self.id})")
        self.is_active = False
        session.add(self)  # Ensure the object is tracked
        if commit_self:
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully deactivated User(id={self.id})")
        else:
            await session.flush()
            db_logger.info(f"Deactivation prepared for User(id={self.id})")

        return self

    def authenticate(
        self, password: str, return_object: bool = False
    ) -> Union["User", bool]:
        """
        Authenticate the user by verifying the provided password.

        Args:
            password (str): The password to verify.
            return_object (bool, optional): If True, return the user object on successful authentication.
                                            If False, return a boolean indicating success. Defaults to False.

        Returns:
            Union["User", bool]: The user object if return_object is True and authentication is successful,
                                    otherwise a boolean indicating the success of the authentication.
                                    Returns None if return_object is True and authentication fails.
        """
        if verify_password(password, self.hashed_password):
            return self if return_object else True
        return None if return_object else False

    async def change_password(
        self, session: AsyncSession, new_password: str, commit_self: bool = True
    ) -> "User":
        """
        Change the password for the user.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            new_password (str): The new password to set for the user.
            commit_self (bool, optional): If True, commit the change to the database. Defaults to True.

        Returns:
            User: The updated user object with the new hashed password.

        Logs:
            Logs the process of changing the password, including success messages.
        """
        db_logger.info(f"Changing password for User(id={self.id})")
        self.hashed_password = hash_password(new_password)
        session.add(self)  # Ensure the object is tracked
        if commit_self:
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully changed password for User(id={self.id})")
        else:
            await session.flush()
            db_logger.info(f"Password change prepared for User(id={self.id})")

        return self

    async def verify(self, session: AsyncSession, commit_self: bool = True) -> "User":
        """
        Verifies the user by setting the `is_verified` and `is_active` attributes to True.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            commit_self (bool, optional): If True, commit the change to the database. Defaults to True.

        Returns:
            User: The updated user instance with `is_verified` and `is_active` set to True.
        """
        db_logger.info(f"Verifying User(id={self.id})")
        self.is_active = True
        self.is_verified = True
        session.add(self)  # Ensure the object is tracked
        if commit_self:
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully verified User(id={self.id})")
        else:
            await session.flush()
            db_logger.info(f"Verification prepared for User(id={self.id})")

        return self


class OTP(Base):
    __tablename__ = "otps"

    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    code: Mapped[str] = mapped_column(nullable=False)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    user: Mapped[User] = relationship("User", back_populates="otps")
    expiration_time: Mapped[datetime] = mapped_column(nullable=False)
    is_used: Mapped[bool] = mapped_column(default=False)
    is_password_reset: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        default=func.now(), nullable=False, index=True
    )

    @classmethod
    async def create(
        cls,
        session: AsyncSession,
        user_id: UUID,
        commit_self: bool = True,
        is_password_reset: bool = False,
    ) -> "OTP":
        """
        Creates a new OTP record in the database.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            user_id (UUID): The ID of the user associated with the OTP.
            commit_self (bool, optional): If True, commit the OTP instance to the database. Defaults to True.
            is_password_reset (bool, optional): If True, the OTP is for a password reset. Defaults to False.

        Returns:
            OTP: The newly created OTP record.
        """
        code = generate_otp()
        db_logger.info(f"Creating new OTP: {code}")
        expiration_time = datetime.now() + timedelta(
            minutes=get_settings().otp_expiry_minutes
        )
        otp = cls(
            code=code,
            user_id=user_id,
            expiration_time=expiration_time,
            is_password_reset=is_password_reset,
        )
        session.add(otp)

        if commit_self:
            await session.commit()
            await session.refresh(otp)
            db_logger.info(f"Successfully created OTP(id={otp.id})")
        else:
            await session.flush()  # Ensure ID is assigned for later use
            db_logger.info(f"OTP prepared for creation(id={otp.id})")

        return otp

    @classmethod
    async def get(cls, session: AsyncSession, **kwargs) -> Union["OTP", None]:
        """
        Retrieve an OTP record from the database based on provided filter arguments.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the query.
            **kwargs: Arbitrary keyword arguments representing the filter conditions.

        Returns:
            Union["OTP", None]: The OTP object if found, otherwise None.

        Raises:
            ValueError: If no filter arguments are provided or if invalid filter arguments are given.

        Example:
            otp = await OTP.get(session, id=1)
        """
        if not kwargs:
            db_logger.warning("No filter arguments provided to fetch an OTP.")
            raise ValueError("No filter arguments provided")

        valid_keys = {
            "id",
            "code",
            "is_used",
            "is_password_reset",
            "user_id",
            "expiration_time",
            "created_at",
        }
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid filter keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid filter arguments: {', '.join(invalid_keys)}")

        conditions = [getattr(cls, key) == value for key, value in kwargs.items()]
        db_logger.info(f"Fetching OTP with conditions: {kwargs}")
        result = await session.execute(select(cls).where(and_(*conditions)))
        otp = result.scalar_one_or_none()

        if otp:
            db_logger.info(f"OTP found: {otp}")
        else:
            db_logger.info(f"No OTP found for conditions: {kwargs}")

        return otp

    async def use(self, session: AsyncSession, commit_self: bool = True) -> "OTP":
        """
        Marks the OTP as used.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            commit_self (bool, optional): If True, commit the changes to the database. Defaults to True.

        Returns:
            OTP: The updated OTP object with `is_used` set to True.

        Raises:
            ValueError: If the user is already verified.

        Logs:
            Logs the process of using the OTP, including success messages.
        """
        db_logger.info(f"Using OTP(id={self.id})")
        if not self.is_password_reset:
            if self.user.is_verified:
                raise ValueError("User is already verified")

            await self.user.verify(
                session, commit_self=False
            )  # Verify the user when OTP is not for password reset
        self.is_used = True
        session.add(self)  # Ensure the object is tracked

        if commit_self:
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully used OTP(id={self.id})")
        else:
            await session.flush()  # Sync changes to the session
            db_logger.info(f"OTP use prepared(id={self.id})")

        return self

    @property
    def is_expired(self) -> bool:
        """
        Checks if the OTP is expired.

        Returns:
            bool: True if the OTP is expired, False otherwise.
        """
        return self.expiration_time < datetime.now()

    @property
    def is_valid(self) -> bool:
        """
        Checks if the OTP is valid.

        Returns:
            bool: True if the OTP is valid, False otherwise.
        """
        return not self.is_used and not self.is_expired

    async def regenerate(
        self, session: AsyncSession, commit_self: bool = True
    ) -> "OTP":
        """
        Regenerates the OTP code and updates the expiration time.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            commit_self (bool, optional): If True, commit the changes to the database. Defaults to True.

        Returns:
            OTP: The updated OTP object with the new code and expiration time.

        Logs:
            Logs the process of regenerating the OTP, including success messages.
        """
        db_logger.info(f"Regenerating OTP(id={self.id})")
        self.code = generate_otp()
        self.expiration_time = datetime.now() + timedelta(
            minutes=get_settings().otp_expiry_minutes
        )
        session.add(self)

        if commit_self:
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully regenerated OTP(id={self.id})")
        else:
            await session.flush()
            db_logger.info(f"OTP regeneration prepared(id={self.id})")

        return self


class Product(Base):
    __tablename__ = "products"

    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    public_id: Mapped[str | None] = mapped_column(
        nullable=True,
        comment="Unique identifier from cloudinary async upload",
    )
    vendor_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(nullable=False)
    category: Mapped[str] = mapped_column(nullable=False, index=True)
    price: Mapped[Decimal] = mapped_column(Numeric(scale=2), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    specification: Mapped[str] = mapped_column(Text, nullable=False)
    image_url: Mapped[str | None] = mapped_column(nullable=True)  # Folder Path

    created_at: Mapped[datetime] = mapped_column(
        default=func.now(), nullable=False, index=True
    )
    vendor: Mapped["User"] = relationship("User", back_populates="products")

    @classmethod
    def validate_model(cls, **kwargs) -> None:
        """
        Validates the Product model.
        Args:
            **kwargs: Arbitrary keyword arguments containing the fields to validate.
        Raises:
            ValueError: If any of the fields are invalid
        """
        # Log action (excluding sensitive information)
        log_data = {key: value for key, value in kwargs.items()}
        db_logger.info(f"Validating Product data: {log_data}")

        # Validate required fields
        required_fields = {
            "name",
            "category",
            "price",
            "description",
            "specification",
            "vendor_id",
        }
        missing_fields = required_fields - kwargs.keys()
        if missing_fields:
            db_logger.warning(f"Missing required fields: {', '.join(missing_fields)}")
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

        # Validate field keys
        valid_keys = {
            "name",
            "category",
            "price",
            "description",
            "specification",
            "image_url",
            "vendor_id",
        }
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid arguments: {', '.join(invalid_keys)}")

        # Validate price
        if not isinstance(kwargs["price"], Decimal):
            db_logger.warning(f"Invalid price: {kwargs['price']}")
            raise ValueError("Price must be a Decimal")

    @classmethod
    async def create(
        cls, session: AsyncSession, commit_self: bool = True, **kwargs
    ) -> "Product":
        """
        Asynchronously creates a new Product record in the database.
        This method performs several tasks:
        - Logs the creation action (excluding sensitive information).
        - Validates required fields.
        - Validates field keys against model columns.
        - Checks for unique constraints (name, category).
        - Creates and saves the new Product record.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for database operations.
            commit_self (bool, optional): If True, commit the Product instance to the database. Defaults to True.
            **kwargs: Arbitrary keyword arguments containing the fields for the new Product record.
        Returns:
            Product: The newly created Product object.
        Raises:
            ValueError: If required fields are missing, invalid keys are provided.
        """
        # Log action (excluding sensitive information)
        log_data = {key: value for key, value in kwargs.items()}
        db_logger.info(f"Creating new Product with data: {log_data}")

        # Validate the Product model
        cls.validate_model(**kwargs)

        # Ensure only vendor roles can create products
        user = await User.get(session, id=kwargs["vendor_id"])
        if user.role != Role.VENDOR:
            db_logger.warning(
                f"User(id={user.id}) is not authorized to create a Product"
            )
            raise ValueError("User is not authorized to create a Product")

        product = cls(**kwargs)
        session.add(product)

        if commit_self:
            try:
                await session.commit()
                await session.refresh(product)
                db_logger.info(f"Successfully created Product(id={product.id})")
            except Exception as e:
                db_logger.error(f"Failed to create Product: {str(e)}")
                raise
        else:
            await session.flush()
            db_logger.info(f"Product prepared for creation(id={product.id})")

        return product

    @classmethod
    async def get(cls, session: AsyncSession, **kwargs) -> Union["Product", None]:
        """
        Retrieve a Product record from the database based on provided filter arguments.
        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the query.
            **kwargs: Arbitrary keyword arguments representing the filter conditions.
        Returns:
            Union["Product", None]: The Product object if found, otherwise None.
        Raises:
            ValueError: If no filter arguments are provided or if invalid filter arguments are given.
        Example:
            product = await Product.get(session, id=1)
        """
        if not kwargs:
            db_logger.warning("No filter arguments provided to fetch a Product.")
            raise ValueError("No filter arguments provided")

        valid_keys = {column.key for column in cls.__table__.columns}
        invalid_keys = set(kwargs.keys()) - valid_keys
        if invalid_keys:
            db_logger.warning(f"Invalid filter keys: {', '.join(invalid_keys)}")
            raise ValueError(f"Invalid filter arguments: {', '.join(invalid_keys)}")

        conditions = [getattr(cls, key) == value for key, value in kwargs.items()]
        db_logger.info(f"Fetching Product with conditions: {kwargs}")
        result = await session.execute(select(cls).where(and_(*conditions)))
        product = result.scalar_one_or_none()

        if product:
            db_logger.info(f"Product found: {product}")
        else:
            db_logger.info(f"No Product found for conditions: {kwargs}")

        return product

    async def upload_image(
        self,
        session: AsyncSession,
        public_id: str,
        image_url: str,
        commit_self: bool = True,
    ) -> "Product":
        """
        Updates the product with an image URL.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.
            public_id (str): The public ID of the uploaded image
            image_url (str): The URL of the uploaded image.
            commit_self (bool, optional): If True, commit the changes to the database. Defaults to True.

        Returns:
            Product: The updated product object with the image URL.

        Logs:
            Logs the process of uploading the image, including success messages.
        """
        db_logger.info(f"Uploading image for Product(id={self.id})")
        self.image_url = image_url
        self.public_id = public_id
        session.add(self)

        if commit_self:
            await session.commit()
            await session.refresh(self)
            db_logger.info(f"Successfully uploaded image for Product(id={self.id})")
        else:
            await session.flush()
            db_logger.info(f"Image upload prepared for Product(id={self.id})")

    async def delete(self, session: AsyncSession, commit_self: bool = True) -> None:
        """
        Deletes the current instance of the Product model.

        Args:
            session (AsyncSession): The SQLAlchemy async session to use for the operation.
            commit_self (bool, optional): If True, commit the deletion to the database. Defaults to True.

        Returns:
            None
        """
        db_logger.info(f"Deleting Product(id={self.id})")
        await session.delete(self)
        if commit_self:
            await session.commit()
            db_logger.info(f"Successfully deleted Product(id={self.id})")
        else:
            await session.flush()
            db_logger.info(f"Deletion prepared for Product(id={self.id})")

        return None


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        default=func.now(), nullable=False, index=True
    )

    user: Mapped["User"] = relationship("User")
    artifacts: Mapped[list["OrderArtifact"]] = relationship(
        "OrderArtifact", back_populates="order"
    )

    async def get_total_price(self, session: AsyncSession) -> Decimal:
        """
        Get the total price of the order.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.

        Returns:
            Decimal: The total price of the order.
        """
        total_price_query = (
            select(func.sum(OrderArtifact.price * OrderArtifact.unit))
            .where(OrderArtifact.order_id == self.id)
            .scalar_subquery()
        )
        result = await session.execute(total_price_query)
        return


class OrderArtifact(Base):
    __tablename__ = "order_artifacts"

    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    order_id: Mapped[UUID] = mapped_column(ForeignKey("orders.id"), nullable=False)
    product_id: Mapped[UUID] = mapped_column(ForeignKey("products.id"), nullable=False)
    unit: Mapped[int] = mapped_column(nullable=False)
    price: Mapped[Decimal] = mapped_column(Numeric(scale=2), nullable=False)
    delivery_status: Mapped[DeliveryStatus] = mapped_column(
        nullable=False, default=DeliveryStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(
        default=func.now(), nullable=False, index=True
    )

    product: Mapped["Product"] = relationship("Product")
    order: Mapped["Order"] = relationship("Order", back_populates="artifacts")

    @property
    def total_price(self) -> Decimal:
        return self.price * self.unit

    async def get_product(self, session: AsyncSession) -> str:
        """
        Get the product associated with the order artifact.

        Args:
            session (AsyncSession): The SQLAlchemy asynchronous session to use for the operation.

        Returns:
            str: The product.
        """
        product = await Product.get(session, id=self.product_id)
        return product
