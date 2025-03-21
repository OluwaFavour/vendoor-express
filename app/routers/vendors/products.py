from datetime import datetime
from typing import Annotated, BinaryIO
from uuid import UUID
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from rich import print
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings, request_logger
from app.core.dependencies import get_async_smtp, get_logged_in_vendor
from app.core.enums import Status
from app.core.utils.files import CloudinaryException, destroy, upload
from app.core.utils.messages import send_email
from app.db.config import get_async_session, get_async_session_context
from app.db.models import Product, User
from app.db.pagination import paginate_query
from app.schemas.vendors.products import (
    PaginatedProductsResponse,
    ProductCreateForm,
    ProductResponse,
    ProductWebhookData,
)
from app.schemas.users import MessageResponse

prefix = "/vendors/products"
router = APIRouter(prefix=prefix, tags=["products", "vendors"])

cloudinary_webhook_url = "/cloudinary_webhook"


async def send_image_upload_status_email(
    user_email: str, product_id: UUID, upload_status: Status, detail: str = ""
) -> None:
    settings = get_settings()
    message = ""
    if upload_status == Status.PENDING:
        message = f"Product image upload for user {user_email} with product {product_id} is pending."
    elif upload_status == Status.SUCCESS:
        message = f"Product image upload for user {user_email} with product {product_id} was successful."
    elif upload_status == Status.FAILED:
        message = f"Product image upload for user {user_email} with product {product_id} failed with error: {detail}."

    # Send email
    async with get_async_smtp() as smtp:
        try:
            await send_email(
                smtp=smtp,
                subject="Product Image Upload Status from Vendoor Express",
                recipient={
                    "email": settings.from_email,
                    "display_name": settings.from_name,
                },
                plain_text=message,
            )
            request_logger.info(f"Email sent to {settings.from_email}")
        except Exception as e:
            request_logger.error(
                f"Error sending email to {settings.from_email}: {str(e)}"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            )


async def image_upload_background_task(
    product_id: UUID,
    vendor_id: UUID,
    file_content: bytes,
) -> None:
    try:
        async with get_async_session_context() as session:
            async with session.begin():
                request_logger.info(f"Retrieving product with ID: {product_id}")
                product = await Product.get(session, id=product_id)
                product_image_folder = f"users/{vendor_id}/products/{product_id}"
                request_logger.info(
                    f"Uploading image to Cloudinary: {product_image_folder}"
                )
                vendor = await User.get(session, id=vendor_id)
                upload(
                    file_content,
                    product_image_folder,
                    "image",
                    f"{prefix}{cloudinary_webhook_url}",
                    {"product_id": str(product_id), "user_email": str(vendor.email)},
                )
                request_logger.info("Product upload pending")
            await session.refresh(product)
    except CloudinaryException as e:
        request_logger.error(f"Error uploading product image: {str(e)}")
    except Exception as e:
        request_logger.error(f"Error uploading product image: {str(e)}")


async def destroy_product_image(public_id: str) -> None:
    try:
        request_logger.info(f"Deleting image from Cloudinary: {public_id}")
        destroy(public_id)
        request_logger.info("Product image asset deleted")
    except CloudinaryException as e:
        request_logger.error(f"Error deleting product image: {str(e)}")
    except Exception as e:
        request_logger.error(f"Error deleting product image: {str(e)}")


@router.post(cloudinary_webhook_url)
async def cloudinary_webhook(
    data: ProductWebhookData,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> MessageResponse:
    """
    Handles the Cloudinary webhook to update product image URL.
    Args:
        data (ProductWebhookData): The data received from the Cloudinary webhook containing the context and secure_url.
        session (Annotated[AsyncSession, Depends(get_async_session)]): The database session dependency.
    Returns:
        MessageResponse: A response message indicating the result of the operation.
    Raises:
        HTTPException: If the product is not found or if there is an error updating the product image URL.
    """
    print(f"[cyan]data: {data}[/cyan]")
    product_id = data.context.custom["product_id"]
    user_email = data.context.custom["user_email"]
    try:
        async with session.begin():
            # Get product by product_id
            product = await Product.get(session, id=product_id)
            if not product:
                request_logger.warning(
                    f"Product not found with product_id: {product_id}"
                )
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
                )
            # Update product with image URL
            await product.upload_image(
                session, data.public_id, data.secure_url, commit_self=False
            )
        await send_image_upload_status_email(user_email, product_id, Status.SUCCESS)
    except HTTPException as e:
        if e.status_code == status.HTTP_404_NOT_FOUND:
            await send_image_upload_status_email(
                user_email, product_id, Status.FAILED, "Product not found"
            )
        raise
    except Exception as e:
        request_logger.error(f"Error updating product with image URL: {str(e)}")
        await send_image_upload_status_email(
            user_email, product_id, Status.FAILED, str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )

    return MessageResponse(message="Product image uploaded successfully")


@router.post("/")
async def add_product(
    data: Annotated[ProductCreateForm, Depends()],
    vendor: Annotated[User, Depends(get_logged_in_vendor)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    background_tasks: BackgroundTasks,
) -> ProductResponse:
    """
    add_product adds a new product to the database.
    Args:
        data (ProductCreate): The product data to add.
        vendor (Annotated[User, Depends(get_logged_in_vendor)]): The logged in active vendor dependency.
        session (Annotated[AsyncSession, Depends(get_async_session)]): The database session dependency.
        background_tasks (BackgroundTasks): The background tasks dependency.
    Returns:
        ProductReponse: The added product.
    Raises:
        HTTPException: If there is an error adding the product.
    """
    try:
        # Upload product image to Cloudinary
        upload_data = data.model_dump()
        product_image: UploadFile = upload_data.pop("image")
        image_content = await product_image.read() if product_image else None

        async with session.begin():
            request_logger.info("Adding product to database")
            product = await Product.create(
                session,
                commit_self=False,
                vendor_id=vendor.id,
                **upload_data,
            )
            await session.flush()
        if image_content:
            background_tasks.add_task(
                image_upload_background_task,
                product.id,
                vendor.id,
                image_content,
            )
        await session.refresh(product)
        return ProductResponse(message="Product added successfully", product=product)
    except ValueError as e:
        request_logger.error(f"Error adding product: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        request_logger.error(f"Error adding product: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.get("/", response_model=PaginatedProductsResponse)
async def get_products(
    vendor: Annotated[User, Depends(get_logged_in_vendor)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    after: Annotated[datetime | None, Query()] = None,
    before: Annotated[datetime | None, Query()] = None,
    include_total: Annotated[
        bool, Query(description="Whether to include the total count of items")
    ] = False,
):
    """
    Retrieve a paginated list of products for the logged-in vendor.
    Args:
        vendor (User): The logged-in active vendor.
        session (AsyncSession): The database session.
        limit (int, optional): The maximum number of products to return (default is 10, must be between 1 and 100).
        after (datetime, optional): Return products created after this datetime.
        before (datetime, optional): Return products created before this datetime.
        include_total (bool, optional): Whether to include the total count of items (default is False).
    Returns:
        PaginatedProductsResponse: A response object containing the paginated list of products, total count (if requested), and pagination cursors.
    Raises:
        HTTPException: If both 'after' and 'before' query parameters are provided.
        HTTPException: If there is an error retrieving the products.
    """
    if after and before:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot provide both 'after' and 'before'",
        )

    try:
        async with session.begin():
            products, total, next_cursor, previous_cursor = await paginate_query(
                session=session,
                model=Product,
                filter_conditions={"vendor_id": vendor.id},
                limit=limit,
                after=after,
                before=before,
                order_by_field="created_at",
                include_total=include_total,
            )

        return PaginatedProductsResponse(
            items=products,
            total=total,
            next_cursor=next_cursor,
            previous_cursor=previous_cursor,
            limit=limit,
            vendor=vendor,
        )
    except Exception as e:
        request_logger.error(f"Error getting products: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.get("/products/{product_id}")
async def get_product(
    product_id: UUID,
    vendor: Annotated[User, Depends(get_logged_in_vendor)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> ProductResponse:
    """
    get_product retrieves a product by its ID.
    Args:
        product_id (UUID): The ID of the product to retrieve.
        vendor (Annotated[User, Depends(get_logged_in_vendor)]): The logged in active vendor dependency.
        session (Annotated[AsyncSession, Depends(get_async_session)]): The database session dependency.
    Returns:
        ProductResponse: The retrieved product.
    Raises:
        HTTPException: If the product is not found.
    """
    try:
        async with session.begin():
            request_logger.info(f"Retrieving product with ID: {product_id}")
            product = await Product.get(session, id=product_id, vendor_id=vendor.id)
            if not product:
                request_logger.warning(f"Product not found with ID: {product_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
                )
        return ProductResponse(
            message="Product retrieved successfully", product=product
        )
    except HTTPException:
        raise
    except Exception as e:
        request_logger.error(f"Error getting product: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.delete("/products/{product_id}")
async def delete_product(
    product_id: UUID,
    vendor: Annotated[User, Depends(get_logged_in_vendor)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    background_tasks: BackgroundTasks,
) -> MessageResponse:
    """
    delete_product deletes a product by its ID.
    Args:
        product_id (UUID): The ID of the product to delete.
        vendor (Annotated[User, Depends(get_logged_in_vendor)]): The logged in active vendor dependency.
        session (Annotated[AsyncSession, Depends(get_async_session)]): The database session dependency.
        background_tasks (BackgroundTasks): The background tasks dependency.
    Returns:
        MessageResponse: A response message indicating the result of the operation.
    Raises:
        HTTPException: If the product is not found or if there is an error deleting the product.
    """
    try:
        public_id = None
        async with session.begin():
            request_logger.info(f"Retrieving product with ID: {product_id}")
            product = await Product.get(session, id=product_id, vendor_id=vendor.id)
            if not product:
                request_logger.warning(f"Product not found with ID: {product_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
                )
            request_logger.info(f"Product public_id: {product.public_id!r}")
            public_id = product.public_id if product.public_id else None
            request_logger.info(f"Deleting product with ID: {product_id}")
            await product.delete(session, commit_self=False)
        request_logger.info(f"Assigned public_id: {public_id!r}")
        if public_id:
            background_tasks.add_task(destroy_product_image, public_id)
        return MessageResponse(message="Product deleted successfully")
    except HTTPException:
        raise
    except Exception as e:
        request_logger.error(f"Error deleting product: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
