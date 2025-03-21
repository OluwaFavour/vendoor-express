from typing import Any
from cloudinary.uploader import (
    upload as cloudinary_upload,
    destroy as cloudinary_destroy,
)

from app.core.config import get_settings


class CloudinaryException(Exception):
    pass


def upload(
    file: Any,
    folder: str,
    resource_type: str,
    notification_url: str,
    context: dict[str, str] | None = None,
) -> None:
    """
    upload uploads a file to Cloudinary asynchronously.
    Ensure the Cloudinary notification URL is configured in settings to receive notifications.

    Args:
        file Any: The file to upload.
        folder (str): The folder to upload the file to.
        resource_type (str): The type of resource to upload, can be 'auto', 'image', 'video', or 'raw'.
        notification_url (str): The URL to receive webhook notifications from Cloudinary.
        context (dict[str, str] | None): The context to attach to the file.

    Raises:
        CloudinaryException: If the file fails to upload to Cloudinary.
    """
    options = {
        "use_filename": True,
        "folder": folder,
        "resource_type": resource_type,
        "async": True,
        "notification_url": f"{get_settings().app_url}{notification_url}",
        "tags": ["vendoor-express"],
    }
    if context:
        options["context"] = context
    cloudinary_response = cloudinary_upload(file=file, **options)

    if cloudinary_response["status"] != "pending":
        raise CloudinaryException("Failed to upload file to Cloudinary")


def destroy(public_id: str) -> None:
    """
    destroy deletes a file from Cloudinary.

    Args:
        public_id (str): The public ID of the file to delete.

    Raises:
        CloudinaryException: If the file fails to delete from Cloudinary.
    """
    cloudinary_response = cloudinary_destroy(public_id=public_id)
    if cloudinary_response["result"] != "ok":
        raise CloudinaryException("Failed to delete file from Cloudinary")
