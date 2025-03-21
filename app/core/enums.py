from enum import Enum


class Role(Enum):
    ADMIN = "admin"
    CUSTOMER = "customer"
    VENDOR = "vendor"


class Status(Enum):
    PENDING = "pending"
    FAILED = "failed"
    SUCCESS = "success"


class DeliveryStatus(Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
