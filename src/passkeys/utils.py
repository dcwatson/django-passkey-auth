import base64
import binascii
import uuid
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib import auth
from django.db import models
from django.http import HttpRequest
from django.utils.module_loading import import_string

if TYPE_CHECKING:
    from .backend import PasskeyBackend


def pk_bytes(obj: Any) -> bytes:
    """
    Given a primary key value, return its bytestring representation.
    """
    if isinstance(obj, int):
        return obj.to_bytes(8)
    elif isinstance(obj, uuid.UUID):
        return obj.bytes
    return str(obj).encode("utf-8")


def pk_value(data: bytes, model=None):
    """
    Parse the specified bytestring into an appropriate primary key value for the
    given model (or the auth user model if none is specified).
    """
    if model is None:
        model = auth.get_user_model()
    field = model._meta.pk
    if isinstance(field, models.IntegerField):
        return int.from_bytes(data)
    elif isinstance(field, models.UUIDField):
        return uuid.UUID(bytes=data)
    return data.decode("utf-8")


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(data: str) -> bytes:
    for i in range(3):
        try:
            return base64.urlsafe_b64decode(data + ("=" * i))
        except binascii.Error:
            pass
    raise ValueError("Could not base64url_decode `{data}`")


def get_backend(request: HttpRequest) -> "PasskeyBackend":
    backend_class = import_string(
        getattr(settings, "PASSKEY_BACKEND", "passkeys.backend.PasskeyBackend")
    )
    return backend_class(request)
