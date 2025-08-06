import base64
import binascii
import uuid

from django.conf import settings
from django.db import models
from django.http import HttpRequest
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
)


def get_server(request: HttpRequest) -> Fido2Server:
    origin = request.get_host().split(":")[0]
    site_name = getattr(settings, "PASSKEY_SITE_NAME", origin)
    rp = PublicKeyCredentialRpEntity(name=site_name, id=origin)
    return Fido2Server(rp)


def pk_bytes(obj) -> bytes:
    """
    Given a primary key value, return its bytestring representation.
    """
    if isinstance(obj, int):
        return obj.to_bytes(8)
    elif isinstance(obj, uuid.UUID):
        return obj.bytes
    return str(obj).encode("utf-8")


def pk_value(model, data: bytes):
    """
    Given a model class, parse the specified bytestring into an appropriate primary key
    value for the model.
    """
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
