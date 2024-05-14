from typing import Union

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
    load_pem_public_key,
)
from django import forms
from django.db import models


def load_public_key(data) -> PublicKeyTypes:
    if isinstance(data, PublicKeyTypes):
        return data
    elif isinstance(data, str):
        return load_pem_public_key(data.encode())
    elif isinstance(data, bytes):
        return load_der_public_key(data)
    raise ValueError("Unknown public key type `{}`".format(data.__class__.__name__))


class PublicKeyFormField(forms.Field):
    widget = forms.Textarea

    def to_python(self, value):
        return load_public_key(value)

    def prepare_value(self, value):
        return value.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        ).decode()


class PublicKeyField(models.TextField):
    @classmethod
    def load(cls, value: Union[str, bytes]):
        return load_public_key(value)

    def formfield(self, **kwargs):
        return PublicKeyFormField(**kwargs)

    def from_db_value(self, value, expression, connection):
        return load_public_key(value)

    def get_prep_value(self, value):
        return (
            load_public_key(value)
            .public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def to_python(self, value):
        return load_public_key(value)
