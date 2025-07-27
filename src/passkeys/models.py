import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import models
from django.utils import timezone

from .fields import PublicKeyField


class COSEAlgorithm(models.IntegerChoices):
    ES256 = -7, "ES256 (ECDSA w/ SHA-256)"  # pyright: ignore
    EDDSA = -8, "EdDSA"  # pyright: ignore


class Passkey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="passkeys",
    )
    credential_id = models.CharField(max_length=100)
    name = models.CharField(max_length=100, blank=True)
    algorithm = models.IntegerField(choices=COSEAlgorithm.choices)
    public_key = PublicKeyField()
    date_created = models.DateTimeField(default=timezone.now)
    last_used = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "credential_id"], name="unique_user_credential"
            ),
        ]

    def __str__(self):
        return self.name or self.credential_id

    def verify(self, auth_data: bytes, client_data: bytes, signature: bytes):
        check_data = auth_data + hashlib.sha256(client_data).digest()
        if self.algorithm == COSEAlgorithm.ES256:
            self.public_key.verify(signature, check_data, ec.ECDSA(hashes.SHA256()))
        else:
            self.public_key.verify(signature, check_data)
