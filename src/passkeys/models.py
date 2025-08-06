from django.conf import settings
from django.db import models
from django.utils import timezone


class Passkey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="passkeys",
    )
    credential_id = models.CharField(max_length=100)
    name = models.CharField(max_length=100, blank=True)
    credential_data = models.BinaryField()
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
