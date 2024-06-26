# Generated by Django 5.0.4 on 2024-04-04 00:49

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models

import passkeys.fields


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Passkey",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("credential_id", models.CharField(max_length=100)),
                (
                    "algorithm",
                    models.IntegerField(
                        choices=[(-7, "ES256 (ECDSA w/ SHA-256)"), (-8, "EdDSA")]
                    ),
                ),
                ("public_key", passkeys.fields.PublicKeyField()),
                (
                    "date_created",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="passkeys",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="passkey",
            constraint=models.UniqueConstraint(
                fields=("user", "credential_id"), name="unique_user_credential"
            ),
        ),
    ]
