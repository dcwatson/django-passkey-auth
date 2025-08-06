from django.contrib import admin

from .models import Passkey


@admin.register(Passkey)
class PasskeyAdmin(admin.ModelAdmin):
    list_display = [
        "credential_id",
        "user",
        "name",
        "date_created",
        "last_used",
    ]
