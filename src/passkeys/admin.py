from django.contrib import admin

from .models import Passkey


@admin.register(Passkey)
class PasskeyAdmin(admin.ModelAdmin):
    list_display = ["credential_id", "user", "algorithm", "date_created"]
