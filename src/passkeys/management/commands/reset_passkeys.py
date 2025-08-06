from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = "Drops and re-creates the passkey database table."

    def handle(self, *args, **options):
        with connection.cursor() as c:
            c.execute("DROP TABLE IF EXISTS passkeys_passkey")
            c.execute("DELETE FROM django_migrations WHERE app='passkeys'")
        call_command("migrate", "passkeys")
