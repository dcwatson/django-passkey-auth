import json

from django.conf import settings
from django.contrib import auth
from django.http import HttpRequest
from django.utils import timezone
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from .models import Passkey
from .utils import base64url_decode, base64url_encode, pk_bytes, pk_value


class PasskeyBackend:
    def __init__(self, request: HttpRequest):
        self.request = request
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(name=self.name, id=self.origin)
        )

    @property
    def origin(self) -> str:
        return self.request.get_host().split(":")[0]

    @property
    def name(self) -> str:
        return getattr(settings, "PASSKEY_SITE_NAME", self.origin)

    @property
    def session_key(self):
        return getattr(settings, "PASSKEY_SESSION_KEY", "_passkey")

    @property
    def user(self):
        return self.request.user

    @property
    def user_bytes(self):
        return pk_bytes(self.user.pk)

    @property
    def user_name(self):
        return self.user.get_username()

    @property
    def user_display(self):
        return str(self.user)

    def set_state(self, state):
        self.request.session[self.session_key] = state

    def pop_state(self):
        return self.request.session.pop(self.session_key, None)

    def register_start(self):
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(
                id=self.user_bytes,
                name=self.user_name,
                display_name=self.user_display,
            )
        )
        self.set_state(state)
        return dict(options.public_key)

    def register_finish(self) -> Passkey:
        auth_data = self.server.register_complete(
            self.pop_state(),
            json.loads(self.request.body),
        )
        if cred := auth_data.credential_data:
            return Passkey.objects.create(
                user=self.user,
                credential_id=base64url_encode(cred.credential_id),
                credential_data=cred,
            )
        raise Exception("No credential data")

    def auth_start(self) -> dict:
        options, state = self.server.authenticate_begin()
        self.set_state(state)
        return dict(options.public_key)

    def auth_finish(self) -> Passkey:
        data = json.loads(self.request.body)
        user_id = pk_value(base64url_decode(data["response"]["userHandle"]))
        passkey = Passkey.objects.select_related("user").get(
            user_id=user_id,
            credential_id=data["id"],
        )
        self.server.authenticate_complete(
            self.pop_state(),
            [AttestedCredentialData(passkey.credential_data)],
            data,
        )
        passkey.last_used = timezone.now()
        passkey.save(update_fields=["last_used"])
        auth.login(self.request, passkey.user)
        return passkey
