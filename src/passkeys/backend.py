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
    def session_state_key(self):
        return getattr(settings, "PASSKEY_STATE_KEY", "_passkey_state")

    @property
    def session_current_key(self):
        return getattr(settings, "PASSKEY_CURRENT_KEY", "_passkey")

    @property
    def user(self):
        return self.request.user

    @property
    def user_bytes(self):
        return pk_bytes(self.user.pk)

    @property
    def user_id(self):
        return base64url_encode(self.user_bytes)

    @property
    def user_name(self):
        return self.user.get_username()

    @property
    def user_display(self):
        return str(self.user)

    @property
    def is_authenticated(self):
        return self.user.is_authenticated

    @property
    def credential_ids(self):
        if not self.is_authenticated:
            return []
        return [pk.credential_id for pk in Passkey.objects.filter(user=self.user)]

    @property
    def current_passkey(self) -> Passkey | None:
        if cred_id := self.get(self.session_current_key):
            return Passkey.objects.filter(user=self.user, credential_id=cred_id).first()

    def get(self, key, default=None):
        """Interface for getting data from the request session."""
        return self.request.session.get(key, default)

    def set(self, key, value):
        """Interface for setting data in the request session."""
        self.request.session[key] = value

    def pop(self, key, default=None):
        """Interface for popping data from the request session."""
        return self.request.session.pop(key, default)

    def get_info(self) -> dict:
        info: dict = {"rpId": self.server.rp.id}
        if self.is_authenticated:
            info.update(
                {
                    "userId": self.user_id,
                    "userName": self.user_name,
                    "userDisplay": self.user_display,
                    "credentials": self.credential_ids,
                    "currentCredential": self.get(self.session_current_key),
                }
            )
        return info

    def register_start(self):
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(
                id=self.user_bytes,
                name=self.user_name,
                display_name=self.user_display,
            )
        )
        self.set(self.session_state_key, state)
        return dict(options.public_key)

    def register_finish(self) -> Passkey:
        auth_data = self.server.register_complete(
            self.pop(self.session_state_key),
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
        self.set(self.session_state_key, state)
        return dict(options.public_key)

    def auth_finish(self) -> Passkey:
        data = json.loads(self.request.body)
        user_id = pk_value(base64url_decode(data["response"]["userHandle"]))
        passkey = Passkey.objects.select_related("user").get(
            user_id=user_id,
            credential_id=data["id"],
        )
        self.server.authenticate_complete(
            self.pop(self.session_state_key),
            [AttestedCredentialData(passkey.credential_data)],
            data,
        )
        passkey.last_used = timezone.now()
        passkey.save(update_fields=["last_used"])
        auth.login(self.request, passkey.user)
        self.set(self.session_current_key, passkey.credential_id)
        return passkey
