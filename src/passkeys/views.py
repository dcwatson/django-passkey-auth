import json

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.generic import View
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialUserEntity,
)

from .models import Passkey
from .utils import base64url_decode, base64url_encode, get_server, pk_bytes, pk_value


class PasskeyView(View):
    server: Fido2Server

    @property
    def session_key(self):
        return getattr(settings, "PASSKEY_SESSION_KEY", "_passkey")

    def set_state(self, state):
        self.request.session[self.session_key] = state

    def pop_state(self):
        return self.request.session.pop(self.session_key, None)

    def dispatch(self, request: HttpRequest, *args, **kwargs):
        self.server = get_server(request)
        response = super().dispatch(request, *args, **kwargs)
        if isinstance(response, dict):
            return JsonResponse(response, json_dumps_params={"indent": 4})
        return response


class PasskeyRegister(LoginRequiredMixin, PasskeyView):
    def get(self, request):
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(
                id=pk_bytes(request.user.pk),
                name=request.user.get_username(),
                display_name=request.user.get_full_name(),
            )
        )
        self.set_state(state)
        return dict(options.public_key)

    def post(self, request):
        auth_data = self.server.register_complete(
            self.pop_state(),
            json.loads(request.body),
        )

        if cred := auth_data.credential_data:
            Passkey.objects.create(
                user=request.user,
                credential_id=base64url_encode(cred.credential_id),
                credential_data=cred,
            )

        return {"success": True}


class PasskeyLogin(PasskeyView):
    def get(self, request):
        options, state = self.server.authenticate_begin()
        self.set_state(state)
        return dict(options.public_key)

    def post(self, request):
        auth = json.loads(request.body)
        user_id = pk_value(
            get_user_model(),
            base64url_decode(auth["response"]["userHandle"]),
        )
        passkey = Passkey.objects.select_related("user").get(
            user_id=user_id,
            credential_id=auth["id"],
        )
        self.server.authenticate_complete(
            self.pop_state(),
            [AttestedCredentialData(passkey.credential_data)],
            auth,
        )
        passkey.last_used = timezone.now()
        passkey.save(update_fields=["last_used"])
        login(request, passkey.user)
        return {"success": True}
