import base64
import json
import os
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import models
from django.http import JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from .fields import PublicKeyField
from .models import COSEAlgorithm, Passkey

PASSKEY_CHALLENGE_KEY = getattr(settings, "PASSKEY_CHALLENGE_KEY", "_challenge")
PASSKEY_SITE_NAME = getattr(settings, "PASSKEY_SITE_NAME", None)
PASSKEY_TIMEOUT = getattr(settings, "PASSKEY_TIMEOUT", 120000)


def pk_bytes(obj) -> bytes:
    """
    Given a primary key value, return its bytestring representation.
    """
    if isinstance(obj, int):
        return obj.to_bytes(8)
    elif isinstance(obj, uuid.UUID):
        return obj.bytes
    return str(obj).encode("utf-8")


def pk_value(model, data: bytes):
    """
    Given a model class, parse the specified bytestring into an appropriate primary key
    value for the model.
    """
    field = model._meta.pk
    if isinstance(field, models.IntegerField):
        return int.from_bytes(data)
    elif isinstance(field, models.UUIDField):
        return uuid.UUID(bytes=data)
    return data.decode("utf-8")


@method_decorator(csrf_exempt, name="dispatch")
class PasskeyRegister(LoginRequiredMixin, View):
    def get(self, request):
        origin = request.get_host().split(":")[0]
        challenge = os.urandom(32)
        request.session[PASSKEY_CHALLENGE_KEY] = (
            base64.urlsafe_b64encode(challenge).decode().rstrip("=")
        )
        return JsonResponse(
            {
                "challenge": list(challenge),
                "rp": {
                    "id": origin,
                    "name": PASSKEY_SITE_NAME or origin,
                },
                "user": {
                    "id": list(pk_bytes(request.user.pk)),
                    "name": request.user.get_username(),
                    "displayName": request.user.get_full_name(),
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": alg} for alg in COSEAlgorithm.values
                ],
                "timeout": PASSKEY_TIMEOUT,
                "attestation": "none",
                "authenticatorSelection": {
                    "residentKey": "required",
                },
            }
        )

    def post(self, request):
        passkey_data = json.loads(request.body)
        public_key_bytes = base64.b64decode(passkey_data["publicKeyDer"])
        client_data = json.loads(base64.b64decode(passkey_data["clientData"]))
        # auth_data = base64.b64decode(passkey_data["authData"])
        assert client_data["type"] == "webauthn.create"
        assert client_data["challenge"] == request.session[PASSKEY_CHALLENGE_KEY]
        del request.session[PASSKEY_CHALLENGE_KEY]
        Passkey.objects.create(
            user=request.user,
            credential_id=passkey_data["id"],
            algorithm=passkey_data["algorithm"],
            public_key=PublicKeyField.load(public_key_bytes),
        )
        return JsonResponse({"success": True})


@method_decorator(csrf_exempt, name="dispatch")
class PasskeyLogin(View):
    def get(self, request):
        challenge = os.urandom(32)
        request.session[PASSKEY_CHALLENGE_KEY] = (
            base64.urlsafe_b64encode(challenge).decode().rstrip("=")
        )
        return JsonResponse({"challenge": list(challenge)})

    def post(self, request):
        User = get_user_model()
        data = json.loads(request.body)
        user_id = pk_value(User, base64.b64decode(data["userId"]))
        client_data = base64.b64decode(data["clientData"])
        client_json = json.loads(client_data)
        assert client_json["type"] == "webauthn.get"
        assert client_json["challenge"] == request.session[PASSKEY_CHALLENGE_KEY]
        del request.session[PASSKEY_CHALLENGE_KEY]
        auth_data = base64.b64decode(data["authData"])
        sig_data = base64.b64decode(data["signature"])
        user = User.objects.get(pk=user_id)
        cred = Passkey.objects.get(user=user, credential_id=data["id"])
        cred.verify(auth_data, client_data, sig_data)
        cred.last_used = timezone.now()
        cred.save(update_fields=["last_used"])
        login(request, user)
        return JsonResponse({"success": True})
