from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, JsonResponse
from django.views.generic import View

from .utils import base64url_encode, get_backend, pk_bytes


class PasskeyView(View):
    def dispatch(self, request: HttpRequest, *args, **kwargs):
        try:
            self.backend = get_backend(request)
            response = super().dispatch(request, *args, **kwargs)
            if isinstance(response, dict):
                return JsonResponse(response)
            return response
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=400)


class PasskeyRegister(LoginRequiredMixin, PasskeyView):
    def get(self, request):
        return self.backend.register_start()

    def post(self, request):
        passkey = self.backend.register_finish()
        return {
            "success": True,
            "credentials": [pk.credential_id for pk in passkey.user.passkeys.all()],
        }


class PasskeyLogin(PasskeyView):
    def get(self, request):
        return self.backend.auth_start()

    def post(self, request):
        passkey = self.backend.auth_finish()
        return {
            "success": True,
            "userId": base64url_encode(pk_bytes(passkey.user.pk)),
            "credentials": [pk.credential_id for pk in passkey.user.passkeys.all()],
        }
