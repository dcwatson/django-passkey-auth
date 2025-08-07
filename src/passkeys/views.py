from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, JsonResponse
from django.views.generic import View

from .utils import get_backend


class PasskeyView(View):
    def dispatch(self, request: HttpRequest, *args, **kwargs):
        params = {"indent": 4} if settings.DEBUG else {}
        try:
            self.backend = get_backend(request)
            response = super().dispatch(request, *args, **kwargs)
            if isinstance(response, dict):
                return JsonResponse(response, json_dumps_params=params)
            return response
        except Exception as e:
            return JsonResponse(
                {"success": False, "error": str(e)},
                json_dumps_params=params,
                status=400,
            )


class PasskeyInfo(PasskeyView):
    def get(self, request):
        return self.backend.get_info()


class PasskeyRegister(LoginRequiredMixin, PasskeyView):
    def get(self, request):
        return self.backend.register_start()

    def post(self, request):
        passkey = self.backend.register_finish()
        return {
            "success": True,
            "id": passkey.credential_id,
            **self.backend.get_info(),
        }


class PasskeyLogin(PasskeyView):
    def get(self, request):
        return self.backend.auth_start()

    def post(self, request):
        passkey = self.backend.auth_finish()
        return {
            "success": True,
            "id": passkey.credential_id,
            **self.backend.get_info(),
        }
