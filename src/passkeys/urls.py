from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .views import PasskeyLogin, PasskeyRegister

urlpatterns = [
    path("register/", csrf_exempt(PasskeyRegister.as_view()), name="passkey-register"),
    path("login/", csrf_exempt(PasskeyLogin.as_view()), name="passkey-login"),
]
