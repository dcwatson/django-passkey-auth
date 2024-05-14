from django.urls import path

from .views import PasskeyLogin, PasskeyRegister

urlpatterns = [
    path("register/", PasskeyRegister.as_view(), name="passkey-register"),
    path("login/", PasskeyLogin.as_view(), name="passkey-login"),
]
