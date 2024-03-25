from django.shortcuts import redirect
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from ego.models import * 

from django.urls import reverse

class TwoFactorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if user.is_authenticated:
            user_profile, created = UserProfile.objects.get_or_create(email=user.email)
            if user_profile.two_factor_auth:
                # Enforce 2FA
                pass
        return self.get_response(request)
