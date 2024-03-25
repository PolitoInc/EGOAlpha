from ego.models import *
import pyotp
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status
import pyotp
import qrcode
from io import BytesIO
import base64


# auth_app/services.py
def getUserService(request):
    user = request.user
    print(f"User in getUserService: {user}")  # This should also print the user's username
    if user.is_authenticated:
        try:
            user_profile = UserProfile.objects.get(user=user)  # Retrieve the UserProfile object based on the user field
            return user_profile
        except UserProfile.DoesNotExist:
            return None
    else:
        return None

def getQRCodeService(user_profile):
    otp_base32 = pyotp.random_base32()
    otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
        name=user_profile.user.username.lower(), issuer_name="127.0.0.1"
    )

    user_profile.otp_base32 = otp_base32
    user_profile.save()

    # Print out the saved otp_base32 to confirm it's saved correctly
    print(user_profile.otp_base32)

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otp_auth_url)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered, format="JPEG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return img_str


# auth_app/services.py
def getOTPValidityService(user, otp):
    field_names = [field.name for field in user._meta.get_fields()]
    if user.otp_base32 is None:
        return False  # Return False if otp_base32 is None
    totp = pyotp.TOTP(user.otp_base32)
    if not totp.verify(otp):
        print('false',otp)
        return False
    print('true')
    user.logged_in = True
    user.save()
    return True

#auth_app/services.py


# auth_app/services.py
from django.contrib.auth import login

def getLoginUserService(request, otp_code):
    username = request.POST.get('username', None)
    password = request.POST.get('password', None)
    user = authenticate(request, username=username, password=password)
    if user is not None:
        user_profile = UserProfile.objects.get(user=user)
        print(user_profile.__dict__) 
        check = getOTPValidityService(user_profile, otp_code)
        if check:
            login(request, user)  # Log in the user
            return True
    return None


def login_user_service(request, username, password):
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return True
    else:
        return False