"""
Views for the user API.
"""
import random
import datetime

from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


from rest_framework import generics, permissions, status, views
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken


import jwt

from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from .serializers import (
    UserSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    RequestPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
)
from .utils import Util


class RegisterView(generics.CreateAPIView):
    """Create a new user in the system and send email virefy otp with end date."""
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        """Ovride create function to add email validation method"""
        response_data = super(RegisterView, self).create(
            request, *args, **kwargs)
        user = get_user_model().objects.get(email=request.data['email'])

        email_body = f'Hi {user.name} use this code to activate account {user.otp} this code will be valid for 3 days'
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify yout email'}

        Util.send_email(data)

        return response_data


class ManageUSer(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user."""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """Retrive and return the authenticated user."""
        return self.request.user


class VerifyEmail(views.APIView):
    """Manage the user email verify."""

    serializer_class = EmailVerificationSerializer

    @extend_schema(
        # add token parameters added to the schema
        parameters=[
            OpenApiParameter(
                name='otp', description='Email verify otp', required=True, type=int),
            OpenApiParameter(
                name='userid', description='User ID', required=True, type=int),
        ]
    )
    def get(self, request):
        """
        Retrive token from request and verify user email if valied.
        jwt token payload:
            'token_type': 'access',
            'exp': 1669013732,
            'iat': 1669013432,
            'jti': 'b934c5640c43407ca2b2dcfae5b80fa2',
            'user_id': 18
        """
        otp = int(request.GET.get('otp'))
        userid = request.GET.get('userid')

        try:
            user = get_user_model().objects.get(id=userid)
            if not user:
                return Response({'error': 'user not exist'}, status=status.HTTP_400_BAD_REQUEST)

            if user.is_verified:
                return Response({'error': 'user is already verify'}, status=status.HTTP_400_BAD_REQUEST)

            if user.otp != otp:
                return Response({'error': 'wrong otp'}, status=status.HTTP_400_BAD_REQUEST)

            if not (user.otp_end_date - datetime.datetime.now(datetime.timezone.utc)).days > 0 :
                return Response({'error': 'otp expired'}, status=status.HTTP_400_BAD_REQUEST)

            if not user.is_verified:
                user.is_verified = True
                user.otp = None
                user.otp_end_date = None
                user.save()

            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f'mmmmmmmmmmmm ............ errrrrrrrrrrrrrr {e}')


class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = RequestPasswordEmailRequestSerializer

    def post(self, request):

        # serializer = self.serializer_class(data=request.data)

        email = request.data['email']

        if get_user_model().objects.filter(email=email).exists():
            user = get_user_model().objects.get(email=email)

            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            # send verify url by email
            current_site = get_current_site(request).domain
            relative_link = reverse('user:password-rest', kwargs={
                'uidb64': uidb64,
                'token': token
            })
            absurls = f'http://{current_site}{relative_link}'
            print(f'test url ............. {absurls}')
            email_body = f'hello {user.name}, \n Use link below to reset your password \n {absurls}'
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset yout password'}

            Util.send_email(data)

        return Response({'success': 'We have sent you link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({
                'success': True,
                'message': 'Credentials Valid',
                'uidb64': uidb64,
                'token': token,
            }, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class= SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({
            'success': True,
            'message': 'Password reset success'
        },
        status=status.HTTP_200_OK
        )
