"""
Views for the user API.
"""

import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework import generics, permissions, status, views
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema, OpenApiParameter

from .serializers import (
    UserSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    RequestPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
)

from core.utils import Util


class RegisterView(generics.CreateAPIView):
    """Create a new user in the system and send email verify otp with end date."""
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        """Override create function to add email validation method with otp"""
        super(RegisterView, self).create(
            request, *args, **kwargs)

        # create otp for email verification
        user = get_user_model().objects.get(email=request.data['email'])
        user.is_verified = False
        user.otp_token()
        user.save()

        # Create and send email
        email_body = f'Hi {user.name} thank you for joining my app, you just need to confirm that we got your ' \
                     f'email right \n Your verification code: {user.otp} \n this code will expire in 3 days ' \
                     f'\n Welcome and thanks'
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Please confirm your email'}

        Util.send_email(data)

        return Response({'email': 'user register completed, and email has been sent to you to actvate your account'}, status=status.HTTP_201_CREATED)


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
                name='email', description='User ID', required=True, type=str),
            OpenApiParameter(
                name='otp', description='Email verify otp', required=True, type=int),

        ]
    )
    def get(self, request):
        """
        Retrieve token from request and verify user email if valied.
        jwt token payload:
            'token_type': 'access',
            'exp': 1669013732,
            'iat': 1669013432,
            'jti': 'b934c5640c43407ca2b2dcfae5b80fa2',
            'user_id': 18
        """
        try:

            otp = int(request.GET.get('otp'))
            email = request.data['email']

            if not get_user_model().objects.filter(email=email).exists():
                return Response({'error': 'user not exist'}, status=status.HTTP_400_BAD_REQUEST)

            user = get_user_model().objects.get(email=email)

            if user.is_verified:
                return Response({'error': 'user is already verify'}, status=status.HTTP_400_BAD_REQUEST)

            if user.otp != otp:
                return Response({'error': 'wrong otp'}, status=status.HTTP_400_BAD_REQUEST)

            if not (user.otp_end_date - datetime.datetime.now(datetime.timezone.utc)).days > 0:
                return Response({'error': 'otp expired'}, status=status.HTTP_400_BAD_REQUEST)

            if not user.is_verified:
                user.is_verified = True
                user.otp = None
                user.otp_end_date = None
                user.save()

            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f'error ............ {e}')


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
            user.otp_token()
            user.save()

        email_body = f'hello {user.name}, \n Use the code below to reset your password \n {user.otp} \n code will expire in 3 days'

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
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({
            'success': True,
            'message': 'Password reset success'
        },
            status=status.HTTP_200_OK
        )
