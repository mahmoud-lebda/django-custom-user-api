"""
Views for the user API.
"""
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import (
    get_user_model,
)

from rest_framework import generics, permissions, status, views
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

import jwt

from .serializers import (
    UserSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
)
from .utils import Util
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes


class RegisterView(generics.CreateAPIView):
    """Create a new user in the system."""
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):

            """Ovride create function to add email validation method"""
            response_data = super(RegisterView, self).create(
                request, *args, **kwargs)
            user = get_user_model().objects.get(email=request.data['email'])
            token = str(RefreshToken.for_user(user).access_token)

            current_site = get_current_site(request).domain
            relative_link = reverse('user:email-verify')

            absurls = f'http://{current_site}{relative_link}?token={token}'
            print(f'test url ............. {absurls}')
            email_body = f'Hi {user.name} Use link to verify your email \n {absurls}'
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify yout email'}

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
            OpenApiParameter(name='token', description='Email verify token', required=True, type=str),
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
        token = request.GET.get('token')
        try:
            payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            user = get_user_model().objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            return Response({'error': 'Invaled token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.CreateAPIView):

    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

