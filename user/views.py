"""
Views for the user API.
"""
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth import (
    get_user_model,
)

from rest_framework import generics, permissions, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    UserSerializer,
)
from .utils import Util


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


class VerifyEmail(generics.GenericAPIView):
    def get(self):
        pass