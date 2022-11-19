"""
URL mappings for the user API.
"""
from django.urls import path

from .views import RegisterView, VerifyEmail, ManageUSer


app_name = 'user'

urlpatterns = [
    path('register/', RegisterView.as_view(), name='create'),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('me/', ManageUSer.as_view(), name='me'),
]
