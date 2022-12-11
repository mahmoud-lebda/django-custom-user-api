"""
URL mappings for the user API.
"""
from django.urls import path

# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
# )

from .views import (RegisterView,
                    VerifyEmailView,
                    ManageUSer,
                    LoginAPIView,
                    PasswordTokenCheckAPI,
                    RequestPasswordResetEmail,
                    SetNewPasswordAPIView,
                    ReSendUserEmailVerifyView,
                    )


app_name = 'user'

urlpatterns = [
    path('register/', RegisterView.as_view(), name='create'),
    path('email-verify/', VerifyEmailView.as_view(), name='email-verify'),
    path('resend-email-verify/', ReSendUserEmailVerifyView.as_view(), name='resend-email-verify'),
    
    path('me/', ManageUSer.as_view(), name='me'),

    # path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('login/', LoginAPIView.as_view(), name='login'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),
         name='request-reset-email'),
    path('password-rest/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-rest'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete')

]
