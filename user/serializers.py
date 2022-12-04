"""
Serializers for the user API View.
"""
import random
import datetime

from django.contrib.auth import (
    get_user_model,
    authenticate
)
from django.utils.translation import gettext as _
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user objects."""

    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'name']
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

    def create(self, validated_data):
        data = validated_data

        # create otp for email verify
        data['otp'] = random.randint(1000, 9999)
        data['otp_end_date'] = datetime.datetime.now() + datetime.timedelta(days=3)

        return get_user_model().objects.create_user(**data)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user


class EmailVerificationSerializer(serializers.ModelSerializer):
    otp = serializers.IntegerField()
    userid = serializers.IntegerField()

    class Meta:
        model = get_user_model()
        fields = ['otp', 'userid']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6, write_only=True)
    tokens = serializers.CharField(read_only=True)

    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credntials, try again')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')

        if not user.is_verified:
            raise AuthenticationFailed('Email  is not verified')

        return {
            'email': user.email,
            'tokens': user.tokens()
        }


class RequestPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email', '')

        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, write_only=True)
    tokens = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = smart_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                raise AuthenticationFailed('the reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return user

        except AuthenticationFailed as e:
            raise AuthenticationFailed('the reset link is invalid', 401)
        return super().validate(attrs)
