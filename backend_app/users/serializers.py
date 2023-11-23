import logging
from typing import Any


import jwt
from django.conf import settings
from django.core import signing
from rest_framework import serializers
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    User
)

# from bmovez.users.api.v1.uitls import (
#     create_pbx_profile,
#     generate_email_verification_link,
#     generate_password_reset_key,
#     validate_email_verification_signature,
#     validate_otp_pin,
# )
# from bmovez.users.models import FreepbxExtentionProfile, User
# from bmovez.utils.managers import FreePbxConnector
# from bmovez.utils.tasks import send_mail_task

logger = logging.getLogger()



class UserSerializer(serializers.ModelSerializer):
    token = None

    class Meta:
        model = User
        fields = [
            "id",
            "date_joined",
            "last_login",
            "username",
            "name",
            "email",
            "password",
            "profile_picture",
            "phone_number",
          
        ]

        read_only_fields = [
            "id",
            "date_joined",
            "last_login",
        ]
        extra_kwargs = {"password": {"write_only": True}}

    def generate_auth_token(self, user: User) -> None:
        """Generate authentication token."""
        refresh_token = RefreshToken.for_user(user)
        claims = {"sub": str(user.id), "info": {"email": user.email}}
        self.token = {
            "backend": str(refresh_token.access_token),
        }
        return self.token

    def create(self, validated_data: dict[str, Any]) -> User:
        """create user."""
        user = super().create(validated_data)
        user.set_password(validated_data["password"])
        # NOTE (change to back to False when a working ESP is procured )
        user.is_active = True
        user.save()
         # NOTE (Move this to a celery task)
        self.generate_auth_token(user)

        request: Request = self.context["request"]

        return user

    def update(self, instance: User, validated_data: dict[str, Any]) -> User:
        """Update user."""
        user = super().update(instance, validated_data)

        if "password" in validated_data.keys():
            user.set_password(validated_data["password"])
            user.save(update_fields=["password"])
            self.generate_auth_token(user)
        return user


    def validate_username(self, value: str) -> str:
        """check that username is unique"""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exits")
        return value

    def validate_phone_number(self, value: str) -> str:
        """Check that phone number is unique"""
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError(
                "A user with this phone number already exits"
            )
        return value

    def validate_email(self, value: str) -> str:
        """Check that email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "A user with this email address already exits"
            )
        return value

    def to_representation(self, instance: User):
       
        data = {**super().to_representation(instance)}
        if self.token:
            data.update({"auth_token": self.token})
        return data
    


class SignInSerializer(serializers.Serializer):
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> User:
        super().validate(attrs)
        user = User.objects.filter(username=attrs["username"], is_active=True).first()

        if user and user.check_password(attrs["password"]):
            return user

        raise serializers.ValidationError(
            "No active account found with the given credentials"
        )

    def to_representation(self, instance: User) -> dict[str, Any]:
        user_serializer = UserSerializer(instance=instance)
        user_serializer.generate_auth_token(instance)
        return user_serializer.to_representation(instance)


class OTPCreationSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    password_reset_key = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        super().validate(attrs)

        # unsign password_reset_key
        try:
            signer = signing.TimestampSigner()
            data = signer.unsign_object(attrs["password_reset_key"])
            user = User.objects.filter(
                email=attrs["email"], password_reset_key=data["key"]
            ).first()
        except KeyError as error:
            logger.error(
                "bmoves::users::api::v1::serializers::ResetPasswordSerializer:: Keyerror occured.",
                extra={"details": str(error)},
            )
        else:
            if user:
                user.password_reset_key = None
                user.set_password(attrs["new_password"])
                user.save(update_fields=["password", "password_reset_key"])
                return {}
        raise serializers.ValidationError(
            "An error occured in the process please retry."
        )


