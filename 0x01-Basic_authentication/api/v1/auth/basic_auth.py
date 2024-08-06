#!/usr/bin/env python3
""" Module of BasicAuth
"""

from typing import TypeVar
from .auth import Auth
import base64
from models.user import User


class BasicAuth(Auth):
    """ "BasicAuth Class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """extract_base64_authorization_header method"""
        if isinstance(authorization_header, str) and \
            authorization_header.startswith(
            "Basic "
        ):
            return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """decode_base64_authorization_header"""
        if isinstance(base64_authorization_header, str):
            try:
                decoded_bytes = base64.b64decode(base64_authorization_header)
                decoded_string = decoded_bytes.decode("utf-8")
                return decoded_string
            except (base64.binascii.Error, UnicodeDecodeError) as error:
                return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """extract_user_credentials"""
        if isinstance(decoded_base64_authorization_header, str):
            index = decoded_base64_authorization_header.find(":")
            if index != -1:
                return (
                    decoded_base64_authorization_header[:index],
                    decoded_base64_authorization_header[index + 1:],
                )
        return (None, None)

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """user_object_from_credentials"""
        if user_email is None or user_pwd is None:
            return None
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None
        try:
            user = User.search({"email": user_email})
            if user:
                if user[0].is_valid_password(user_pwd):
                    return user[0]
            else:
                return None
        except Exception:
            return None
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """current_user"""
        auth_header = self.authorization_header(request)
        b64_auth_header = self.extract_base64_authorization_header(auth_header)
        decoded_auth_header = self.decode_base64_authorization_header(
                                                b64_auth_header)
        user, pwd = self.extract_user_credentials(decoded_auth_header)
        return self.user_object_from_credentials(user, pwd)
