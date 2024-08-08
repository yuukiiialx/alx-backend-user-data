#!/usr/bin/env python3
""" Module of auth
"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """ "Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require_auth
        arg:
            @path
            @excluded_paths
        return True if path not in excluded_paths
        """
        if bool(path and excluded_paths):
            path = path + "/" if path[-1] != "/" else path
            for p in excluded_paths:
                if p.endswith("*") and path.startswith(p[:-1]):
                    return False
                if p == path:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """authorization header method
        return None or request["Authorization"]
        """
        if bool(request and "Authorization" in request.headers.keys()):
            return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """get current user
        return None
        """
        return None

    def session_cookie(self, request=None) -> str:
        """returns a cookie value from a request"""
        if request:
            return request.cookies.get(getenv("SESSION_NAME"))
