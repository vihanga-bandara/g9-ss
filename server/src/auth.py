"""Account routes and the require_auth decorator."""

from collections.abc import Callable
from functools import wraps

from flask import Blueprint, g, jsonify, request

from auth_service import AuthService
from service_errors import ServiceError


def make_require_auth(auth_service: AuthService) -> Callable:
    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise ServiceError("Missing or invalid Authorization header", 401)
            g.user = auth_service.validate_token(auth.split(" ", 1)[1].strip())
            return f(*args, **kwargs)

        return wrapper

    return require_auth


def create_blueprint(auth_service: AuthService) -> Blueprint:
    bp = Blueprint("auth", __name__)

    @bp.post("/api/create-user")
    def create_user():
        return jsonify(
            auth_service.create_user(request.get_json(silent=True) or {})
        ), 201

    @bp.post("/api/login")
    def login():
        return jsonify(auth_service.login(request.get_json(silent=True) or {})), 200

    return bp
