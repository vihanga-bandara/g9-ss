"""User registration, credentials and signed authentication tokens."""

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from service_errors import ServiceError


class AuthService:
    def __init__(self, get_engine, secret_key, token_ttl):
        self.get_engine = get_engine
        self.token_ttl = token_ttl
        self.serializer = URLSafeTimedSerializer(secret_key, salt="tatou-auth")

    def validate_token(self, token):
        try:
            data = self.serializer.loads(token, max_age=self.token_ttl)
        except SignatureExpired as exc:
            raise ServiceError("Token expired", 401) from exc
        except BadSignature as exc:
            raise ServiceError("Invalid token", 401) from exc
        return {
            "id": int(data["uid"]),
            "login": data["login"],
            "email": data.get("email"),
        }

    def create_user(self, payload):
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            raise ServiceError("email, login, and password are required", 400)

        hpw = generate_password_hash(password)

        try:
            with self.get_engine().begin() as conn:
                res = conn.execute(
                    text(
                        "INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"
                    ),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            raise ServiceError("email or login already exists", 409)
        except Exception:
            raise ServiceError("database error", 503)

        return {"id": row.id, "email": row.email, "login": row.login}

    def login(self, payload):
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            raise ServiceError("email and password are required", 400)

        try:
            with self.get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"
                    ),
                    {"email": email},
                ).first()
        except Exception:
            raise ServiceError("database error", 503)

        if not row or not check_password_hash(row.hpassword, password):
            raise ServiceError("invalid credentials", 401)

        token = self.serializer.dumps(
            {"uid": int(row.id), "login": row.login, "email": row.email}
        )
        return {"token": token, "token_type": "bearer", "expires_in": self.token_ttl}
