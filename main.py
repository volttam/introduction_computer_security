
from fastapi import Depends, FastAPI, HTTPException, status
from models.api_requests.api_requests import *
from sqlmodel import Session, select
from models.orm.users import User
from loggers.logger import logger
from loggers.attempts_logger import log_login_attempt
from api_gateway import *
import time
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from functools import wraps
from starlette.middleware.base import BaseHTTPMiddleware
from context import ctx

app = FastAPI()


@app.get("/")
def read_root():
    return {"message": "Hello World"}


def log_login_attempt_decorator():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            payload = kwargs.get("payload")
            username = getattr(payload, "username", None)
            try:
                response = func(*args, **kwargs)
                latency_ms = (time.time() - start_time) * 1000
                result = response.get("message")
                log_login_attempt(
                    username=username,
                    protection_flags=ctx.get_protection_flags,
                    result=result,
                    latency_ms=latency_ms,
                )
                return response
            except HTTPException as exc:
                latency_ms = (time.time() - start_time) * 1000
                log_login_attempt(
                    username=username,
                    protection_flags=ctx.get_protection_flags,
                    result=str(exc.detail),
                    latency_ms=latency_ms,
                )
                raise exc
        return wrapper
    return decorator

@app.post("/login")
@log_login_attempt_decorator()
def login_user(payload: LoginRequest, session: Session = Depends(ctx.db_manager.get_session), request: Request = None):
    captcha_token = request.headers.get("X-CAPTCHA-TOKEN") if request else None
    ctx.api_gateway.activate_gateway(payload=payload,captcha_token=captcha_token)
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    password = ctx.pepper_manager.apply_pepper_if_activated(payload.password)
    stored_hash = ctx.user_handler.get_stored_password_hash(user, ctx.settings.hash_mode)
    if not ctx.password_hasher_selector.get_password_hasher(ctx.settings.hash_mode).verify_password(password, stored_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if ctx.settings.totp_enabled:
        return {"message": "Credentials are valid but totp code is required"}
    return {"message": "Login successful"}

@app.get("/admin/get_captcha_token")
def get_captcha_token(group_seed: str):
    if group_seed != ctx.settings.seed_group:
        raise HTTPException(status_code=403)
    return {
        "captcha_token": ctx.captcha_manager.issue_token()
    }

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(
    payload: RegisterRequest,
    session: Session = Depends(ctx.db_manager.get_session),
):
    existing_user = session.exec(
        select(User).where(
            (User.username == payload.username)
            | (User.email == payload.email)
        )
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )
    sha256_result = ctx.password_hasher_selector.sha256_hasher.hash_password(payload.password)
    sha256_stored = f"{sha256_result.salt}${sha256_result.hash}"
    bcrypt_hash = ctx.password_hasher_selector.bcrypt_hasher.hash_password(payload.password)
    argon2id_hash = ctx.password_hasher_selector.argon2id_hasher.hash_password(payload.password)
    totp_secret = ctx.totp_manager.generate_secret()
    user = User(
        username=payload.username,
        email=payload.email,
        sha_256_salt_password_hash=sha256_stored,
        bcrypt_password_hash=bcrypt_hash,
        argon2id_password_hash=argon2id_hash,
        totp_secret=totp_secret
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return {
        "detail": "User registered successfully",
        "user_id": user.id,
    }

@app.post("/login_totp")
#@log_login_attempt_decorator()
def login_totp(payload: TOTPLoginRequest, session: Session = Depends(ctx.db_manager.get_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    verification = ctx.totp_manager.verify_code(
        secret=user.totp_secret,
        code=payload.totp_code,
        last_verified_at=user.totp_last_verified_at,
    )
    if not verification.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=verification.reason,
        )
    if verification.timecode is not None:
        user.totp_last_verified_at = ctx.totp_manager.timestamp_from_timecode(verification.timecode)
        session.add(user)
        session.commit()
    return {"message": "Login successful", "totp": "verified"}

