
from fastapi import Depends, FastAPI, HTTPException, status
from models.api_requests.api_requests import *
from sqlmodel import Session, select
from models.orm.users import User
from loggers.logger import logger
from dependecies import *


app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello World"}


@app.post("/login", dependencies=[Depends(rate_limit_login_dependency), Depends(user_lockout_dependency), Depends(captcha_dependency)])
def login_user(payload: LoginRequest, session: Session = Depends(ctx.db_manager.get_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    stored_hash = ctx.user_handler.get_stored_password_hash(user, ctx.settings.hash_mode)
    if not ctx.password_hasher_selector.get_password_hasher(ctx.settings.hash_mode).verify_password(payload.password, stored_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
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

@app.post("/login_totp", dependencies=[Depends(rate_limit_login_dependency), Depends(user_lockout_dependency), Depends(captcha_dependency)])
def login_totp(payload: TOTPLoginRequest, session: Session = Depends(ctx.db_manager.get_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    stored_hash = ctx.user_handler.get_stored_password_hash(user, ctx.settings.hash_mode)
    if not ctx.password_hasher_selector.get_password_hasher(ctx.settings.hash_mode).verify_password(payload.password, stored_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
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

