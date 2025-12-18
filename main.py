
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from models.api_requests.api_requests import LoginRequest, RegisterRequest
from sqlmodel import Session, select
from models.orm.users import User
from db_manager import DBManager
from context import Context
from logger import logger


app = FastAPI()
ctx = Context()

@app.get("/")
def home():
    return {"message": "FastAPI project running!"}


@app.post("/login")
def login_user(payload: LoginRequest, session: Session = Depends(ctx.db_manager.get_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    logger.info(f"hashing mechanism is {ctx.settings.hashing_mechanism}")
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    stored_hash = ctx.user_handler.get_stored_password_hash(user, ctx.settings.hashing_mechanism)
    if not ctx.password_hasher_selector.get_password_hasher(ctx.settings.hashing_mechanism).verify_password(payload.password, stored_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return {"message": "Login successful"}

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(
    payload: RegisterRequest,
    session: Session = Depends(ctx.db_manager.get_session),
):
    # 1️⃣ Check username or email already exists
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
    user = User(
        username=payload.username,
        email=payload.email,
        sha_256_salt_password_hash=sha256_stored,
        bcrypt_password_hash=bcrypt_hash,
        argon2id_password_hash=argon2id_hash,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return {
        "message": "User registered successfully",
        "user_id": user.id,
    }