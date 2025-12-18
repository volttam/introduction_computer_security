import os
from typing import Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from models.api_requests.api_requests import LoginRequest, RegisterRequest
from sqlmodel import Session, select
from models.orm.users import User
from db_manager import DBManager
from context import Context


app = FastAPI()
ctx = Context()
load_dotenv()
SupportedHashing = Literal["sha256", "bcrypt", "argon2id"]

@app.get("/")
def home():
    return {"message": "FastAPI project running!"}


@app.post("/login")
def login_user(payload: LoginRequest, session: Session = Depends(ctx.db_manager.get_db_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    mechanism = get_hashing_mechanism()
    if not _verify_password_for_user(user, payload.password, mechanism):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return {"message": "Login successful"}

def _verify_password_for_user(user: User, password: str, mechanism: SupportedHashing) -> bool:
    if mechanism == "sha256":
        return PasswordSHA256Hasher.verify_password(
            password, user.sha256_password_hash or "", user.sha256_password_salt or ""
        )
    if mechanism == "bcrypt":
        return PasswordBcryptHasher.verify_password(password, user.bcrypt_password_hash or "")
    if mechanism == "argon2id":
        return PasswordArgon2idHasher.verify_password(password, user.argon2id_password_hash or "")