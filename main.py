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
from logger import logger


app = FastAPI()
ctx = Context()

@app.get("/")
def home():
    return {"message": "FastAPI project running!"}


@app.post("/login")
def login_user(payload: LoginRequest, session: Session = Depends(ctx.db_manager.get_db_session)):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    stored_hash = ctx.user_handler.get_stored_password_hash(user, ctx.settings.hashing_mechanism)
    if not ctx.password_hasher_selector.get_password_hasher(ctx.settings.hashing_mechanism).verify_password(payload.password, stored_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return {"message": "Login successful"}

