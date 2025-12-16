from fastapi import FastAPI
from sqlmodel import Session, select
from sqlmodel import delete
from db_manager import DBManager
from hashing.sha256_hashing import PasswordSHA256Hasher
from hashing.bcrypt_hashing import PasswordBcryptHasher
from hashing.argon2id_hashing import PasswordArgon2idHasher
from models.users import User

app = FastAPI()

@app.get("/")
def home():
    return {"message": "FastAPI project running!"}


