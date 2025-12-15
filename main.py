from fastapi import FastAPI
from sqlmodel import Session, select
from sqlmodel import delete
from db_manager import DBManager
from hashing.sha256_hashing import PasswordSHA256Hasher
from models.users import User

app = FastAPI()

@app.get("/")
def home():
    return {"message": "FastAPI project running!"}



if __name__ == "__main__":
    x=1