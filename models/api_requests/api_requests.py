from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str

class TOTPLoginRequest(BaseModel):
    username: str
    totp_code: str