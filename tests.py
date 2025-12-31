from fastapi.testclient import TestClient
from main import app
from sqlmodel import Session, select, delete
from models.orm.users import User
from db_manager import DBManager
from context import ctx

client = TestClient(app)


def test_login_weak_user_success():
    """
    Login should succeed with the correct password.
    """
    response = client.post(
        "/login",
        json={
            "username": "weak_password_user_1",
            "password": "123456",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Login successful"}

def test_login_weak_user_wrong_password():
    """
    Login should fail with an incorrect password.
    """
    response = client.post(
        "/login",
        json={
            "username": "weak_password_user_1",
            "password": "666666",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_delete_all_users():
    """
    Drop the users table and confirm it no longer exists.
    """
    db = DBManager()

    session_gen = db.get_session()
    session = next(session_gen)

    try:
        # Drop the table
        User.__table__.drop(bind=session.get_bind())

        # Verify table is gone
        from sqlalchemy import inspect
        inspector = inspect(session.get_bind())

        assert "user" not in inspector.get_table_names()

    finally:
        session.close()




def test_login_totp_success():
    """
    Successful TOTP login with a freshly generated code.
    """
    username = "weak_password_user_1"
    password = "123456"
    with ctx.db_manager.get_session() as session:
        user = session.exec(select(User).where(User.username == "weak_password_user_1")).first()
        assert user is not None
        current_code = ctx.totp_manager.generate_current_code(user.totp_secret)
    response = client.post(
        "/login_totp",
        json={
            "username": username,
            "password": password,
            "totp_code": current_code,
        },
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Login successful", "totp": "verified"}

"""
def test_register_user_success():
    payload = {
        "username": "test_register_user_1",
        "email": "test_register_user_1@example.com",
        "password": "TestPassword123",
    }
    response = client.post("/register", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == "User registered successfully"
    assert "user_id" in response.json()
    db = DBManager()
    with next(db.get_session()) as session:
        user = session.exec(
            select(User).where(User.username == payload["username"])
        ).first()
        assert user is not None
        assert user.email == payload["email"]
        assert user.sha_256_salt_password_hash is not None
        assert "$" in user.sha_256_salt_password_hash
        assert user.bcrypt_password_hash.startswith("$2")
        assert user.argon2id_password_hash.startswith("$argon2id$")

"""