from fastapi.testclient import TestClient
from server.main import app
from sqlmodel import select
from server.models.orm.users import User
from server.context import ctx

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



def test_register_delete_user_endpoint():
    username = "test_register_user_1"
    payload = {
        "username": username,
        "email": "delete_me_user@example.com",
        "password": "DeleteMePassword123",
    }
    register_response = client.post("/register", json=payload)
    assert register_response.status_code == 201
    delete_response = client.delete(f"/users/{username}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"detail": "User deleted successfully"}
    session_gen = ctx.db_manager.get_session()
    session = next(session_gen)
    user = session.exec(select(User).where(User.username == username)).first()
    assert user is None