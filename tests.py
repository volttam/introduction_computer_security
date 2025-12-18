from fastapi.testclient import TestClient
from main import app

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

