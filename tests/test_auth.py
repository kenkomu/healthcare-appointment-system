import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import os
import sys
from pathlib import Path

# Add project root to Python path - more robust approach
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

print(f"Project root: {project_root}")
print(f"Python path: {sys.path}")
print(f"Files in project root: {list(project_root.glob('*.py'))}")

# Set testing environment variable
os.environ["TESTING"] = "1"

# Ensure we're using SQLite for tests
os.environ["TEST_DATABASE_URL"] = "sqlite:///./test.db"

try:
    from app.main import app
    print("Successfully imported app from app.main")
except ImportError as e:
    print(f"Failed to import app.main: {e}")
    # Try alternative import paths
    try:
        from main import app
        print("Successfully imported app from main")
    except ImportError as e2:
        print(f"Failed to import main: {e2}")
        raise

from app.core.database import get_db, Base
from app.core.security import UserRole

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function")
def test_db():
    # Create tables
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client

# Test data
test_user_data = {
    "email": "test@example.com",
    "password": "TestPassword123",
    "role": "patient",
    "first_name": "Test",
    "last_name": "User"
}

test_login_data = {
    "email": "test@example.com",
    "password": "TestPassword123"
}

class TestAuthentication:
    
    def test_register_user(self, client, test_db):
        """Test user registration."""
        response = client.post("/api/v1/auth/register", json=test_user_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["email"] == test_user_data["email"]
        assert data["role"] == test_user_data["role"]
        assert "password" not in data
    
    def test_register_duplicate_email(self, client, test_db):
        """Test registration with duplicate email."""
        # Register first user
        client.post("/api/v1/auth/register", json=test_user_data)
        
        # Try to register with same email
        response = client.post("/api/v1/auth/register", json=test_user_data)
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]
    
    def test_register_invalid_password(self, client, test_db):
        """Test registration with invalid password."""
        invalid_data = test_user_data.copy()
        invalid_data["password"] = "weak"
        
        response = client.post("/api/v1/auth/register", json=invalid_data)
        assert response.status_code == 422
    
    def test_login_success(self, client, test_db):
        """Test successful login."""
        # Register user first
        client.post("/api/v1/auth/register", json=test_user_data)
        
        # Login
        response = client.post("/api/v1/auth/login", json=test_login_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
    
    def test_login_invalid_credentials(self, client, test_db):
        """Test login with invalid credentials."""
        invalid_login = {
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }
        
        response = client.post("/api/v1/auth/login", json=invalid_login)
        assert response.status_code == 401
    
    def test_login_wrong_password(self, client, test_db):
        """Test login with wrong password."""
        # Register user first
        client.post("/api/v1/auth/register", json=test_user_data)
        
        # Login with wrong password
        wrong_login = test_login_data.copy()
        wrong_login["password"] = "wrongpassword"
        
        response = client.post("/api/v1/auth/login", json=wrong_login)
        assert response.status_code == 401
    
    def test_get_current_user(self, client, test_db):
        """Test getting current user info."""
        # Register and login
        client.post("/api/v1/auth/register", json=test_user_data)
        login_response = client.post("/api/v1/auth/login", json=test_login_data)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get current user
        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert data["email"] == test_user_data["email"]
    
    def test_get_current_user_invalid_token(self, client, test_db):
        """Test get current user with invalid token."""
        headers = {"Authorization": "Bearer invalid_token"}
        
        response = client.get("/api/v1/auth/me", headers=headers)
        assert response.status_code == 401
    
    def test_refresh_token(self, client, test_db):
        """Test token refresh."""
        # Register and login
        client.post("/api/v1/auth/register", json=test_user_data)
        login_response = client.post("/api/v1/auth/login", json=test_login_data)
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Refresh token
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    def test_refresh_invalid_token(self, client, test_db):
        """Test refresh with invalid token."""
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )
        assert response.status_code == 401
    
    def test_logout(self, client, test_db):
        """Test user logout."""
        # Register and login
        client.post("/api/v1/auth/register", json=test_user_data)
        login_response = client.post("/api/v1/auth/login", json=test_login_data)
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Logout
        response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200
    
    def test_change_password(self, client, test_db):
        """Test password change."""
        # Register and login
        client.post("/api/v1/auth/register", json=test_user_data)
        login_response = client.post("/api/v1/auth/login", json=test_login_data)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Change password
        password_data = {
            "current_password": "TestPassword123",
            "new_password": "NewPassword123"
        }
        
        response = client.post(
            "/api/v1/auth/change-password",
            json=password_data,
            headers=headers
        )
        assert response.status_code == 200
    
    def test_change_password_wrong_current(self, client, test_db):
        """Test password change with wrong current password."""
        # Register and login
        client.post("/api/v1/auth/register", json=test_user_data)
        login_response = client.post("/api/v1/auth/login", json=test_login_data)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Change password with wrong current password
        password_data = {
            "current_password": "WrongPassword",
            "new_password": "NewPassword123"
        }
        
        response = client.post(
            "/api/v1/auth/change-password",
            json=password_data,
            headers=headers
        )
        assert response.status_code == 400
    
    def test_verify_token(self, client, test_db):
        """Test token verification."""
        # Register and login
        client.post("/api/v1/auth/register", json=test_user_data)
        login_response = client.post("/api/v1/auth/login", json=test_login_data)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Verify token
        response = client.post("/api/v1/auth/verify-token", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert data["valid"] == True
        assert "user_id" in data

if __name__ == "__main__":
    pytest.main([__file__])