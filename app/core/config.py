from pydantic_settings import BaseSettings
from typing import Optional, List
import os
from pathlib import Path

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Healthcare Appointment System"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    TESTING: bool = os.getenv("TESTING", "0").lower() in ("1", "true", "t", "yes", "y")
    
    # Database - PostgreSQL only configuration
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://ken:Kikis_216@localhost:5432/healthcare_db"
    )
    TEST_DATABASE_URL: str = os.getenv(
        "TEST_DATABASE_URL",
        "postgresql://ken:Kikis_216@localhost:5432/healthcare_test_db"
    )
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # OAuth 2.0 Settings
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    OAUTH_REDIRECT_URI: str = "http://localhost:8000/auth/callback"
    
    # Redis (for caching and sessions)
    REDIS_URL: str = "redis://localhost:6379"
    
    # Email settings (for notifications)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080", "http://testserver"]
    
    @property
    def get_database_url(self):
        """Return the appropriate database URL based on if we're testing"""
        if self.TESTING:
            return self.TEST_DATABASE_URL
        return self.DATABASE_URL
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create settings instance
settings = Settings()