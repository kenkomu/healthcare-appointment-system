from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
import redis
from .config import settings

# PostgreSQL database setup with appropriate connection pool settings
engine = create_engine(
    settings.get_database_url,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,  # Recycle connections after 30 minutes
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Redis setup - mock for testing
if settings.TESTING:
    # Use a simple dict-based mock for Redis in tests
    class RedisMock:
        def __init__(self):
            self.data = {}
        
        def setex(self, key, time, value):
            self.data[key] = value
            return True
        
        def get(self, key):
            return self.data.get(key)
        
        def delete(self, key):
            if key in self.data:
                del self.data[key]
            return 1
        
        def incr(self, key):
            if key in self.data:
                try:
                    self.data[key] = str(int(self.data[key]) + 1)
                except:
                    self.data[key] = "1"
            else:
                self.data[key] = "1"
            return int(self.data[key])
    
    redis_client = RedisMock()
else:
    # Real Redis client for production
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

# Database dependency
def get_db() -> Generator[Session, None, None]:
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Redis dependency
def get_redis():
    """Get Redis client."""
    return redis_client

# Database initialization
def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)