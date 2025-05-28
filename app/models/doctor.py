from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from ..core.database import Base

class Doctor(Base):
    __tablename__ = "doctors"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    
    # Personal information
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    specialization = Column(String(100), nullable=False)
    license_number = Column(String(50), nullable=False, unique=True)
    
    # Professional information
    years_of_experience = Column(Integer, nullable=True)
    qualification = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)
    
    # Contact information
    phone_number = Column(String(20), nullable=True)
    office_address = Column(String(255), nullable=True)
    
    # Availability
    is_available = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="doctor")
    appointments = relationship("Appointment", back_populates="doctor")
    
    def __repr__(self):
        return f"<Doctor(id={self.id}, name='{self.first_name} {self.last_name}', specialization='{self.specialization}')>"
