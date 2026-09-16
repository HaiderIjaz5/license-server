from sqlalchemy import Column, String, Boolean, DateTime
from database import Base
import datetime

class Token(Base):
    __tablename__ = "tokens"
    
    id = Column(String, primary_key=True, index=True)
    token_string = Column(String, unique=True, index=True)
    duration_days = Column(String)  # '7', '30', '365'
    expiry_date = Column(DateTime, nullable=True)  # Set on first use
    hardware_id = Column(String, nullable=True)  # Bound on first use
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
