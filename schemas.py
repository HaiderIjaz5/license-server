from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class TokenGenerate(BaseModel):
    duration_days: str

class TokenValidate(BaseModel):
    token_string: str
    hardware_id: str

class TokenResponse(BaseModel):
    token_string: str
    duration_days: str
    expiry_date: Optional[datetime]
    hardware_id: Optional[str]
    is_active: bool
    
    class Config:
        from_attributes = True
