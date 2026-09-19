import os
import uuid
import datetime
import secrets
from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from database import engine, get_db, Base
import models
import schemas

Base.metadata.create_all(bind=engine)

app = FastAPI(title="License Manager Server")

# Create templates directory if not exists
os.makedirs("templates", exist_ok=True)
templates = Jinja2Templates(directory="templates")

security = HTTPBasic()

def get_current_admin(credentials: HTTPBasicCredentials = Depends(security)):
    import secrets
    correct_username = secrets.compare_digest(credentials.username, os.getenv("ADMIN_USERNAME", "admin"))
    correct_password = secrets.compare_digest(credentials.password, os.getenv("ADMIN_PASSWORD", "password123"))
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/health")
def health_check():
    return {"status": "OK"}

@app.get("/", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db), admin: str = Depends(get_current_admin)):
    tokens = db.query(models.Token).order_by(models.Token.created_at.desc()).all()
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request, "tokens": tokens})

@app.post("/generate")
def generate_token_form(duration: str = Form(...), db: Session = Depends(get_db), admin: str = Depends(get_current_admin)):
    token_str = "CS-" + secrets.token_hex(12).upper()
    new_token = models.Token(
        id=str(uuid.uuid4()),
        token_string=token_str,
        duration_days=duration
    )
    db.add(new_token)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/revoke/{token_id}")
def revoke_token(token_id: str, db: Session = Depends(get_db), admin: str = Depends(get_current_admin)):
    token = db.query(models.Token).filter(models.Token.id == token_id).first()
    if token:
        token.is_active = False
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/reactivate/{token_id}")
def reactivate_token(token_id: str, db: Session = Depends(get_db), admin: str = Depends(get_current_admin)):
    token = db.query(models.Token).filter(models.Token.id == token_id).first()
    if token:
        token.is_active = True
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/delete/{token_id}")
def delete_token(token_id: str, db: Session = Depends(get_db), admin: str = Depends(get_current_admin)):
    token = db.query(models.Token).filter(models.Token.id == token_id).first()
    if token:
        db.delete(token)
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/api/validate", response_model=schemas.TokenResponse)
def validate_token(data: schemas.TokenValidate, db: Session = Depends(get_db)):
    token = db.query(models.Token).filter(models.Token.token_string == data.token_string).first()
    
    if not token:
        raise HTTPException(status_code=404, detail="Invalid token")
        
    if not token.is_active:
        raise HTTPException(status_code=403, detail="Token has been revoked")
        
    # Bind hardware ID if first time
    if not token.hardware_id:
        token.hardware_id = data.hardware_id
        # Calculate expiry date
        days = int(token.duration_days)
        token.expiry_date = datetime.datetime.utcnow() + datetime.timedelta(days=days)
        db.commit()
        
    # Verify hardware ID
    if token.hardware_id != data.hardware_id:
        raise HTTPException(status_code=403, detail="Token is bound to another device")
        
    # Check expiry
    if token.expiry_date and datetime.datetime.utcnow() > token.expiry_date:
        token.is_active = False
        db.commit()
        raise HTTPException(status_code=403, detail="Token has expired")
        
    return token

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
