from fastapi import APIRouter, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import hashlib
from pydantic import BaseModel
from backend.models import User, SessionLocal

router = APIRouter()
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserIn(BaseModel):
    username: str
    password: str

@router.post("/auth/register")
def register_api(user: UserIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Usuario ya existe")

    new_user = User(
        username=user.username,
        password_hash=hashlib.sha256(user.password.encode()).hexdigest()
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario registrado"}

@router.post("/auth/login")
def login_api(user: UserIn, db: Session = Depends(get_db)):
    pwd_hash = hashlib.sha256(user.password.encode()).hexdigest()
    existing = db.query(User).filter(
        User.username == user.username,
        User.password_hash == pwd_hash
    ).first()
    if not existing:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"token": user.username}

@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Usuario ya existe"
        })

    new_user = User(
        username=username,
        password_hash=hashlib.sha256(password.encode()).hexdigest()
    )
    db.add(new_user)
    db.commit()

    request.session["user_id"] = new_user.id
    request.session["username"] = new_user.username

    return RedirectResponse(url="/dashboard", status_code=302)