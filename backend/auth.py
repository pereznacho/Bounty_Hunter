from fastapi import APIRouter, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import hashlib
from pydantic import BaseModel
from backend.models import User, SessionLocal

router = APIRouter()
templates = Jinja2Templates(directory="templates")


# Dependency para obtener sesión de DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------------------
# MODELO PARA API JSON
# -------------------------------

class UserIn(BaseModel):
    username: str
    password: str


# -------------------------------
# API JSON - REGISTRO
# -------------------------------

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


# -------------------------------
# API JSON - LOGIN
# -------------------------------

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


# -------------------------------
# FORMULARIO HTML - REGISTRO (GET)
# -------------------------------

@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


# -------------------------------
# FORMULARIO HTML - REGISTRO (POST)
# -------------------------------

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


# -------------------------------
# FORMULARIO HTML - LOGIN (GET)
# -------------------------------

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# -------------------------------
# FORMULARIO HTML - LOGIN (POST)
# -------------------------------

@router.post("/login")
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    user = db.query(User).filter(
        User.username == username,
        User.password_hash == pwd_hash
    ).first()

    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Usuario o contraseña incorrectos"
        })

    request.session["user_id"] = user.id
    request.session["username"] = user.username

    return RedirectResponse(url="/dashboard", status_code=302)


# -------------------------------
# LOGOUT (opcional)
# -------------------------------

@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
