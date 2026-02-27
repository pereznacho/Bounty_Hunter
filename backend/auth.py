from fastapi import APIRouter, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel
from backend.models import User
from backend.database import get_db
from backend.constants import VALID_THEMES

# Cookie used for theme on public pages (login/register) and after logout
BOUNTY_THEME_COOKIE = "bounty_theme"
BOUNTY_THEME_COOKIE_MAX_AGE = 365 * 24 * 60 * 60  # 1 year

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# -------------------------------
# FUNCION PARA OBTENER USUARIO LOGUEADO (usa la misma get_db que main para una sola sesión/BD)
# -------------------------------
def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Usuario no autenticado")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return user

# -------------------------------
# MODELO Pydantic PARA API JSON
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
        password_hash=generate_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario registrado"}

# -------------------------------
# API JSON - LOGIN
# -------------------------------
@router.post("/auth/login")
def login_api(user: UserIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if not existing or not check_password_hash(existing.password_hash, user.password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    return {"token": user.username}

def _theme_for_request(request: Request, db: Session) -> str:
    user_id = request.session.get("user_id")
    if not user_id:
        return "default"
    user = db.query(User).filter(User.id == user_id).first()
    return (getattr(user, "theme", None) or "default").strip() or "default"


def theme_for_public(request: Request, db: Session) -> str:
    """Theme for public pages (login/register): session user theme if logged in, else cookie."""
    user_id = request.session.get("user_id")
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            t = (getattr(user, "theme", None) or "default").strip() or "default"
            return t if t in VALID_THEMES else "default"
    raw = (request.cookies.get(BOUNTY_THEME_COOKIE) or "").strip().lower()
    return raw if raw in VALID_THEMES else "default"


# -------------------------------
# FORMULARIO HTML - REGISTRO (GET)
# -------------------------------
@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request, db: Session = Depends(get_db)):
    theme = theme_for_public(request, db)
    return templates.TemplateResponse("register.html", {"request": request, "theme": theme, "page_id": "register"})

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
        theme = theme_for_public(request, db)
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Usuario ya existe",
            "theme": theme,
            "page_id": "register",
        })

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password)
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
def login_form(request: Request, db: Session = Depends(get_db)):
    theme = theme_for_public(request, db)
    return templates.TemplateResponse("login.html", {"request": request, "theme": theme, "page_id": "login"})

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
    user = db.query(User).filter(User.username == username).first()
    if not user or not check_password_hash(user.password_hash, password):
        theme = theme_for_public(request, db)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Usuario o contraseña incorrectos",
            "theme": theme,
            "page_id": "login",
        })

    request.session["user_id"] = user.id
    request.session["username"] = user.username

    cookie_theme = (request.cookies.get(BOUNTY_THEME_COOKIE) or "").strip().lower()
    if cookie_theme in VALID_THEMES:
        try:
            user.theme = cookie_theme
            db.commit()
        except Exception:
            db.rollback()
    theme = (getattr(user, "theme", None) or "default").strip() or "default"
    if theme not in VALID_THEMES:
        theme = "default"
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        BOUNTY_THEME_COOKIE,
        theme,
        max_age=BOUNTY_THEME_COOKIE_MAX_AGE,
        path="/",
    )
    return response

# -------------------------------
# LOGOUT
# -------------------------------
@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    theme = "default"
    user_id = request.session.get("user_id")
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            t = (getattr(user, "theme", None) or "default").strip() or "default"
            theme = t if t in VALID_THEMES else "default"
    request.session.clear()
    response = templates.TemplateResponse(
        "logout.html",
        {"request": request, "theme": theme, "page_id": "logout"},
    )
    response.set_cookie(
        BOUNTY_THEME_COOKIE,
        theme,
        max_age=BOUNTY_THEME_COOKIE_MAX_AGE,
        path="/",
    )
    return response