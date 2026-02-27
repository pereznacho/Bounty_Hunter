from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from backend.models import Project, get_db
from sqlalchemy.orm import Session
from backend.auth import get_current_user
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="frontend/templates")

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    user_projects = db.query(Project).filter(Project.user_id == user["id"]).all()
    
    # Añadir conteo de dominios y urls
    projects = []
    for p in user_projects:
        projects.append({
            "id": p.id,
            "name": p.name,
            "created_at": p.created_at,
            "domain_count": len(p.targets_domains),
            "url_count": len(p.targets_urls),
        })
    
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": user["username"], "projects": projects})