import json
import logging
import subprocess
import os
import re
import time
import glob
import shutil
import threading
from datetime import datetime

logger = logging.getLogger(__name__)
from fastapi import FastAPI, Request, Form, status, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import hashlib
import threading
import os

from backend.models import SessionLocal, User, Project, Target, ScanState, Platform, BountyProgram, DiscoveredURL


def _commit_with_retry(db, max_attempts=4):
    """Retry commit on SQLite 'database is locked' / 'busy'."""
    for attempt in range(max_attempts):
        try:
            db.commit()
            return True
        except OperationalError as e:
            if "locked" not in str(e).lower() and "busy" not in str(e).lower():
                raise
            db.rollback()
            if attempt < max_attempts - 1:
                time.sleep(0.3 * (attempt + 1))
    return False
from backend.project_routes import router as project_router
from backend.scan_worker import run_scan, delete_target_and_results, launch_scans_for_new_targets, request_skip
from modules.recon import run_domain_recon_save_for_selection
from utils.path_utils import get_safe_name_from_target

app = FastAPI(title="Bounty Hunter", description="Bug Bounty Management Platform")
app.add_middleware(SessionMiddleware, secret_key="17f8b4eeb499e55f11f3fcebb933e7196050fa343482f7c3064ad595c5518c1f")

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")
app.include_router(project_router)
from fastapi.staticfiles import StaticFiles
from fastapi import Query
from starlette.templating import Jinja2Templates
from backend.models import SessionLocal, Project, ScanState, User, Target, engine
from sqlalchemy import text
from backend.project_routes import router
from backend.routers.hackerone import router as hackerone_router
from starlette.middleware.sessions import SessionMiddleware
from backend.auth import router as auth_router
from werkzeug.security import check_password_hash
from bs4 import BeautifulSoup
from backend.routers import hackerone
from backend.database import get_db
from sqlalchemy.orm import Session
from backend.auth import get_current_user
from backend.constants import VALID_THEMES, APP_VERSION
from backend.auth import BOUNTY_THEME_COOKIE, BOUNTY_THEME_COOKIE_MAX_AGE
from sqlalchemy.orm import selectinload
from backend.routers.intigriti import router as intigriti_router
from backend.routers.yeswehack import router as yeswehack_router
from backend.routers.bugcrowd import router as bugcrowd_router
from backend.scan_worker import run_scan, delete_target_and_results, launch_scans_for_new_targets, request_skip
from backend.template_filters import setup_template_filters, clean_html_malformed_spans
from backend.routers.project import router as project_router



app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Configure custom Jinja2 filters
setup_template_filters(templates)
running_processes = {}
app.add_middleware(SessionMiddleware, secret_key="17f8b4eeb499e55f11f3fcebb933e7196050fa343482f7c3064ad595c5518c1f")
app.include_router(router)
app.include_router(auth_router)
app.include_router(hackerone_router)
app.include_router(intigriti_router)
app.include_router(yeswehack_router)
app.include_router(bugcrowd_router)
app.include_router(project_router)


@app.on_event("startup")
def _ensure_theme_column():
    """Create tables if missing, then add theme column to users if missing (Docker + volume .:/app)."""
    from backend.models import Base
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            if "sqlite" in str(engine.url):
                r = conn.execute(text("PRAGMA table_info(users)"))
                cols = [row[1] for row in r]
                if cols and "theme" not in cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN theme VARCHAR DEFAULT 'default'"))
                    conn.commit()
    except Exception:
        pass


def is_valid_url(value):
    return re.match(r'^https?://', value) is not None

def classify_identifier(identifier: str) -> str:
    """Return 'domain' or 'url' for a given identifier string."""
    DOMAIN_LIKE_RE = re.compile(r"^(\*\.|)([a-z0-9\-\_]+\.[a-z]{2,}(?:\.[a-z]{2,})?)$", re.IGNORECASE)
    URL_LIKE_RE = re.compile(r"^(https?:\/\/|www\.)", re.IGNORECASE)
    
    s = identifier.strip().lower()
    if URL_LIKE_RE.match(s):
        return "url"
    if DOMAIN_LIKE_RE.match(s):
        return "domain"
    # fallback heuristics
    if "/" in s:
        return "url"
    return "domain"

def normalize_identifier(identifier: str, typ: str) -> str:
    """Clean identifier based on type."""
    s = identifier.strip()
    if typ == "domain":
        s = s.replace("http://", "").replace("https://", "").replace("//", "")
        if s.startswith("www."):
            s = s[4:]
        # remove path parts
        s = s.split("/")[0]
        if s.startswith("*."):
            s = s[2:]
        elif s.startswith("*"):
            s = s[1:]
        return s.lower()
    else:
        if not s.startswith(("http://", "https://")):
            s = f"https://{s.lstrip('/')}"
        return s

@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/login")

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    project_list = db.query(Project).options(selectinload(Project.targets), selectinload(Project.scan_state)).filter(Project.owner_id == current_user.id).all()

    projects = []
    for p in project_list:
        platform = "Manual"
        if getattr(p, "platform", None):
            platform = p.platform
        elif p.created_from_hackerone:
            platform = "HackerOne"
        elif p.name and "intigriti" in p.name.lower():
            platform = "Intigriti"
        elif p.name and "yeswehack" in p.name.lower():
            platform = "YesWeHack"
        elif p.name and "bugcrowd" in p.name.lower():
            platform = "BugCrowd"

        if platform == "Manual" and len(p.targets) == 1:
            targets_text = p.targets[0].target
        else:
            targets_text = f"{len(p.targets)} targets"

        progress = getattr(p.scan_state, "progress", 0) if p.scan_state else 0
        awaiting_url_selection = (
            p.scan_state is not None
            and getattr(p.scan_state, "status", None) == "awaiting_url_selection"
        )
        projects.append({
            "id": p.id,
            "name": p.name or "Unnamed Project",
            "platform": platform,
            "targets_text": targets_text,
            "progress": progress,
            "has_vulnerabilities": getattr(p, "has_vulnerabilities", False),
            "vulnerability_level": getattr(p, "vulnerability_level", None),
            "awaiting_url_selection": awaiting_url_selection,
        })

    theme_passed = (getattr(current_user, "theme", None) or "default").strip() or "default"
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": current_user,
            "projects": projects,
            "theme": theme_passed,
            "page_id": "dashboard",
        }
    )

@app.get("/api/user/theme")
def get_user_theme(current_user: User = Depends(get_current_user)):
    """Return the current user's saved theme (source of truth for the frontend)."""
    theme = (getattr(current_user, "theme", None) or "default").strip() or "default"
    if theme not in VALID_THEMES:
        theme = "default"
    return JSONResponse(content={"theme": theme})


@app.get("/api/version")
def get_version():
    """Return current app version (no auth)."""
    return JSONResponse(content={"version": APP_VERSION})


@app.get("/api/version/check")
def get_version_check():
    """Check GitHub for latest release; return latest version and url (no auth). Rate limit: call infrequently (e.g. once per 12h)."""
    import re
    repo = os.environ.get("GITHUB_REPO", "pereznacho/Bounty_Hunter").strip()
    try:
        import urllib.request
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        tag = (data.get("tag_name") or "").strip()
        # Normalize v1.2.0 -> 1.2.0
        latest = re.sub(r"^v", "", tag) if tag else None
        html_url = data.get("html_url") or f"https://github.com/{repo}/releases"
        if not latest:
            return JSONResponse(content={"latest": APP_VERSION, "url": html_url, "current": APP_VERSION})
        return JSONResponse(content={"latest": latest, "url": html_url, "current": APP_VERSION})
    except Exception as e:
        return JSONResponse(content={"latest": APP_VERSION, "url": None, "current": APP_VERSION, "error": str(e)})


@app.post("/api/user/theme")
async def save_user_theme(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Save the current user's theme preference. Body: { \"theme\": \"cyberpunk\" }"""
    try:
        data = await request.json()
    except Exception:
        data = {}
    theme = (data.get("theme") or "").strip().lower()
    if theme not in VALID_THEMES:
        theme = "default"
    try:
        current_user.theme = theme
        db.commit()
        with engine.connect() as conn:
            conn.execute(text("UPDATE users SET theme = :t WHERE id = :id"), {"t": theme, "id": current_user.id})
            conn.commit()
    except Exception as e:
        db.rollback()
        return JSONResponse(content={"ok": False, "error": str(e)}, status_code=500)
    resp = JSONResponse(content={"ok": True, "theme": theme})
    resp.set_cookie(
        BOUNTY_THEME_COOKIE,
        theme,
        max_age=BOUNTY_THEME_COOKIE_MAX_AGE,
        path="/",
    )
    return resp

@app.get("/project/new", response_class=HTMLResponse)
async def new_project_form(request: Request, db: Session = Depends(get_db)):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)
    user = db.query(User).filter(User.id == request.session.get("user_id")).first()
    theme = (getattr(user, "theme", None) or "default").strip() or "default"
    return templates.TemplateResponse("new_project.html", {"request": request, "theme": theme, "page_id": "new_project"})

@app.post("/project/new")
async def create_project(
    request: Request,
    name: str = Form(...),
    target: str = Form(...),
    mode: str = Form(...),
    start_now: str = Form(None)
):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project_id = None
    target_type = None
    try:
        # Classify the target using the same logic as bug bounty programs
        target_type = classify_identifier(target)
        normalized_target = normalize_identifier(target, target_type)
        
        # Determine mode automatically
        auto_mode = "url" if target_type == "url" else "domain"
        
        # Create results directory
        safe_target = get_safe_name_from_target(normalized_target)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        folder_name = f"{safe_target}_{timestamp}"
        
        # Create the project
        owner_id = request.session.get("user_id")
        if owner_id is not None:
            owner_id = int(owner_id)
        project = Project(
            name=name,
            target=normalized_target,
            mode=auto_mode,
            platform="Manual",
            results_dir=folder_name,
            owner_id=owner_id
        )
        db.add(project)
        if not _commit_with_retry(db):
            raise Exception("Failed to commit project after retries")
        db.refresh(project)
        project_id = project.id

        # Create the target - do NOT do auto-expansion here, let scan_worker handle it
        target_obj = Target(
            project_id=project.id,
            target=normalized_target,
            type=target_type,
            status="pending"
        )
        db.add(target_obj)
        
        if target_type == "domain":
            print(f"[🎯] MANUAL DOMAIN TARGET CREATED: {normalized_target} (auto-expansion will happen during scan)")
        else:
            print(f"[🔗] MANUAL URL TARGET CREATED: {normalized_target}")
        
        # Create the scan state
        state = ScanState(project_id=project_id, current_stage="Recon", status="pending", progress=0)
        db.add(state)
        if not _commit_with_retry(db):
            raise Exception("Failed to commit scan state after retries")
        
        print(f"[📋] Created manual project {project_id} with target {normalized_target} (type: {target_type})")
        

        # Si se debe iniciar inmediatamente: mismo flujo que bounty (recon → guardar URLs → consultor elige)
        if start_now and start_now.lower() == "yes":
            print(f"Starting scan for project {project_id} (type={target_type})")
            state.status = "running"
            _commit_with_retry(db)

            results_dir_path = os.path.join("results", folder_name)
            _pid, _tid, _norm = project_id, target_type, normalized_target

            def scan_thread():
                try:
                    if _tid == "domain":
                        # Recon + guardar en DiscoveredURL → awaiting_url_selection (no crear cards)
                        run_domain_recon_save_for_selection(_pid, [_norm], results_dir_path)
                        print(f"[✅] Recon done; project {_pid} awaiting URL selection")
                    else:
                        run_scan(project_id=_pid)
                        print(f"Thread completed for project {_pid}")
                except Exception as e:
                    print(f"Error in scan thread for project {_pid}: {e}")

            threading.Thread(target=scan_thread, daemon=True).start()
            print(f"Thread launched for project {project_id}")

    except Exception as e:
        logger.exception("Error creating manual project: %s", e)
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()

    # Dominio con start_now: llevar a targets para ver lista de URLs descubiertas y marcar cuáles escanear
    if project_id and start_now and start_now.lower() == "yes" and target_type == "domain":
        return RedirectResponse(url=f"/project/{project_id}/targets", status_code=303)
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/project/{project_id}/target/{target_id}/stop", response_class=RedirectResponse)
async def stop_target_scan(request: Request, project_id: int, target_id: int):
    """Stop all scanning tasks for this target only (kills process via request_skip, marks target cancelled)."""
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id, Target.project_id == project_id).first()
        if not target:
            return RedirectResponse(url=f"/project/{project_id}/targets", status_code=303)
        request_skip(project_id, target.target)
        target.status = "cancelled"
        db.commit()
        # If no other target is running, mark ScanState as cancelled
        any_running = db.query(Target).filter(Target.project_id == project_id, Target.status == "running").first()
        if not any_running:
            state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
            if state:
                state.status = "cancelled"
                db.commit()
    finally:
        db.close()
    return RedirectResponse(url=f"/project/{project_id}/target/{target_id}", status_code=303)


@app.post("/project/{project_id}/stop")
async def stop_project(request: Request, project_id: int):
    """Legacy: stop single process in running_processes. Prefer stop_target_scan or stop_project_scans for per-target / full-project stop."""
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    proc = running_processes.get(project_id)
    if proc and proc.poll() is None:
        proc.terminate()
        proc.wait()
        del running_processes[project_id]

        db = SessionLocal()
        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if state:
            state.status = "stopped"
            db.commit()
        db.close()

    return RedirectResponse(url=f"/project/{project_id}", status_code=303)


@app.post("/project/{project_id}/stop-scan", response_class=RedirectResponse)
async def stop_project_scans(request: Request, project_id: int):
    """Stop all scans for all targets in this project (request_skip per target, mark all cancelled)."""
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)
    redirect_url = f"/project/{project_id}/targets"
    db = SessionLocal()
    try:
        user_id = request.session.get("user_id")
        try:
            user_id = int(user_id) if user_id is not None else None
        except (TypeError, ValueError):
            user_id = None
        project = db.query(Project).filter(Project.id == project_id, Project.owner_id == user_id).first() if user_id else None
        if not project:
            db.close()
            return RedirectResponse(url="/dashboard", status_code=303)
        targets = db.query(Target).filter(Target.project_id == project_id).all()
        for t in targets:
            if getattr(t, "status", None) == "running" and getattr(t, "target", None):
                try:
                    request_skip(project_id, t.target)
                except Exception:
                    pass
                t.status = "cancelled"
        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if state:
            state.status = "cancelled"
        db.commit()
    except Exception as e:
        logger.exception("stop_project_scans error for project_id=%s: %s", project_id, e)
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()
    # Kill legacy single process if any
    try:
        proc = running_processes.get(project_id)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass
        if project_id in running_processes:
            del running_processes[project_id]
    except Exception:
        pass
    return RedirectResponse(url=redirect_url, status_code=303)



@app.get("/go_to_project/{project_id}")
def go_to_project(project_id: int):
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Verifica si es proyecto manual o importado desde plataforma
    if project.platform == "Manual":
        return RedirectResponse(url=f"/project/{project.id}")
    else:
        return RedirectResponse(url=f"/project/{project.id}/targets")

# Vista de todos los targets del proyecto (estilo dashboard)
@app.get("/project/{project_id}/targets", response_class=HTMLResponse)
async def project_targets(request: Request, project_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).options(
        selectinload(Project.targets),
        selectinload(Project.scan_state),
        selectinload(Project.discovered_urls),
    ).filter(Project.id == project_id).first()

    if not project:
        db.close()
        raise HTTPException(status_code=404, detail="Project not found")

    targets = project.targets
    state = project.scan_state
    discovered_urls = list(project.discovered_urls) if getattr(project, "discovered_urls", None) else []
    awaiting_selection = state and getattr(state, "status", None) == "awaiting_url_selection"
    has_url_targets = any(getattr(t, "type", None) == "url" for t in targets)

    user = db.query(User).filter(User.id == request.session.get("user_id")).first()
    theme = (getattr(user, "theme", None) or "default").strip() or "default"

    response = templates.TemplateResponse("project_targets.html", {
        "request": request,
        "project": project,
        "targets": targets,
        "state": state,
        "discovered_urls": discovered_urls,
        "awaiting_selection": awaiting_selection,
        "has_url_targets": has_url_targets,
        "theme": theme,
        "page_id": "targets",
    })
    db.close()
    return response

@app.get("/project/{project_id}", response_class=HTMLResponse)
async def project_detail(request: Request, project_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).options(selectinload(Project.targets)).filter(Project.id == project_id).first()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    
    if not project:
        db.close()
        raise HTTPException(status_code=404, detail="Project not found")

    # Search for target if it exists (for platforms)
    target = None
    scans = None  # Placeholder, puedes completar si tienes lógica de scans
    if project and project.targets:
        target = project.targets[0]
    
    # Verificar si es un proyecto manual (sin plataforma específica) CON targets
    # Si es manual y tiene targets, redirigir a la vista de targets para mostrar alertas
    platform = getattr(project, 'platform', None)
    if (platform is None or 
        platform == "Manual" or 
        platform == "Manual (Auto-expanded)") and len(project.targets) > 1:
        db.close()
        return RedirectResponse(url=f"/project/{project_id}/targets", status_code=302)

    user = db.query(User).filter(User.id == request.session.get("user_id")).first()
    theme = (getattr(user, "theme", None) or "default").strip() or "default"
    db.close()

    # Cargar archivos generados
    files = {}
    if hasattr(project, "target"):
        clean_target = (
            project.target
            .replace("https://", "")
            .replace("http://", "")
            .rstrip("/")
            .replace("/", "_")
        )
        pattern = f"results/{clean_target}_*"
        dirs = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

        if dirs:
            latest_dir = dirs[0]
            for file in os.listdir(latest_dir):
                if file.endswith(".txt"):
                    path = os.path.join(latest_dir, file)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        files[file] = content
                    except Exception:
                        files[file] = "[Error reading file]"

    # Si el proyecto fue creado con plataforma (no manual) y tiene target, usar el template especial
    if project.platform != "Manual" and target:
        return templates.TemplateResponse("project_target_detail.html", {
            "request": request,
            "project": project,
            "target": target,
            "scans": scans,
            "files": files,
            "state": state,
            "theme": theme,
            "page_id": "target_detail",
        })

    return templates.TemplateResponse("project_detail.html", {
        "request": request,
        "project": project,
        "state": state,
        "files": files,
        "theme": theme,
        "page_id": "project_detail",
    })


@app.get("/project/{project_id}/target/{target_id}", response_class=HTMLResponse)
async def project_target_detail(request: Request, project_id: int, target_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    project = db.query(Project).options(selectinload(Project.scan_state)).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    target = db.query(Target).filter(Target.id == target_id, Target.project_id == project_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Marcar alerta de vulnerabilidad como vista si tiene vulnerabilidades no vistas
    if target.has_unviewed_vulnerabilities:
        target.vulnerability_alert_viewed = True
        target.vulnerability_alert_viewed_at = datetime.utcnow()
        db.commit()

    scan_state = db.query(ScanState).filter(ScanState.project_id == project.id).first()

    # Buscar último directorio con resultados de este target (como en project_detail)
    clean_target = (
        target.target
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
        .replace("/", "_")
    )
    pattern = f"results/{clean_target}_*"
    dirs = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    files = {}
    if dirs:
        latest_dir = dirs[0]
        for file in os.listdir(latest_dir):
            if file.endswith(".txt"):
                path = os.path.join(latest_dir, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    files[file] = content
                except Exception:
                    files[file] = "[Error reading file]"

    theme = (getattr(current_user, "theme", None) or "default").strip() or "default"
    return templates.TemplateResponse("project_target_detail.html", {
        "request": request,
        "project": project,
        "target": target,
        "scan_state": scan_state,
        "files": files,
        "state": scan_state,
        "theme": theme,
        "page_id": "target_detail",
    })

@app.post("/project/{project_id}/start")
async def start_project(request: Request, project_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    if not project:
        return JSONResponse(content={"error": "Project not found"}, status_code=404)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = project.target.replace('https://', '').replace('http://', '').replace('/', '_')
    output_dir = f"results/{clean_target}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    if is_valid_url(project.target):
        cmd = ["python3", "bounty_hunter.py", "-u", project.target]
    else:
        cmd = ["python3", "bounty_hunter.py", "-d", project.target]

    logfile = open(os.path.join(output_dir, "output.log"), "w")
    proc = subprocess.Popen(cmd, stdout=logfile, stderr=logfile)
    running_processes[project_id] = proc

    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if state:
        state.status = "running"
        db.commit()
    db.close()

    # Conditional redirect: if project.platform and project.targets, go to first target, else go to project main page
    if getattr(project, "platform", None) and getattr(project, "targets", None) and project.targets:
        return RedirectResponse(f"/project/{project_id}/target/{project.targets[0].id}", status_code=303)
    else:
        return RedirectResponse(f"/project/{project_id}", status_code=303)

@app.post("/project/{project_id}/delete")
async def delete_project(request: Request, project_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()

    if project:
        # Stop any running scans for this project
        scan_state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if scan_state and scan_state.status == "running":
            scan_state.status = "cancelled"
            db.commit()
            print(f"[!] Cancelled running scan for project {project_id}")

        # Get all targets for this project to clean their result directories
        targets = db.query(Target).filter(Target.project_id == project_id).all()
        results_root = "results"

        if os.path.exists(results_root):
            # Clean directories for all targets (domains and URLs)
            for target in targets:
                clean_target = (
                    target.target
                    .replace("https://", "")
                    .replace("http://", "")
                    .rstrip("/")
                    .replace("/", "_")
                )

                for folder in os.listdir(results_root):
                    if folder.startswith(clean_target):
                        folder_path = os.path.join(results_root, folder)
                        if os.path.isdir(folder_path):
                            try:
                                shutil.rmtree(folder_path)
                                print(f"[✔] Eliminado directorio de target o dominio: {folder_path}")
                            except Exception as e:
                                print(f"[✘] Error al eliminar {folder_path}: {e}")

            # Clean additional directories related to the project name (for bounty expansions)
            if project.name:
                safe_project_name = (
                    project.name
                    .replace(" ", "_")
                    .replace("/", "_")
                )
                for folder in os.listdir(results_root):
                    if safe_project_name.lower() in folder.lower():
                        folder_path = os.path.join(results_root, folder)
                        if os.path.isdir(folder_path):
                            try:
                                shutil.rmtree(folder_path)
                                print(f"[✔] Eliminado directorio relacionado al programa: {folder_path}")
                            except Exception as e:
                                print(f"[✘] Error al eliminar {folder_path}: {e}")

        # Delete all targets first (cascade should handle this, but being explicit)
        db.query(Target).filter(Target.project_id == project_id).delete()

        # Delete scan state
        db.query(ScanState).filter(ScanState.project_id == project_id).delete()

        # Delete the project
        db.query(Project).filter(Project.id == project_id).delete()
        db.commit()

        print(f"[✔] Eliminado proyecto completo: {project.name} (ID: {project_id})")

    db.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/project/{project_id}/discovered-urls/scan", response_class=RedirectResponse)
async def scan_selected_discovered_urls(request: Request, project_id: int):
    """El consultor eligió URLs: se crean targets y se lanza run_scan (flujo dominio manual/bounty)."""
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    form = await request.form()
    selected = form.getlist("urls") if hasattr(form, "getlist") else [v for k, v in form.multi_items() if k == "urls"]

    if not selected:
        return RedirectResponse(url=f"/project/{project_id}/targets", status_code=303)

    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        selected_set = set()
        for url in selected:
            url = (url or "").strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            selected_set.add(url)
            if not db.query(Target).filter(Target.project_id == project_id, Target.target == url).first():
                db.add(Target(project_id=project_id, target=url, type="url", status="pending"))
        # Remove only the selected URLs from discovered list (keep the rest for later selection)
        if selected_set:
            db.query(DiscoveredURL).filter(
                DiscoveredURL.project_id == project_id,
                DiscoveredURL.url.in_(selected_set)
            ).delete(synchronize_session=False)
        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if state:
            state.status = "running"
            state.current_stage = "Recon"
        db.commit()
    finally:
        db.close()

    # Launch one scan per selected URL in parallel (multithreaded)
    threading.Thread(target=launch_scans_for_new_targets, args=(project_id,), daemon=True).start()
    return RedirectResponse(url=f"/project/{project_id}/targets", status_code=303)


@app.post("/project/{project_id}/target/{target_id}/delete")
async def delete_target(request: Request, project_id: int, target_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    
    # Verify project and target exist and belong to user
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        db.close()
        raise HTTPException(status_code=404, detail="Project not found")
    
    target = db.query(Target).filter(Target.id == target_id, Target.project_id == project_id).first()
    if not target:
        db.close()
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Stop any running scan for this specific target
    # We need to check if there are running scans and stop the specific target thread
    scan_state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if scan_state and scan_state.status == "running":
        # Mark the target as cancelled so its thread will stop
        target.status = "cancelled"
        db.commit()
        print(f"[!] Marked target {target.target} as cancelled to stop its scan thread")
    
    # Clean up result files for this specific target using shared function
    delete_target_and_results(target.id, target.target)
    
    # Re-add this URL to the discovered/pending list so it can be selected again (incomplete or deleted scan = not fully audited)
    target_url = (target.target or "").strip()
    if target_url and target_url.startswith(("http://", "https://")):
        existing = db.query(DiscoveredURL).filter(
            DiscoveredURL.project_id == project_id,
            DiscoveredURL.url == target_url
        ).first()
        if not existing:
            db.add(DiscoveredURL(project_id=project_id, url=target_url))
    
    # Delete the target from database
    db.delete(target)
    
    # Check if this was the last target - if so, clean up the project's scan state
    remaining_targets = db.query(Target).filter(Target.project_id == project_id).count()
    if remaining_targets == 1:  # Will be 0 after commit
        if scan_state:
            db.delete(scan_state)
            print(f"[✔] Removed scan state for project {project_id} (no targets remaining)")
    
    db.commit()
    db.close()
    
    # Check where to redirect - if no more targets, go to dashboard, otherwise back to targets view
    db = SessionLocal()
    remaining_targets_after = db.query(Target).filter(Target.project_id == project_id).count()
    db.close()
    
    if remaining_targets_after == 0:
        return RedirectResponse(url="/dashboard", status_code=303)
    else:
        return RedirectResponse(url=f"/project/{project_id}/targets", status_code=303)


@app.get("/api/project/{project_id}/status")
async def get_project_status(request: Request, project_id: int):
    if "user_id" not in request.session:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    db.close()

    if not state:
        return JSONResponse(content={"error": "State not found"}, status_code=404)

    proc = running_processes.get(project_id)
    if proc and proc.poll() is not None:
        db = SessionLocal()
        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if state:
            state.status = "completed"
            state.progress = 100
            db.commit()
        db.close()

    return JSONResponse(content={
        "progress": state.progress,
        "status": state.status,
        "stage": state.current_stage,
        "current_module": state.current_module
    })


@app.get("/api/project/{project_id}/discovered-urls")
async def get_discovered_urls(request: Request, project_id: int):
    """Return count and list of discovered URLs for the project (awaiting selection). No auth for same-session usage."""
    if "user_id" not in request.session:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    db = SessionLocal()
    try:
        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        awaiting = state and getattr(state, "status", None) == "awaiting_url_selection"
        urls = db.query(DiscoveredURL).filter(DiscoveredURL.project_id == project_id).all()
        count = len(urls)
        return JSONResponse(content={
            "count": count,
            "awaiting_selection": awaiting,
            "urls": [u.url for u in urls]
        })
    finally:
        db.close()


@app.get("/project/{project_id}/results")
async def get_results(request: Request, project_id: int):
    if "user_id" not in request.session:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    if not project:
        return JSONResponse(content={"error": "Project not found"}, status_code=404)

    clean_target = project.target.replace('https://', '').replace('http://', '').replace('/', '_')
    pattern = f"results/{clean_target}_*"
    dirs = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    if not dirs:
        return JSONResponse(content={})

    latest_dir = dirs[0]
    result = {}

    for file in os.listdir(latest_dir):
        if file.endswith(".txt"):
            path = os.path.join(latest_dir, file)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                result[file] = content
            except Exception:
                result[file] = "[Error reading file]"

    return JSONResponse(content=result)



def remove_ansi_sequences(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@app.post("/api/targets/{target_id}/dismiss-alert")
def dismiss_target_vulnerability_alert(target_id: int):
    """Dismiss vulnerability alert for a specific target"""
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        
        # Mark vulnerability alert as viewed
        if hasattr(target, 'vulnerability_alert_viewed'):
            target.vulnerability_alert_viewed = True
            target.vulnerability_alert_viewed_at = datetime.utcnow()
            db.commit()
        
        return {"success": True, "message": "Vulnerability alert dismissed"}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error dismissing alert: {str(e)}")
    finally:
        db.close()

# Enhanced function to get targets with vulnerability information
def get_enhanced_targets_for_project(project_id: int):
    """Get all targets for a specific project with vulnerability alerts"""
    db = SessionLocal()
    try:
        targets = db.query(Target).filter(Target.project_id == project_id).all()
        
        targets_data = []
        for target in targets:
            # Get vulnerability information with better defaults
            vulnerability_alert = getattr(target, 'vulnerability_alert', False)
            max_severity = getattr(target, 'max_severity', None)
            vulnerability_count = getattr(target, 'vulnerability_count', 0)
            alert_viewed = getattr(target, 'vulnerability_alert_viewed', False)
            
            # Check for vulnerability alert (not viewed)
            has_alert = vulnerability_alert and not alert_viewed
            
            # Ensure max_severity has a valid value
            if has_alert and vulnerability_count > 0 and not max_severity:
                max_severity = 'medium'  # default to medium if vulnerabilities exist but no severity set
            
            targets_data.append({
                "id": target.id,
                "target": target.target,
                "type": target.type,
                "status": target.status,
                "vulnerability_alert": has_alert,
                "max_severity": max_severity,
                "vulnerability_count": vulnerability_count
            })
        
        return {"targets": targets_data}
    finally:
        db.close()

@app.get("/api/projects/{project_id}/targets")
def get_project_targets_api(project_id: int):
    """API endpoint to get targets with vulnerability information"""
    return get_enhanced_targets_for_project(project_id)

