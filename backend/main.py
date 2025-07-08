from fastapi import FastAPI, Request, Form, status, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi import Query
from starlette.templating import Jinja2Templates
from backend.models import SessionLocal, Project, ScanState, User
import subprocess
import os
import re
import time
import glob
import shutil
from datetime import datetime
from backend.project_routes import router
from starlette.middleware.sessions import SessionMiddleware
from backend.auth import router as auth_router
from werkzeug.security import check_password_hash
from bs4 import BeautifulSoup

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
running_processes = {}

app.add_middleware(SessionMiddleware, secret_key="17f8b4eeb499e55f11f3fcebb933e7196050fa343482f7c3064ad595c5518c1f")

app.include_router(router)
app.include_router(auth_router)

def clean_html_malformed_spans(html_content: str) -> str:
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.prettify()

def is_valid_url(value):
    return re.match(r'^https?://', value) is not None

@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_post(request: Request):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")

    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()

    if not user or not check_password_hash(user.password_hash, password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Credenciales inválidas"
        })

    request.session["user_id"] = user.id
    request.session["username"] = user.username

    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    projects = db.query(Project).all()
    project_data = []

    for p in projects:
        state = db.query(ScanState).filter(ScanState.project_id == p.id).first()
        project_data.append({
            "id": p.id,
            "name": p.name,
            "target": p.target,
            "mode": p.mode,
            "created_at": p.created_at,
            "status": state.status if state else "pendiente",
            "progress": state.progress if state else 0
        })

    db.close()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "projects": project_data
    })

@app.get("/project/new", response_class=HTMLResponse)
async def new_project_form(request: Request):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("new_project.html", {"request": request})

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
    project = Project(name=name, target=target, mode=mode)
    db.add(project)
    db.commit()
    db.refresh(project)
    project_id = project.id

    state = ScanState(project_id=project_id, current_stage="Recon", status="pending", progress=0)
    db.add(state)
    db.commit()
    db.close()

    if start_now:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_target = target.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"results/{clean_target}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        if is_valid_url(target):
            cmd = ["python3", "bounty_hunter.py", "-u", target]
        else:
            cmd = ["python3", "bounty_hunter.py", "-d", target]

        logfile = open(os.path.join(output_dir, "output.log"), "w")
        proc = subprocess.Popen(cmd, stdout=logfile, stderr=logfile)
        running_processes[project_id] = proc

        db = SessionLocal()
        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if state:
            state.status = "running"
            db.commit()
        db.close()

    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/project/{project_id}/stop")
async def stop_project(request: Request, project_id: int):
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

@app.get("/project/{project_id}", response_class=HTMLResponse)
async def view_project(request: Request, project_id: int, file: str = Query(default=None)):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    db.close()

    timestamp_dirs = []
    target_clean = project.target.replace("https://", "").replace("http://", "").replace("/", "_")
    results_base = f"results/{target_clean}"
    if os.path.isdir("results"):
        for d in os.listdir("results"):
            if d.startswith(target_clean):
                timestamp_dirs.append(d)
        if timestamp_dirs:
            latest_dir = sorted(timestamp_dirs)[-1]
            result_dir = os.path.join("results", latest_dir)
        else:
            result_dir = None
    else:
        result_dir = None

    files = {}
    line_counts = {}
    if result_dir and os.path.isdir(result_dir):
        for fname in os.listdir(result_dir):
            if fname.endswith(".txt"):
                fpath = os.path.join(result_dir, fname)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if content.startswith("Details:"):
                        content = "[Info] " + content
                    content = remove_ansi_sequences(content)  # elimina colores de terminal
                    content = clean_html_malformed_spans(content)  # limpia etiquetas rotas
                    files[fname] = content
                    line_counts[fname] = content.count('\n')

    is_running = project_id in running_processes and running_processes[project_id].poll() is None

    return templates.TemplateResponse("project_detail.html", {
        "request": request,
        "project": project,
        "state": state,
        "files": files,
        "line_counts": line_counts,
        "is_running": is_running,
        "file_to_expand": file  # <- este es el nuevo contexto para Jinja
    })

@app.post("/project/{project_id}/start")
async def start_project(request: Request, project_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    if not project:
        return JSONResponse(content={"error": "Proyecto no encontrado"}, status_code=404)

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

    return RedirectResponse(url=f"/project/{project_id}", status_code=303)

@app.post("/project/{project_id}/delete")
async def delete_project(request: Request, project_id: int):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=302)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()

    if project:
        clean_target = (
            project.target
            .replace("https://", "")
            .replace("http://", "")
            .rstrip("/")
            .replace("/", "_")
        )

        results_root = "results"

        if os.path.exists(results_root):
            for folder in os.listdir(results_root):
                if folder.startswith(clean_target):
                    folder_path = os.path.join(results_root, folder)
                    if os.path.isdir(folder_path):
                        try:
                            shutil.rmtree(folder_path)
                            print(f"[✔] Eliminado: {folder_path}")
                        except Exception as e:
                            print(f"[✘] Error al eliminar {folder_path}: {e}")

        db.query(ScanState).filter(ScanState.project_id == project_id).delete()
        db.query(Project).filter(Project.id == project_id).delete()
        db.commit()

    db.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/api/project/{project_id}/status")
async def get_project_status(request: Request, project_id: int):
    if "user_id" not in request.session:
        return JSONResponse(content={"error": "No autenticado"}, status_code=401)

    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    db.close()

    if not state:
        return JSONResponse(content={"error": "Estado no encontrado"}, status_code=404)

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

@app.get("/project/{project_id}/results")
async def get_results(request: Request, project_id: int):
    if "user_id" not in request.session:
        return JSONResponse(content={"error": "No autenticado"}, status_code=401)

    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    if not project:
        return JSONResponse(content={"error": "Proyecto no encontrado"}, status_code=404)

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
                result[file] = "[Error al leer archivo]"

    return JSONResponse(content=result)

def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    return user_id


def remove_ansi_sequences(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)