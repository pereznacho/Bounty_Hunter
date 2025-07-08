# backend/project_routes.py

from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime
import os
import shutil
import threading

from weasyprint import HTML
from backend.scan_worker import run_scan
from backend.models import SessionLocal, Project, User, ScanState
from utils.path_utils import get_safe_name_from_target
from utils.reporter import generate_markdown_report
from modules.ffuf import run_ffuf
from backend.constants import MODULES
from utils.burp_exporter import export_to_burp_txt

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/projects")
def create_project_form(
    name: str = Form(...),
    target: str = Form(...),
    mode: str = Form(...),
    start_now: str = Form(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")
    username = request.session.get("username")
    if not user_id:
        raise HTTPException(status_code=403, detail="Usuario no autenticado")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = get_safe_name_from_target(target)
    folder_name = f"{safe_target}_{timestamp}"

    new_proj = Project(
        name=name,
        target=target,
        mode=mode,
        owner=user,
        created_at=datetime.utcnow(),
        results_dir=folder_name
    )
    db.add(new_proj)
    db.commit()
    db.refresh(new_proj)

    scan = ScanState(project_id=new_proj.id)
    db.add(scan)
    db.commit()

    if start_now == "yes":
        scan.status = "running"
        scan.current_step = "Inicializando"
        scan.progress = 0
        db.commit()

        threading.Thread(
            target=run_scan,
            kwargs=dict(
                project_id=new_proj.id
            ),
            daemon=True
        ).start()

    return RedirectResponse(url="/dashboard", status_code=303)


@router.post("/project/{project_id}/start")
def start_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    scan = project.scan_state
    if scan.status != "running":
        scan.status = "running"
        scan.current_step = "Inicializando"
        scan.progress = 0
        db.commit()
        threading.Thread(target=run_scan, args=(project.id,), daemon=True).start()

    return RedirectResponse(url=f"/project/{project_id}", status_code=303)


@router.api_route("/project/{project_id}/skip", methods=["GET", "POST"])
def skip_stage(project_id: int, db: Session = Depends(get_db)):
    """
    Salta al siguiente módulo y lo ejecuta inmediatamente.
    """
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if not scan or scan.status != "running":
        raise HTTPException(status_code=400, detail="No se puede saltar etapa en estado actual.")

    # Calcular siguiente módulo
    next_index = scan.last_module_index + 1

    if next_index >= len(MODULES):
        # Ya no hay más módulos
        scan.status = "completed"
        scan.current_step = "Finalizado"
        scan.progress = 100
        db.commit()
        return RedirectResponse(url=f"/project/{project_id}", status_code=303)

    # Actualizar el módulo en curso antes de lanzarlo
    scan.current_step = MODULES[next_index]
    scan.last_module_index = next_index
    scan.status = "running"
    db.commit()

    # Ejecutar solo el módulo siguiente
    threading.Thread(
        target=run_scan,
        kwargs=dict(
            project_id=project_id,
            repeat=True,
            forced_index=next_index
        ),
        daemon=True
    ).start()

    return RedirectResponse(url=f"/project/{project_id}", status_code=303)


@router.post("/project/{project_id}/repeat")
def repeat_stage(project_id: int, db: Session = Depends(get_db)):
    """
    Repite el módulo actual sin avanzar.
    """
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if not scan or scan.status != "running":
        raise HTTPException(status_code=400, detail="No se puede repetir etapa en estado actual.")

    current_index = scan.last_module_index

    if current_index < 0 or current_index >= len(MODULES):
        raise HTTPException(status_code=400, detail="Índice de módulo inválido para repetir.")

    scan.current_step = MODULES[current_index]
    scan.status = "running"
    db.commit()

    threading.Thread(
        target=run_scan,
        kwargs=dict(
            project_id=project_id,
            repeat=True,
            forced_index=current_index
        ),
        daemon=True
    ).start()

    return RedirectResponse(url=f"/project/{project_id}", status_code=303)


@router.post("/project/{project_id}/stop")
def stop_project(project_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if scan and scan.status == "running":
        scan.status = "cancelled"
        db.commit()
    return RedirectResponse(url=f"/project/{project_id}", status_code=303)


@router.post("/project/{project_id}/delete")
def delete_project(project_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=403)

    project = db.query(Project).filter(Project.id == project_id, Project.owner_id == user_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    clean_target = (
        project.target
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
        .replace("/", "_")
    )

    base_path = os.path.abspath("results")
    if os.path.isdir(base_path):
        for folder in os.listdir(base_path):
            if folder.startswith(clean_target):
                folder_path = os.path.join(base_path, folder)
                if os.path.isdir(folder_path):
                    try:
                        shutil.rmtree(folder_path)
                        print(f"[✔] Eliminado: {folder_path}")
                    except Exception as e:
                        print(f"[✘] Error al eliminar {folder_path}: {e}")

    if project.scan_state:
        db.delete(project.scan_state)
    db.delete(project)
    db.commit()

    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    username = request.session.get("username")

    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    projects = db.query(Project).filter(Project.owner_id == user_id).all()

    for p in projects:
        if p.scan_state:
            if p.scan_state.status == "running":
                p.scan_state.update_progress()
                db.commit()
            p.status = p.scan_state.status
            p.progress = p.scan_state.progress
        else:
            p.status = "pending"
            p.progress = 0

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "projects": projects,
        "user": username
    })


@router.get("/api/project/list")
def get_user_projects(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content=[], status_code=200)

    proyectos = db.query(Project).filter(Project.owner_id == user_id).all()
    data = []
    for p in proyectos:
        if p.scan_state and p.scan_state.status == "running":
            p.scan_state.update_progress()
            db.commit()
            status = "running"
        elif p.scan_state:
            status = p.scan_state.status
        else:
            status = "pending"

        progress = p.scan_state.progress if p.scan_state else 0

        data.append({
            "id": p.id,
            "name": p.name,
            "target": p.target,
            "mode": p.mode,
            "created_at": p.created_at.isoformat(),
            "progress": progress,
            "status": status
        })

    return JSONResponse(content=data, status_code=200)


@router.get("/api/project/{project_id}/status")
def get_project_status(project_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()

    if scan is None:
        return {
            "status": "unknown",
            "progress": 0,
            "current_step": "No iniciado"
        }

    return {
        "status": scan.status,
        "progress": scan.progress,
        "current_step": scan.current_step
    }


@router.get("/project/{project_id}/export", response_class=FileResponse)
def export_pdf(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).get(project_id)
    scan = db.query(ScanState).filter_by(project_id=project_id).first()
    if not project or not scan:
        raise HTTPException(status_code=404, detail="Proyecto o escaneo no encontrado")

    result_dir = os.path.join("results", project.results_dir)

    files = {}
    if os.path.exists(result_dir):
        for fname in os.listdir(result_dir):
            full_path = os.path.join(result_dir, fname)
            if os.path.isfile(full_path):
                with open(full_path, encoding="utf-8", errors="ignore") as f:
                    files[fname] = f.read()

    html = templates.get_template("export_pdf.html").render({
        "project": project,
        "scan": scan,
        "files": files,
        "datetime": datetime
    })

    pdf_output = f"/tmp/project_{project.id}_report.pdf"
    HTML(string=html).write_pdf(pdf_output)
    return FileResponse(path=pdf_output, media_type='application/pdf', filename=f"project_{project.id}_report.pdf")


@router.get("/project/{project_id}/download-md")
def download_markdown(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    output_dir = os.path.join("results", project.results_dir)
    if not os.path.exists(output_dir):
        raise HTTPException(status_code=404, detail="Directorio de resultados no encontrado")

    stats = {
        "URLs encontradas": sum(1 for fname in os.listdir(output_dir) if "urls" in fname.lower()),
        "Vulnerabilidades detectadas": sum(
            1 for fname in os.listdir(output_dir)
            if "xss" in fname.lower() or "sqli" in fname.lower()
        )
    }

    md_path = generate_markdown_report(project.target, stats, output_dir)
    return FileResponse(path=md_path, filename="Proyecto.md", media_type="text/markdown")


@router.get("/project/{project_id}/export/burp")
def export_project_to_burp(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado.")

    result_dir = os.path.join("results", project.results_dir)
    txt_path = export_to_burp_txt(result_dir)

    return FileResponse(
        txt_path,
        filename="burp_export.txt",
        media_type="text/plain"
    )