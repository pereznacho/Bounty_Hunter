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
from backend.scan_worker import run_scan, continue_scan_from_module
from backend.models import SessionLocal, Project, User, ScanState, Target
from utils.path_utils import get_safe_name_from_target
from utils.reporter import generate_markdown_report
from modules.ffuf import run_ffuf
from backend.constants import MODULES
from utils.burp_exporter import export_to_burp_txt
from backend.template_filters import setup_template_filters
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout


router = APIRouter()
templates = Jinja2Templates(directory="templates")
setup_template_filters(templates)


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
        platform="Manual",  # Marcar como proyecto manual
        owner=user,
        created_at=datetime.utcnow(),
        results_dir=folder_name
    )
    db.add(new_proj)
    db.commit()
    db.refresh(new_proj)

    # Crear el Target asociado al proyecto
    target_type = "url" if target.startswith(("http://", "https://")) else "domain"
    new_target = Target(
        project_id=new_proj.id,
        target=target,
        type=target_type,
        status="pending"
    )
    db.add(new_target)
    db.commit()
    db.refresh(new_target)

    scan = ScanState(project_id=new_proj.id)
    db.add(scan)
    db.commit()

    if start_now == "yes":
        scan.status = "running"
        scan.current_step = "Initializing"
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
        scan.current_step = "Initializing"
        scan.progress = 0
        db.commit()
        threading.Thread(target=run_scan, args=(project.id,), daemon=True).start()

    return RedirectResponse(url=f"/project/{project_id}", status_code=303)


@router.post("/project/{project_id}/skip")  
def skip_scan(
    project_id: int,
    request: Request,
    db: Session = Depends(get_db),
    target_id: int = Form(None),
    target_str: str = Form(None)
):
    """
    Salta al siguiente módulo del **target actual**.
    Mata el proceso del módulo en curso **solo** para ese (proyecto, target),
    y continúa con el siguiente módulo del mismo target.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login")

    # --- Resolver el TARGET al que aplica el Skip (por target, no por proyecto) ---
    # Intentar por form fields si llegaron; si no, heurísticas: uno solo / en running
    current_target_obj = None
    if target_id is not None:
        current_target_obj = db.query(Target).filter(Target.id == target_id, Target.project_id == project_id).first()
    if current_target_obj is None and target_str:
        current_target_obj = db.query(Target).filter(Target.project_id == project_id, Target.target == target_str).first()
    if current_target_obj is None:
        targets_all = db.query(Target).filter(Target.project_id == project_id).all()
        if len(targets_all) == 1:
            current_target_obj = targets_all[0]
        else:
            # Buscar uno en ejecución si hubiera estado
            candidate = db.query(Target).filter(Target.project_id == project_id, Target.status == "running").first()
            current_target_obj = candidate or (targets_all[0] if targets_all else None)

    if not current_target_obj:
        print(f"[⚠️] Skip solicitado pero no se pudo resolver target para proyecto {project_id}")
        return RedirectResponse(url=f"/project/{project_id}", status_code=303)

    current_target_value = current_target_obj.target

    try:
        # Obtener estado actual (una por proyecto)
        scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        if not scan or scan.status != "running":
            print(f"[⚠️] No hay escaneo en ejecución para proyecto {project_id}")
            return RedirectResponse(url=f"/project/{project_id}", status_code=303)

        from backend.constants import MODULES

        # 1) Determinar el índice del módulo EN CURSO por nombre
        current_name = (scan.current_step or "").strip()
        if current_name in MODULES:
            current_index = MODULES.index(current_name)
        else:
            # Fallbacks:
            # - si current_step no está seteado, intenta usar el siguiente a last_module_index
            # - si last_module_index es None, arrancamos en 0
            current_index = (scan.last_module_index or -1) + 1
            # Cap a rango válido
            if current_index < 0:
                current_index = 0
            if current_index >= len(MODULES):
                current_index = len(MODULES) - 1

        # 2) Calcular el siguiente índice a ejecutar
        next_index = current_index + 1

        # Log útil
        print(f"[⏭️] Skip: módulo actual {current_index+1}/{len(MODULES)} ({MODULES[current_index]})")
        if next_index < len(MODULES):
            print(f"[⏭️] Avanzando a módulo {next_index+1}/{len(MODULES)} ({MODULES[next_index]})")
        else:
            print(f"[⏭️] No hay más módulos, marcando como completado")

        # 3) Actualizar estado
        if next_index >= len(MODULES):
            # Completar escaneo
            scan.status = "completed"
            scan.current_step = "Finalizado"
            scan.progress = 100
            scan.last_module_index = len(MODULES) - 1
            db.commit()
            return RedirectResponse(url=f"/project/{project_id}", status_code=303)
        else:
            # Avanzar: dejamos constancia de que el actual quedó "saltado"
            scan.last_module_index = current_index
            scan.current_step = MODULES[next_index]
            scan.status = "running"
            scan.progress = int((next_index / len(MODULES)) * 100)
            db.commit()

            # 👉 Mata procesos del módulo actual ANTES de continuar
            from backend.scan_worker import request_skip
            request_skip(project_id, current_target_value)

            # 4) Continuar desde el siguiente módulo en un hilo aparte
            from backend.scan_worker import continue_scan_from_module
            def run_continuation():
                try:
                    continue_scan_from_module(project_id, next_index)
                except Exception as e:
                    print(f"[❌] Error en continuación del escaneo: {e}")

            threading.Thread(target=run_continuation, daemon=True).start()
            print(f"[🚀] Escaneo continuará desde módulo: {scan.current_step} (índice {next_index})")

            return RedirectResponse(url=f"/project/{project_id}", status_code=303)

    except Exception as e:
        print(f"[❌] Error en skip step: {e}")
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

@router.post("/target/{target_id}/mark-vulnerability-viewed")
def mark_vulnerability_viewed(target_id: int, db: Session = Depends(get_db)):
    """Marca la alerta de vulnerabilidad del target como vista."""
    from backend.models import Target
    
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target no encontrado.")
    
    # Marcar como vista
    target.vulnerability_alert_viewed = True
    target.vulnerability_alert_viewed_at = datetime.utcnow()
    
    db.commit()
    
    return JSONResponse({
        "success": True,
        "message": "Alerta de vulnerabilidad marcada como vista"
    })

@router.post("/api/target/{target_id}/mark-viewed")
def mark_target_vulnerabilities_viewed(target_id: int, db: Session = Depends(get_db)):
    """Marca las vulnerabilidades de un target como vistas"""
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target no encontrado")
            
        if target.mark_vulnerabilities_as_viewed():
            db.commit()
            return {"success": True, "message": "Vulnerabilidades marcadas como vistas"}
        else:
            return {"success": False, "message": "No hay vulnerabilidades para marcar"}
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}

@router.post("/api/project/{project_id}/mark-all-viewed")  
def mark_project_vulnerabilities_viewed(project_id: int, db: Session = Depends(get_db)):
    """Marca todas las vulnerabilidades de un proyecto como vistas"""
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Proyecto no encontrado")
            
        if project.mark_all_vulnerabilities_as_viewed():
            db.commit()
            return {"success": True, "message": "Todas las vulnerabilidades marcadas como vistas"}
        else:
            return {"success": False, "message": "No hay vulnerabilidades para marcar"}
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}


@router.get("/api/project/{project_id}/vulnerability-status")
def get_project_vulnerability_status(project_id: int, db: Session = Depends(get_db)):
    """
    Obtiene el estado de vulnerabilidades del proyecto y sus targets.
    Robusto contra timeouts/errores: jamás retorna 500.
    """

    def run_with_timeout(func, timeout_sec: float, default):
        """Ejecuta func con timeout en un hilo; si vence o falla, devuelve default."""
        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(func)
                return fut.result(timeout=timeout_sec)
        except (FuturesTimeout, Exception):
            return default

    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            # Proyecto no encontrado: respuesta vacía (no 500)
            return {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "has_vulnerabilities": False,
                "last_updated": None,
                "project": {
                    "hasVulnerabilities": False,
                    "level": "none",
                    "timestamp": datetime.now().isoformat()
                },
                "targets": []
            }

        # --- Propiedades del proyecto con timeout seguro ---
        proj_has_vulns = run_with_timeout(
            lambda: bool(getattr(project, "has_vulnerabilities", False)),
            timeout_sec=3.0,
            default=False,
        )
        proj_level = run_with_timeout(
            lambda: str(getattr(project, "vulnerability_level", "none")) or "none",
            timeout_sec=3.0,
            default="none",
        )

        # --- Targets (limitamos por seguridad) ---
        targets_status = []
        try:
            targets = db.query(Target).filter(Target.project_id == project_id).limit(200).all()
        except Exception as e:
            # Si incluso la query falla, seguimos con lista vacía
            targets = []

        for t in targets:
            t_has = run_with_timeout(
                lambda: bool(getattr(t, "has_vulnerabilities", False)),
                timeout_sec=1.5,
                default=False,
            )
            t_level = run_with_timeout(
                lambda: str(getattr(t, "vulnerability_level", "none")) or "none",
                timeout_sec=1.5,
                default="none",
            )
            targets_status.append({
                "id": t.id,
                "target": str(getattr(t, "target", "") or ""),
                "hasVulnerabilities": t_has,
                "level": t_level
            })

        # --- Conteo simple por nivel (del proyecto + targets) ---
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        def bump(level: str):
            lvl = (level or "none").lower()
            if lvl in counts:
                counts[lvl] += 1

        if proj_has_vulns:
            bump(proj_level)

        for t in targets_status:
            if t["hasVulnerabilities"]:
                bump(t["level"])

        response = {
            **counts,
            "has_vulnerabilities": proj_has_vulns or any(t["hasVulnerabilities"] for t in targets_status),
            "last_updated": datetime.now().isoformat(),
            "project": {
                "hasVulnerabilities": proj_has_vulns,
                "level": proj_level,
                "timestamp": datetime.now().isoformat()
            },
            "targets": targets_status
        }

        if not response["has_vulnerabilities"] and not targets_status:
            print(f"[ℹ️] Sin vulnerabilidades encontradas para proyecto {project_id}")

        return response

    except Exception as e:
        # Pase lo que pase, devolvemos estructura válida (no 500)
        print(f"[❌] Error inesperado en vulnerability-status para proyecto {project_id}: {e}")
        return {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "has_vulnerabilities": False,
            "last_updated": None,
            "error": "Error interno procesando vulnerabilidades"
        }


@router.get("/api/project/{project_id}/vulnerabilities-live")
def get_live_vulnerabilities(project_id: int, db: Session = Depends(get_db)):
    """Obtiene vulnerabilidades en tiempo real durante el escaneo"""
    
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            return {"vulnerabilities": [], "total_count": 0}
        
        # Buscar archivo de vulnerabilidades en vivo
        import os
        import json
        
        results_dir = f"results/project_{project_id}"
        live_file = os.path.join(results_dir, "vulnerabilities_live.json")
        
        if os.path.exists(live_file):
            with open(live_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data
        else:
            return {
                "scan_started": None,
                "vulnerabilities": [],
                "total_count": 0,
                "last_updated": None
            }
    
    except Exception as e:
        print(f"[❌] Error obteniendo vulnerabilidades en vivo: {e}")
        return {"vulnerabilities": [], "total_count": 0, "error": str(e)}