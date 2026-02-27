# backend/routers/project.py

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
import logging
import os

from backend.models import SessionLocal, Project, Target, ScanState
from backend.scan_worker import delete_target_and_results

router = APIRouter(prefix="/project", tags=["project"])
logger = logging.getLogger("project")

@router.get("/{project_id}/delete", response_class=HTMLResponse)
def confirm_delete_project(request: Request, project_id: int):
    """
    (Opcional) Vista de confirmación. Si no la usas, puedes omitir esta ruta.
    """
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # Renderiza una vista sencilla, o redirige. Aquí devolvemos 200 simple.
        return HTMLResponse(
            f"<h3>Delete project #{project_id} - {project.name}</h3>"
            f"<form method='post' action='/project/{project_id}/delete'>"
            f"<button type='submit'>Confirm delete</button>"
            f"</form>"
        )
    finally:
        db.close()

@router.post("/{project_id}/delete")
def delete_project(project_id: int):
    """
    Borra todos los directorios de resultados de los targets de este proyecto y
    elimina el proyecto de la base de datos.
    """
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        # 1) Eliminar directorios de resultados de TODOS los targets
        if getattr(project, "targets", None):
            for t in list(project.targets):
                try:
                    delete_target_and_results(t.id, t.target)
                except Exception as e:
                    logger.error(f"Error removing results for target {t.id} ({t.target}): {e}")

        # 2) (Opcional) Si usas un results_dir a nivel de proyecto para bounty,
        #    puedes intentar borrar ficheros sueltos allí también. No borro carpetas
        #    que ya se eliminan por target.
        #    Si deseas limpiar archivos sueltos, agrégalo aquí.

        # 3) Eliminar el proyecto (gracias al cascade='all, delete-orphan' en models,
        #    los targets hijos se eliminarán automáticamente)
        db.delete(project)
        db.commit()

        logger.info("Project %s deleted with all target results", project_id)
        return RedirectResponse(url="/dashboard", status_code=303)
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        logger.exception("Error deleting project %s: %s", project_id, e)
        db.rollback()
        return JSONResponse({"error": "Deletion failed"}, status_code=500)
    finally:
        db.close()

@router.get("/api/project/{project_id}/vulnerability-status")
async def project_vulnerability_status_safe(project_id: int):
    """
    Respuesta estable para el dashboard. Nunca 500 por ausencia de hallazgos
    ni por problemas leyendo el filesystem.
    """
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            # Evitar ruido de errores: devolvemos 200 con estado "not_found"
            return JSONResponse(content={
                "has_vulnerabilities": False,
                "level": "none",
                "status": "not_found",
                "progress": 0
            }, status_code=200)

        # Protegemos propiedades que pueden lanzar excepciones
        try:
            has_vulns = bool(project.has_vulnerabilities)
        except Exception:
            has_vulns = False

        try:
            level = str(project.vulnerability_level or "none")
        except Exception:
            level = "none"

        state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        status_text = getattr(state, "status", "pending")
        progress_val = int(getattr(state, "progress", 0) or 0)

        return JSONResponse(content={
            "has_vulnerabilities": has_vulns,
            "level": level,
            "status": status_text,
            "progress": progress_val
        }, status_code=200)
    except Exception as e:
        # Fallback blindado: el dashboard no debe romper
        return JSONResponse(content={
            "has_vulnerabilities": False,
            "level": "none",
            "status": "unknown",
            "progress": 0,
            "detail": f"safe-fallback: {str(e)}"
        }, status_code=200)
    finally:
        db.close()