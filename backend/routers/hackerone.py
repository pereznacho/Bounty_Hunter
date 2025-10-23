# backend/routers/hackerone.py
from fastapi import APIRouter, Request, HTTPException, Form, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.orm import Session, selectinload
from typing import List, Dict, Any
import logging
import requests
import threading
import uuid
from datetime import datetime
import re
import os
import httpx
import json
from backend.models import SessionLocal, Project, Target, ScanState, User, Platform, BountyProgram
from backend.scan_worker import run_scan
from modules.recon import replicate_manual_domain_behavior
from utils.path_utils import get_safe_name_from_target



router = APIRouter()
templates = Jinja2Templates(directory="templates")


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hackerone")

# remote JSON with hackerone programs
HACKERONE_DATA_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/hackerone_data.json"

DOMAIN_LIKE_RE = re.compile(r"^(\*\.|)([a-z0-9\-\_]+\.[a-z]{2,}(?:\.[a-z]{2,})?)$", re.IGNORECASE)
URL_LIKE_RE = re.compile(r"^(https?:\/\/|www\.)", re.IGNORECASE)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



def fetch_programs() -> List[Dict[str, Any]]:
    """Fetch the JSON from the GitHub raw data and normalize to a list of programs."""
    resp = requests.get(HACKERONE_DATA_URL, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    # some files may wrap under "programs" key or be directly a list
    if isinstance(data, dict) and "programs" in data:
        programs = data["programs"]
    elif isinstance(data, list):
        programs = data
    else:
        # fallback: try to find lists inside dict
        for v in data.values():
            if isinstance(v, list):
                programs = v
                break
        else:
            programs = []
    return programs


def classify_identifier(identifier: str) -> str:
    """Return 'domain' or 'url' for a given identifier string."""
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


@router.get("/hackerone", response_class=HTMLResponse)
async def list_hackerone_programs(request: Request):
    """
    Lista los programas (overview). Devuelve la plantilla import.html con
    una lista simplificada que incluye counts de dominios / urls.
    """
    try:
        programs = fetch_programs()
    except Exception:
        logger.exception("Error fetching HackerOne programs")
        return templates.TemplateResponse("import.html", {
            "request": request,
            "programs": [],
            "selected_program": None,
            "error": "Hubo un problema al obtener los programas de HackerOne."
        })

    simplified_programs = []
    for p in programs:
        # extraer in_scope robustamente
        in_scope = []
        if isinstance(p.get("targets"), dict) and isinstance(p["targets"].get("in_scope"), list):
            in_scope = p["targets"]["in_scope"]
        elif isinstance(p.get("in_scope"), list):
            in_scope = p["in_scope"]
        elif isinstance(p.get("targets"), list):
            in_scope = p["targets"]
        else:
            # fallback: busca listas en el dict
            for v in p.values():
                if isinstance(v, list):
                    in_scope = v
                    break

        domains_c = 0
        urls_c = 0
        normalized_in_scope = []
        for t in in_scope:
            if not isinstance(t, dict):
                continue
            ident = t.get("asset_identifier") or t.get("identifier") or t.get("asset") or t.get("value")
            if not ident:
                continue
            typ = classify_identifier(str(ident))
            if typ == "domain":
                domains_c += 1
            else:
                urls_c += 1
            normalized_in_scope.append({
                "original": ident,
                "type": typ,
                "eligible": bool(t.get("eligible_for_bounty") or t.get("eligible_for_submission") or False)
            })

        simplified_programs.append({
            "name": p.get("name") or p.get("handle") or "Unnamed",
            "handle": p.get("handle") or p.get("name") or "",
            "offers_bounties": p.get("offers_bounties", False),
            "in_scope": normalized_in_scope,
            "domains_count": domains_c,
            "urls_count": urls_c
        })

    simplified_programs = sorted(simplified_programs, key=lambda x: (x["name"] or "").lower())

    return templates.TemplateResponse("import.html", {
        "request": request,
        "programs": simplified_programs,
        "selected_program": None,
        "error": None
    })

@router.get("/hackerone/import", response_class=HTMLResponse)
async def import_hackerone_programs(request: Request):
    """
    Lista (vista de import) preparada para import.html — con counts y
    la lista normalizada para la plantilla.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)

    try:
        programs = fetch_programs()
    except Exception:
        logger.exception("Error fetching HackerOne programs")
        return templates.TemplateResponse("import.html", {
            "request": request,
            "programs": [],
            "selected_program": None,
            "error": "Hubo un problema al obtener los programas de HackerOne."
        })

    # reusar la lógica de preparación igual que en list_hackerone_programs
    simplified_programs = []
    for p in programs:
        in_scope = []
        if isinstance(p.get("targets"), dict) and isinstance(p["targets"].get("in_scope"), list):
            in_scope = p["targets"]["in_scope"]
        elif isinstance(p.get("in_scope"), list):
            in_scope = p["in_scope"]
        elif isinstance(p.get("targets"), list):
            in_scope = p["targets"]
        else:
            for v in p.values():
                if isinstance(v, list):
                    in_scope = v
                    break

        domains_c = 0
        urls_c = 0
        normalized_in_scope = []
        for t in in_scope:
            if not isinstance(t, dict):
                continue
            ident = t.get("asset_identifier") or t.get("identifier") or t.get("asset") or t.get("value")
            if not ident:
                continue
            typ = classify_identifier(str(ident))
            if typ == "domain":
                domains_c += 1
            else:
                urls_c += 1
            normalized_in_scope.append({"original": ident, "type": typ})

        simplified_programs.append({
            "name": p.get("name") or p.get("handle") or "Unnamed",
            "handle": p.get("handle") or p.get("name") or "",
            "offers_bounties": p.get("offers_bounties", False),
            "in_scope": normalized_in_scope,
            "domains_count": domains_c,
            "urls_count": urls_c
        })

    simplified_programs = sorted(simplified_programs, key=lambda x: (x["name"] or "").lower())

    return templates.TemplateResponse("import.html", {
        "request": request,
        "programs": simplified_programs,
        "selected_program": None,
        "error": None
    })

@router.get("/hackerone/program/{handle}", response_class=HTMLResponse)
async def show_program(request: Request, handle: str):
    """
    Muestra el detalle de un programa concreto. Extrae los targets (in_scope)
    y separa en domains / urls (con versión 'clean' y 'original') para la plantilla.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)

    try:
        programs = fetch_programs()
    except Exception:
        logger.exception("Error fetching HackerOne programs")
        return templates.TemplateResponse("import.html", {
            "request": request,
            "programs": [],
            "selected_program": None,
            "error": "No se pudo obtener los programas de HackerOne."
        })

    # construir overview con counts (para el listado lateral)
    overview = []
    for p in programs:
        in_scope_local = []
        if isinstance(p.get("targets"), dict) and isinstance(p["targets"].get("in_scope"), list):
            in_scope_local = p["targets"]["in_scope"]
        elif isinstance(p.get("in_scope"), list):
            in_scope_local = p["in_scope"]
        elif isinstance(p.get("targets"), list):
            in_scope_local = p["targets"]
        identifiers = []
        for t in in_scope_local:
            ident = None
            if isinstance(t, dict):
                ident = t.get("asset_identifier") or t.get("identifier") or t.get("asset")
            if not ident:
                continue
            typ = classify_identifier(str(ident))
            clean = normalize_identifier(str(ident), typ)
            identifiers.append({"type": typ, "clean": clean})
        domains_c = len([x for x in identifiers if x["type"] == "domain"])
        urls_c = len([x for x in identifiers if x["type"] == "url"])
        overview.append({
            "name": p.get("name") or p.get("handle") or "Unnamed",
            "handle": p.get("handle") or p.get("name") or "",
            "domains_count": domains_c,
            "urls_count": urls_c
        })
    overview = sorted(overview, key=lambda x: (x["name"] or "").lower())

    # encontrar el programa solicitado
    selected = next((pr for pr in programs if (pr.get("handle") == handle or pr.get("name") == handle)), None)
    if not selected:
        return RedirectResponse("/hackerone", status_code=302)

    in_scope = selected.get("targets", {}).get("in_scope") or selected.get("in_scope") or selected.get("targets") or []
    domains = []
    urls = []
    filtered_targets = []
    for t in in_scope:
        if not isinstance(t, dict):
            continue
        ident = t.get("asset_identifier") or t.get("identifier") or t.get("asset")
        if not ident:
            continue
        typ = classify_identifier(str(ident))
        clean = normalize_identifier(str(ident), typ)
        eligible = bool(t.get("eligible_for_bounty") or t.get("eligible_for_submission") or False)
        severity_raw = (t.get("max_severity") or "").strip().lower()

        # normalizar severidad (puede venir vacía)
        valid_severities = ["low", "medium", "high", "critical"]
        severity = severity_raw if severity_raw in valid_severities else "none"

        entry = {
            "original": ident,
            "clean": clean,
            "type": typ,
            "eligibility": eligible,
            "severity": severity,
            "program_handle": selected.get("handle"),
            "program_name": selected.get("name") or selected.get("handle")
        }
        filtered_targets.append(entry)
        if typ == "domain":
            domains.append(entry)
        else:
            urls.append(entry)

    summary = {
        "total": len(filtered_targets),
        "domains": len(domains),
        "urls": len(urls),
        "eligible": sum(1 for x in filtered_targets if x["eligibility"])
    }

    program_data = {
        "name": selected.get("name") or selected.get("handle"),
        "handle": selected.get("handle"),
        "url": selected.get("url") or f"https://hackerone.com/{selected.get('handle')}",
        "domains": domains,
        "urls": urls,
        "domains_count": len(domains),
        "urls_count": len(urls),
        "filtered_targets": filtered_targets,
        "summary": summary
    }

    return templates.TemplateResponse("import.html", {
        "request": request,
        "programs": overview,
        "selected_program": program_data,
        "error": None
    })


@router.post("/hackerone/scan", response_class=HTMLResponse)
async def start_scan_from_program(request: Request):
    """
    Recibe múltiples inputs 'targets' (checkboxes). Cada target puede ser:
      - 'domain:example.com' or 'url:https://...'
      - 'example.com' or 'https://...'
    Crea Project + Target rows y lanza el scan con run_scan (misma ruta que flujo manual).
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)

    form = await request.form()
    program_handle = str(form.get("handle") or "")
    program_name = str(form.get("name") or program_handle)

    # starlette form supports getlist; robust fallback if not
    if hasattr(form, "getlist"):
        targets = form.getlist("targets")
    else:
        # try to gather all keys named 'targets'
        targets = [v for k, v in form.multi_items() if k == "targets"] if hasattr(form, "multi_items") else []

    logger.info("Import scan request for program=%s targets=%d", program_handle, len(targets))

    if not targets:
        return templates.TemplateResponse("import.html", {
            "request": request,
            "programs": [],
            "selected_program": None,
            "error": "No targets selected"
        })

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        safe_target = get_safe_name_from_target(targets[0])
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        folder_name = f"{safe_target}_{timestamp}"

        detected_types = []
        cleaned_targets = []
        for raw in targets:
            if isinstance(raw, str) and ":" in raw and raw.split(":", 1)[0] in ("domain", "url"):
                tipo, val = raw.split(":", 1)
                typ = tipo
                ident = val
            else:
                ident = raw
                typ = classify_identifier(str(ident))
            clean = normalize_identifier(str(ident), typ)
            detected_types.append(typ)
            cleaned_targets.append((typ, clean))

        overall_mode = "domain" if all(t == "domain" for t in detected_types) else "url"

        project = Project(
            name=program_name,
            program=program_handle,
            target=cleaned_targets[0][1],
            mode=overall_mode,
            owner=user,
            created_at=datetime.utcnow(),
            results_dir=folder_name,
            created_from_hackerone=True,
            platform="HackerOne"
        )
        db.add(project)
        db.commit()
        db.refresh(project)

        # add Target rows
        for typ, clean in cleaned_targets:
            tobj = Target(
                project_id=project.id,
                target=clean,
                type=typ,
                status="pending"
            )
            db.add(tobj)
        db.commit()

        # create scan state
        scan = ScanState(
            project_id=project.id,
            current_stage="Recon",
            status="running",
            progress=0
        )
        db.add(scan)
        db.commit()

        # Start background thread which first attempts to auto-expand domains into URL targets
        # using the exact manual-form behavior, then runs the normal run_scan worker.
        def run_scan_with_auto_expanded():
            try:
                logger.info("HACKERONE: auto-expanded worker starting for project %s", project.id)

                # Build results_dir for temporary recon artifacts (same convention as manual flow)
                # Use the saved folder_name from outer scope; fallback to project.results_dir or id
                results_dir_path = os.path.join("results", folder_name) if folder_name else (os.path.join("results", project.results_dir) if project.results_dir else f"results/{project.id}")
                os.makedirs(results_dir_path, exist_ok=True)

                # Re-open a fresh DB session and eagerly load targets to avoid DetachedInstanceError
                db_worker = SessionLocal()
                try:
                    proj = (
                        db_worker.query(Project)
                        .options(selectinload(Project.targets))
                        .filter(Project.id == project.id)
                        .first()
                    )
                    if not proj:
                        logger.error("HACKERONE: project %s not found in worker session", project.id)
                        return

                    # Extract domain targets from the freshly-loaded instance
                    domain_list = [t.target for t in proj.targets if getattr(t, 'type', None) == 'domain']
                finally:
                    db_worker.close()

                if domain_list:
                    logger.info("HACKERONE: found %d domains to auto-expand for project %s", len(domain_list), project.id)

                    # replicate_manual_domain_behavior performs the same steps as the manual form
                    try:
                        created_any = replicate_manual_domain_behavior(project.id, domain_list, results_dir_path)
                        if created_any:
                            logger.info("HACKERONE: Auto-expanded created URL targets for project %s", project.id)
                        else:
                            logger.info("HACKERONE: Auto-expanded ran but no new URL targets were created for project %s", project.id)
                    except Exception as re:
                        logger.exception("HACKERONE: Error during auto-expanded replication for project %s: %s", project.id, re)
                else:
                    logger.info("HACKERONE: no domain targets to auto-expand for project %s", project.id)

                # Finally, run the standard scan worker which will pick up the newly created URL targets
                run_scan(project_id=project.id)
            except Exception:
                logger.exception("HACKERONE: Error in auto-expanded scan worker for project %s", project.id)

        # launch worker thread
        threading.Thread(target=run_scan_with_auto_expanded, daemon=True).start()

        logger.info("Started imported-scope background scan for project %s with AUTO-EXPANDED", project.id)
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()



@router.post("/scan", response_class=HTMLResponse)
async def start_scan(request: Request):
    """
    Endpoint genérico que acepta el form con campos:
      - handle (program handle)
      - name (program name)
      - targets (múltiples valores)
    Crea Project / Targets / ScanState y lanza run_scan.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=302)

    form = await request.form()
    program_handle = str(form.get("handle") or "")
    program_name = str(form.get("name") or program_handle)

    if hasattr(form, "getlist"):
        targets = form.getlist("targets")
    else:
        targets = [v for k, v in form.multi_items() if k == "targets"] if hasattr(form, "multi_items") else []

    logger.info("Received scan request for program=%s, targets=%d", program_handle, len(targets))

    if not targets:
        return templates.TemplateResponse("import.html", {
            "request": request,
            "programs": [],
            "selected_program": None,
            "error": "No targets selected"
        })

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        safe_target = get_safe_name_from_target(targets[0])
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        folder_name = f"{safe_target}_{timestamp}"

        # create project
        project = Project(
            name=program_name,
            program=program_handle,
            target=targets[0],
            mode="domain" if all(classify_identifier(t) == "domain" for t in targets) else "url",
            owner=user,
            created_at=datetime.utcnow(),
            results_dir=folder_name
        )
        db.add(project)
        db.commit()
        db.refresh(project)

        # add Target rows
        for t in targets:
            typ = classify_identifier(t)
            clean = normalize_identifier(t, typ)
            tobj = Target(
                project_id=project.id,
                target=clean,
                type=typ,
                status="pending"
            )
            db.add(tobj)
        db.commit()

        # create scan state
        scan = ScanState(
            project_id=project.id,
            current_stage="Recon",
            status="running",
            progress=0
        )
        db.add(scan)
        db.commit()

        # AUTO-EXPANDED MODE: Launch individual scans for all URL targets
        url_targets = db.query(Target).filter(
            Target.project_id == project_id,
            Target.type == "url", 
            Target.status == "pending"
        ).all()
        
        if url_targets:
            print(f"[🚀] AUTO-EXPANDED MODE: Launching individual scans for {len(url_targets)} URL targets")
            
            # Import here to avoid circular imports
            from backend.scan_worker import run_scan_target
            import threading
            import time
            
            for url_target in url_targets:
                target_url = url_target.target
                print(f"[🎯] Launching individual scan for URL: {target_url}")
                
                # Launch scan in separate thread for each URL target
                threading.Thread(
                    target=run_scan_target,
                    args=(project_id, target_url),
                    kwargs={
                        'project_mode': 'url',
                        'project_platform': 'HackerOne'
                    },
                    daemon=True
                ).start()
                
                time.sleep(3)  # Pause between launches to avoid resource conflicts
            
            print(f"[✅] HackerOne AUTO-EXPANDED: {len(url_targets)} individual URL scans launched")
        
        # start background scan
        threading.Thread(target=run_scan, kwargs=dict(project_id=project.id), daemon=True).start()

        logger.info("Started background scan for project %s", project.id)
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()


@router.post("/hackerone/scan")
async def scan_selected(request: Request):
    form = await request.form()
    selected = form.getlist("target")
    program = form.get("program")

    db = SessionLocal()
    new_project = Project(
        name=f"{program}_Scan",
        target=",".join(selected),
        mode="url" if selected[0].startswith("http") else "domain",
        program=program,
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    run_scan(new_project.id, new_project.target, new_project.mode)
    db.close()

    return RedirectResponse(url="/", status_code=303)


@router.post("/hackerone/scan_all")
async def scan_entire_scope(program: str = Form(...)):
    async with httpx.AsyncClient() as client:
        r = await client.get(HACKERONE_DATA_URL)
        data = r.json()

    selected_program = next((p for p in data if p["handle"] == program), None)
    if not selected_program:
        return JSONResponse(content={"error": "Programa no encontrado"}, status_code=404)

    in_scope = selected_program.get("targets", {}).get("in_scope", [])
    targets = [t["asset_identifier"] for t in in_scope]
    target_mode = "url" if any(t.startswith("http") for t in targets) else "domain"

    db = SessionLocal()
    new_project = Project(
        name=f"{program}_FullScope",
        target=",".join(targets),
        mode=target_mode,
        program=program,
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    run_scan(new_project.id, new_project.target, new_project.mode)
    db.close()

    return RedirectResponse(url="/", status_code=303)        



@router.get("/dashboard_data")
def get_dashboard_data(db: Session = Depends(get_db)):
    programs = db.query(BountyProgram).all()
    result = []

    for program in programs:
        result.append({
            "program_id": program.id,
            "program_name": program.name,
            "platform": program.platform.name,
            "icon": program.platform.icon,
            "scans": [
                {
                    "id": scan.id,
                    "type": scan.type,
                    "target": scan.target,
                    "date": scan.date.strftime("%Y-%m-%d"),
                    "status": scan.status,
                    "progress": scan.progress
                }
                for scan in program.scans
            ]
        })
    return result