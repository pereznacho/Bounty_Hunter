# backend/routers/intigriti.py

from fastapi import APIRouter, Request, HTTPException, Form, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from typing import List, Dict
from datetime import datetime
import requests
import logging
import os
import threading as threading_mod
import re

from backend.models import SessionLocal, Project, Target, ScanState, User
from backend.scan_worker import run_scan
from modules.recon import replicate_manual_domain_behavior
from backend.database import get_db
from backend.auth import get_current_user
from utils.path_utils import get_safe_name_from_target
from sqlalchemy.orm import Session, selectinload

router = APIRouter(prefix="/import/intigriti", tags=["intigriti"])
templates = Jinja2Templates(directory="templates")

INTIGRITI_DATA_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/intigriti_data.json"

logger = logging.getLogger("intigriti")

# Regular expressions for classification
DOMAIN_LIKE_RE = re.compile(r"^(\*\.|)([a-z0-9\-\_]+\.[a-z]{2,}(?:\.[a-z]{2,})?)$", re.IGNORECASE)
URL_LIKE_RE = re.compile(r"^(https?:\/\/|www\.)", re.IGNORECASE)

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

def fetch_intigriti_programs() -> List[Dict]:
    resp = requests.get(INTIGRITI_DATA_URL, timeout=10)
    resp.raise_for_status()
    return resp.json()

@router.get("/", response_class=HTMLResponse)
async def list_intigriti_programs(request: Request):
    try:
        programs = fetch_intigriti_programs()
    except Exception:
        logger.exception("Error fetching Intigriti programs")
        return templates.TemplateResponse("intigriti_list.html", {
            "request": request,
            "programs": []
        })

    simplified_programs = []
    for p in programs:
        in_scope = p.get("targets", {}).get("in_scope", [])
        domains_c = 0
        urls_c = 0
        normalized_in_scope = []

        for t in in_scope:
            endpoint = t.get("endpoint") or t.get("target") or t.get("url")
            if not endpoint:
                continue
            if endpoint.startswith("http://") or endpoint.startswith("https://"):
                urls_c += 1
                typ = "url"
            else:
                domains_c += 1
                typ = "domain"
            normalized_in_scope.append({
                "original": endpoint,
                "type": typ,
                "eligible": t.get("eligible_for_bounty", False)
            })

        # Determine if program offers bounties based on min_bounty value
        min_bounty = p.get("min_bounty", {})
        offers_bounties = min_bounty.get("value", 0) > 0
        
        simplified_programs.append({
            "id": p.get("id"),
            "name": p.get("name") or "Unnamed",
            "handle": p.get("handle") or (p.get("name", "").lower().replace(" ", "-")),
            "offers_bounties": offers_bounties,
            "in_scope": normalized_in_scope,
            "domains_count": domains_c,
            "urls_count": urls_c
        })

    simplified_programs = sorted(simplified_programs, key=lambda x: (x["name"] or "").lower())

    return templates.TemplateResponse("intigriti_list.html", {
        "request": request,
        "programs": simplified_programs
    })



@router.get("/program/{handle}", response_class=HTMLResponse)
async def intigriti_program_detail(request: Request, handle: str):
    try:
        programs = fetch_intigriti_programs()
    except Exception:
        logger.exception("Error fetching Intigriti programs")
        return templates.TemplateResponse("intigriti_list.html", {
            "request": request,
            "selected_program": None,
            "programs": [],
            "api_error": "Could not load program data"
        })

    selected_program = next((p for p in programs if p.get("handle") == handle), None)

    if not selected_program:
        return templates.TemplateResponse("intigriti_list.html", {
            "request": request,
            "selected_program": None,
            "programs": [],
            "api_error": f"Program '{handle}' not found"
        })

    # Normalizar los targets
    in_scope = selected_program.get("targets", {}).get("in_scope", [])
    filtered_targets = []
    domains = urls = eligible = 0

    for t in in_scope:
        identifier = t.get("endpoint") or t.get("target") or t.get("url")
        if not identifier:
            continue

        typ = "url" if identifier.startswith("http://") or identifier.startswith("https://") else "domain"
        if typ == "url": urls += 1
        else: domains += 1
        if t.get("eligible_for_bounty"): eligible += 1

        # Extract and normalize severity/criticality
        severity_raw = (t.get("max_severity") or t.get("severity") or t.get("impact") or "").strip().lower()
        valid_severities = ["low", "medium", "high", "critical"]
        severity = severity_raw if severity_raw in valid_severities else "none"

        filtered_targets.append({
            "type": typ,
            "identifier": identifier,
            "eligibility": t.get("eligible_for_bounty", False),
            "severity": severity
        })

    selected_program["filtered_targets"] = filtered_targets
    selected_program["summary"] = {
        "total": len(filtered_targets),
        "domains": domains,
        "urls": urls,
        "eligible": eligible
    }

    # Crear un objeto programa simplificado para coincidir con el formato esperado
    simplified_program = {
        "name": selected_program.get("name", "Unnamed"),
        "handle": selected_program.get("handle", ""),
        "url": selected_program.get("url", ""),
        "domains_count": domains,  # Usar los contadores calculados directamente
        "urls_count": urls,
        "filtered_targets": filtered_targets
    }

    return templates.TemplateResponse("intigriti_list.html", {
        "request": request,
        "selected_program": simplified_program,
        "programs": []
    })

@router.post("/scan", response_class=HTMLResponse)
async def start_scan_from_intigriti(request: Request):
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

    logger.info("Import scan request for Intigriti program=%s targets=%d", program_handle, len(targets))

    if not targets:
        return templates.TemplateResponse("intigriti_list.html", {
            "request": request,
            "programs": [],
            "selected_program": None,
            "api_error": "No targets selected"
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
            created_from_intigriti=True,
            platform="Intigriti"
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

        # 🎯 AUTO-EXPANDED MODE: Create URL targets like manual form BEFORE scanning
        def run_scan_with_auto_expanded():
            try:
                logger.info("INTIGRITI: auto-expanded worker starting for project %s", project.id)

                # Build a stable results dir path (same convention as manual flow)
                # Prefer the project's stored results_dir folder; fall back to name-based dir.
                results_dir_folder = project.results_dir or f"{get_safe_name_from_target(project.name)}"
                results_dir_path = os.path.join("results", results_dir_folder)
                os.makedirs(results_dir_path, exist_ok=True)

                # Re-open a new DB session in this thread and eager-load targets
                db_thread = SessionLocal()
                try:
                    reloaded = (
                        db_thread.query(Project)
                        .options(selectinload(Project.targets))
                        .filter(Project.id == project.id)
                        .first()
                    )
                    if not reloaded:
                        logger.warning("INTIGRITI: project %s not found when reloading in worker", project.id)
                        run_scan(project_id=project.id)
                        return

                    # Extract only domain-type targets; replicate manual behavior on them
                    domain_list = [t.target for t in reloaded.targets if getattr(t, "type", None) == "domain"]
                    if domain_list:
                        logger.info("INTIGRITI: found %d domains to auto-expand for project %s", len(domain_list), project.id)
                        try:
                            created_any = replicate_manual_domain_behavior(project.id, domain_list, results_dir_path)
                            if created_any:
                                logger.info("INTIGRITI: Auto-expanded created URL targets for project %s", project.id)
                            else:
                                logger.info("INTIGRITI: Auto-expanded ran but no new URL targets were created for project %s", project.id)
                        except Exception as re:
                            logger.exception("INTIGRITI: Error during auto-expanded replication for project %s: %s", project.id, re)
                    else:
                        logger.info("INTIGRITI: no domain targets to auto-expand for project %s", project.id)
                finally:
                    try:
                        db_thread.close()
                    except Exception:
                        pass

                # Continue with the normal scan which will pick up the newly created URL targets
                run_scan(project_id=project.id)
            except Exception:
                logger.exception("INTIGRITI: Error in auto-expanded scan worker for project %s", project.id)
        
        # start background thread with auto-expanded logic
        threading_mod.Thread(target=run_scan_with_auto_expanded, daemon=True).start()
        logger.info("Started imported-scope background scan for Intigriti project %s with AUTO-EXPANDED", project.id)
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()
    
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
                    'project_platform': 'Intigriti'
                },
                daemon=True
            ).start()
            
            time.sleep(3)  # Pause between launches to avoid resource conflicts
        
        print(f"[✅] Intigriti AUTO-EXPANDED: {len(url_targets)} individual URL scans launched")