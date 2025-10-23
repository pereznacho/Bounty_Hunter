# backend/hackerone_import.py

import requests
from backend.models import SessionLocal, Project, Target
from datetime import datetime

HACKERONE_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/hackerone_data.json"

def import_hackerone_programs():
    response = requests.get(HACKERONE_URL)
    if response.status_code != 200:
        raise Exception("Failed to fetch HackerOne data")

    data = response.json()
    db = SessionLocal()

    for program in data:
        name = program.get("program_name")
        if not name:
            continue

        existing = db.query(Project).filter(Project.name == name, Project.source == "HackerOne").first()
        if existing:
            continue

        new_project = Project(
            name=name,
            created_at=datetime.utcnow(),
            status="NOT_STARTED",
            source="HackerOne"
        )
        db.add(new_project)
        db.commit()
        db.refresh(new_project)

        for target in program.get("targets", []):
            if not target.get("endpoint"):
                continue
            new_target = Target(
                project_id=new_project.id,
                type=target.get("type", "unknown"),
                scope=target.get("endpoint"),
                in_scope=target.get("in_scope", True)
            )
            db.add(new_target)

        db.commit()
    db.close()