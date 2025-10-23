# utils/hackerone.py
# Helper to fetch and normalize the arkadiyt bounty-targets-data hackerone json.
import requests
from typing import List, Dict, Any

RAW_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/hackerone_data.json"
TIMEOUT = 15

def fetch_raw() -> List[Dict[str, Any]]:
    """Download raw JSON from the repo. Return empty list on error."""
    try:
        r = requests.get(RAW_URL, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json().get("programs", r.json()) if isinstance(r.json(), dict) else r.json()
    except Exception:
        return []

def normalize_program(p: Dict[str, Any]) -> Dict[str, Any]:
    """Return a normalized program dict with name, handle and in_scope list."""
    name = p.get("name") or p.get("handle") or "Unknown"
    handle = p.get("handle") or p.get("url") or name
    targets = []
    # Some variations in structure: try known keys
    in_scope = p.get("targets", {}).get("in_scope") if isinstance(p.get("targets"), dict) else p.get("in_scope") or []
    if not in_scope and isinstance(p.get("targets"), list):
        in_scope = p.get("targets")
    if not in_scope:
        # fallback: maybe p has 'in_scope' directly
        in_scope = p.get("in_scope", []) or []
    for t in in_scope:
        # asset could be object with 'asset_identifier' or 'identifier'
        identifier = t.get("asset_identifier") or t.get("identifier") or t.get("asset") or t.get("asset_identifier")
        if not identifier:
            continue
        asset_type = (t.get("asset_type") or t.get("type") or "OTHER").upper()
        targets.append({
            "original": identifier,
            "identifier": identifier,
            "type": "URL" if identifier.startswith(("http://","https://","//","www.")) else "DOMAIN",
            "eligibility": t.get("eligible_for_submission", False) or t.get("eligibility", False)
        })
    # counts
    domain_count = sum(1 for x in targets if x["type"] == "DOMAIN")
    url_count = sum(1 for x in targets if x["type"] == "URL")
    return {
        "name": name,
        "handle": handle,
        "raw": p,
        "targets": targets,
        "domain_count": domain_count,
        "url_count": url_count,
        "total": len(targets)
    }

def get_hackerone_programs() -> List[Dict[str, Any]]:
    raw = fetch_raw()
    out = []
    for p in raw:
        try:
            out.append(normalize_program(p))
        except Exception:
            continue
    # sort by name
    out_sorted = sorted(out, key=lambda x: (x.get("name") or "").lower())
    return out_sorted

def get_program_by_handle(handle: str):
    progs = get_hackerone_programs()
    for p in progs:
        if p.get("handle") == handle or p.get("name") == handle:
            return p
    return None