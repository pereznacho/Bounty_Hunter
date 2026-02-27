# modules/dir_discovery.py
# Directory & Files discovery using dirb (recursive), gobuster and dirsearch.
# Results from all three tools are consolidated into a single file with full attribution.

import os
import re
import subprocess

# Wordlist: SecLists common then dirb common
WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

# Dirb recurses by default; use timeout large enough for recursive scan
DIRB_TIMEOUT = 600
GOBUSTER_TIMEOUT = 300
DIRSEARCH_TIMEOUT = 300

# Extract any http(s) URL from a line (fallback when format varies)
_URL_RE = re.compile(r"https?://[^\s\)\]\|>\"]+")


def _get_wordlist():
    for w in WORDLISTS:
        if os.path.isfile(w):
            return w
    return None


def _normalize_base_url(target):
    """Ensure target has protocol and trailing slash for directory scan."""
    u = (target or "").strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u.rstrip("/") + "/"


def _is_4xx_warning_line(line):
    """True si la línea es un aviso de dirb sobre códigos 4xx (403, etc.)."""
    t = (line or "").strip()
    if "WARNING" not in t and "(!)" not in t:
        return False
    return "CODE =" in t and "40" in t  # CODE = 403, CODE = 400, etc.


def _extract_urls_from_line(line, base_url):
    """Extract all URLs from a line; normalize relative paths with base_url."""
    seen = set()
    for m in _URL_RE.finditer(line):
        u = m.group(0).rstrip("/")
        # strip trailing punctuation that regex might have included
        for suf in (")", "]", "|", ">", '"', "'", ","):
            if u.endswith(suf):
                u = u[:-1].rstrip("/")
        if u and u not in seen:
            seen.add(u)
            yield u


def _run_dirb(base_url, wordlist, result_dir, timeout=DIRB_TIMEOUT, exclude_status_4xx=False):
    """
    Run dirb (recursive by default: it iterates into each discovered directory).
    Returns list of (url, status_or_type) for consolidation.
    """
    out_name = "_dirb_out.txt"
    out_file = os.path.join(result_dir, out_name)
    found = []
    try:
        # -w: don't stop on WARNING (e.g. "All responses CODE=403" from WAF)
        # -N: ignore these HTTP codes (400-499 when exclude_status_4xx)
        cmd = ["dirb", base_url, wordlist, "-o", out_name, "-w"]
        if exclude_status_4xx:
            cmd.extend(["-N", ",".join(str(c) for c in range(400, 500))])
        r = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=result_dir,
            text=True,
        )
        if r.returncode != 0 and r.stderr:
            # No mostrar mensajes de códigos 4xx (403, etc.) al usuario
            stderr_lines = [ln for ln in r.stderr.splitlines() if not _is_4xx_warning_line(ln)]
            if stderr_lines:
                msg = " ".join(stderr_lines)[:200]
                print(f"[dir_discovery] dirb stderr: {msg}")
        # Dirb may write to -o filename in cwd; also check any _dirb* file in result_dir
        dirb_files = [out_file]
        try:
            for name in os.listdir(result_dir):
                if name.startswith("_dirb") or (name.endswith(".txt") and "dirb" in name.lower()):
                    dirb_files.append(os.path.join(result_dir, name))
            dirb_files = list(dict.fromkeys(dirb_files))
        except OSError:
            pass
        for out_path in dirb_files:
            if not os.path.isfile(out_path):
                continue
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # ==>> DIRECTORY: http://... or DIRECTORY: http://...
                    if "DIRECTORY:" in line:
                        for u in _extract_urls_from_line(line, base_url):
                            found.append((u, "dirb DIRECTORY"))
                        continue
                    # + http://... (CODE:200) or (CODE:200|SIZE:1234)
                    if "+ " in line and "CODE:" in line:
                        m = re.search(r"\+\s+(https?://[^\s]+)\s*\(CODE:(\d+)", line)
                        if m:
                            code = int(m.group(2))
                            if exclude_status_4xx and 400 <= code < 500:
                                continue
                            found.append((m.group(1).rstrip("/"), f"dirb CODE:{m.group(2)}"))
                        else:
                            for u in _extract_urls_from_line(line, base_url):
                                found.append((u, "dirb"))
                        continue
                    # Fallback: any URL in line (no code parsed; include only if not filtering)
                    if exclude_status_4xx and "CODE:4" in line:
                        continue
                    for u in _extract_urls_from_line(line, base_url):
                        if base_url.rstrip("/") in u:
                            found.append((u, "dirb"))
        # Reescribir el archivo principal sin líneas de aviso 4xx para que no se vean al abrirlo
        if exclude_status_4xx and os.path.isfile(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                    all_lines = f.readlines()
                kept = [ln for ln in all_lines if not _is_4xx_warning_line(ln)]
                if len(kept) < len(all_lines):
                    with open(out_file, "w", encoding="utf-8") as f:
                        f.writelines(kept)
            except OSError:
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[dir_discovery] dirb skip: {e}")
    return found


def _run_gobuster(base_url, wordlist, result_dir, timeout=GOBUSTER_TIMEOUT, exclude_status_4xx=False):
    """Run gobuster dir; returns list of (url, info)."""
    out_file = os.path.join(result_dir, "_gobuster_out.txt")
    found = []
    try:
        cmd = [
            "gobuster", "dir", "-u", base_url,
            "-w", wordlist,
            "-q", "--no-error",
            "-t", "20",
            "-o", out_file,
        ]
        if exclude_status_4xx:
            blacklist = ",".join(str(c) for c in range(400, 500))
            cmd.extend(["-b", blacklist])
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        if os.path.isfile(out_file):
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    url = None
                    info = "gobuster"
                    if line.startswith("http"):
                        url = line.rstrip("/")
                    elif line.startswith("/"):
                        path = line.split()[0] if line.split() else line
                        url = (base_url.rstrip("/") + path).rstrip("/")
                    else:
                        idx = line.find(" (Status:")
                        if idx > 0:
                            path = line[:idx].strip()
                            redir = re.search(r"\[-->\s*(\S+)\]", line)
                            if redir:
                                url = redir.group(1).rstrip("/")
                            else:
                                base = base_url.rstrip("/")
                                url = (base + "/" + path.lstrip("/")).rstrip("/") if not path.startswith("http") else path.rstrip("/")
                            status = re.search(r"Status:\s*(\d+)", line)
                            if status:
                                info = f"gobuster Status:{status.group(1)}"
                    if url:
                        found.append((url, info))
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[dir_discovery] gobuster skip: {e}")
    return found


def _run_dirsearch(base_url, result_dir, timeout=DIRSEARCH_TIMEOUT, exclude_status_4xx=False):
    """Run dirsearch; returns list of (url, info)."""
    out_file = os.path.join(result_dir, "_dirsearch_out.txt")
    found = []
    try:
        cmd = [
            "dirsearch", "-u", base_url,
            "-e", "php,html,js,txt,asp,aspx,jsp",
            "-q", "--format=plain",
            "-o", out_file,
        ]
        if exclude_status_4xx:
            cmd.extend(["-x", "400-499"])
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=result_dir, text=True)
        if r.returncode != 0 and r.stderr:
            print(f"[dir_discovery] dirsearch stderr: {r.stderr[:200]}")
        # Pip dirsearch may write to -o as file or as dir; also check reports/ subdir
        to_read = list({out_file})
        try:
            for name in os.listdir(result_dir):
                if name.startswith("_dirsearch") or name.endswith(".plain") or (name.endswith(".txt") and "dirsearch" in name.lower()):
                    to_read.append(os.path.join(result_dir, name))
            reports_dir = os.path.join(result_dir, "reports")
            if os.path.isdir(reports_dir):
                for f in os.listdir(reports_dir):
                    if f.endswith(".txt") or ".plain" in f or "dirsearch" in f.lower():
                        to_read.append(os.path.join(reports_dir, f))
        except OSError:
            pass
        to_read = list(dict.fromkeys(to_read))
        for fp in to_read:
            if not os.path.isfile(fp):
                continue
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    url = None
                    if line.startswith("http"):
                        url = (line.split()[0] if line.split() else line).rstrip("/")
                    else:
                        idx = line.find(" (Status:")
                        if idx < 0:
                            idx = line.find(" ")
                        path_part = line[:idx].strip() if idx > 0 else line.split()[0] if line.split() else ""
                        if path_part.startswith("http"):
                            url = path_part.rstrip("/")
                        elif path_part.startswith("/"):
                            url = (base_url.rstrip("/") + path_part).rstrip("/")
                        elif path_part:
                            url = (base_url.rstrip("/") + "/" + path_part.lstrip("/")).rstrip("/")
                    if url:
                        found.append((url, "dirsearch"))
                    else:
                        for u in _extract_urls_from_line(line, base_url):
                            if base_url.rstrip("/") in u:
                                found.append((u, "dirsearch"))
                                break
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[dir_discovery] dirsearch skip: {e}")
    return found


def run_dir_discovery(target, result_dir, log_file=None, exclude_status_4xx=True):
    """
    Run dirb (recursive), gobuster and dirsearch against target URL.
    Consolidate ALL results into directory_and_files.txt with full attribution:
    - Which tool(s) found each URL
    - All discovered URLs from all three tools (dirb iterates directories; gobuster/dirsearch do not).
    """
    base_url = _normalize_base_url(target)
    wordlist = _get_wordlist()
    out_path = os.path.join(result_dir, "directory_and_files.txt")
    os.makedirs(result_dir, exist_ok=True)

    if not wordlist:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("# Directory & Files (dirb + gobuster + dirsearch)\n")
            f.write(f"# Target: {base_url}\n")
            f.write("# Wordlist not found; install SecLists or dirb wordlists.\n")
        print("[dir_discovery] No wordlist found; skipping.")
        return out_path

    print(f"[dir_discovery] Target: {base_url} wordlist: {wordlist} (dirb recursive, gobuster, dirsearch)")

    # Run all three tools
    dirb_list = _run_dirb(base_url, wordlist, result_dir, exclude_status_4xx=exclude_status_4xx)
    gob_list = _run_gobuster(base_url, wordlist, result_dir, exclude_status_4xx=exclude_status_4xx)
    dsearch_list = _run_dirsearch(base_url, result_dir, exclude_status_4xx=exclude_status_4xx)

    # Build URL -> set of (tool, info) for consolidation
    url_sources = {}
    for url, info in dirb_list:
        url_sources.setdefault(url, set()).add(("dirb", info))
    for url, info in gob_list:
        url_sources.setdefault(url, set()).add(("gobuster", info))
    for url, info in dsearch_list:
        url_sources.setdefault(url, set()).add(("dirsearch", info))

    # Write consolidated file with ALL information
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# Directory & Files — Consolidated (dirb recursive + gobuster + dirsearch)\n")
        f.write(f"# Target: {base_url}\n")
        f.write(f"# Dirb: {len(dirb_list)} | Gobuster: {len(gob_list)} | Dirsearch: {len(dsearch_list)} | Unique URLs: {len(url_sources)}\n\n")
        f.write("# --- Per-URL list (URL | tools that found it) ---\n\n")
        for url in sorted(url_sources.keys()):
            tools = url_sources[url]
            tool_tags = ",".join(sorted(f"{t[0]}" for t in tools))
            f.write(f"{url}  # {tool_tags}\n")
        f.write("\n# --- Unique URLs only (for pipelines) ---\n\n")
        for url in sorted(url_sources.keys()):
            f.write(url + "\n")
    print(f"[dir_discovery] Dirb: {len(dirb_list)} | Gobuster: {len(gob_list)} | Dirsearch: {len(dsearch_list)} | Consolidated: {len(url_sources)} -> {out_path}")
    return out_path
