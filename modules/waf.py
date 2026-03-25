import os
import re
import subprocess
from termcolor import cprint

OUT_FILE = "waf_detected.txt"

# ANSI sequences (wafw00f / rich)
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b\][^\x1b\\]*\\\x1c")


def _strip_ansi(text: str) -> str:
    if not text:
        return ""
    return _ANSI_RE.sub("", text)


def _scrub_waf_noise(text: str) -> str:
    """Remove Python/requests noise from captured wafw00f stderr/stdout."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s and not line:
            out.append("")
            continue
        if "RequestsDependencyWarning" in line:
            continue
        if "warnings.warn(" in line:
            continue
        if "site-packages/requests/" in line:
            continue
        if "site-packages/urllib3/" in line:
            continue
        if "doesn't match a supported version" in line:
            continue
        if s.startswith("Traceback (most recent call last):"):
            continue
        if re.match(r'^\s*File "[^"]+", line \d+', line):
            continue
        if re.match(r"^\s*\^+\s*$", line):
            continue
        out.append(line)
    # Collapse excessive blank lines
    collapsed = []
    blank_run = 0
    for line in out:
        if not line.strip():
            blank_run += 1
            if blank_run <= 1:
                collapsed.append(line)
        else:
            blank_run = 0
            collapsed.append(line)
    return "\n".join(collapsed).strip()


def _trim_waf_banner(text: str) -> str:
    """Drop wafw00f ASCII banner when present; keep from the check line onward."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "[*] Checking" in line:
            return "\n".join(lines[i:]).strip()
        if line.strip().startswith("[+] The site ") and "is behind" in line:
            return "\n".join(lines[i:]).strip()
        if line.strip().startswith("[+] Generic Detection"):
            return "\n".join(lines[i:]).strip()
        if "ERROR:wafw00f:" in line or "ERROR: wafw00f:" in line:
            return "\n".join(lines[i:]).strip()
    return text.strip()


def _format_waf_block_for_file(raw: str) -> str:
    clean = _strip_ansi(raw)
    clean = _scrub_waf_noise(clean)
    clean = _trim_waf_banner(clean)
    return clean


def _extract_verdict(clean_output: str) -> str:
    """Single-line verdict for the summary table."""
    low = clean_output.lower()
    if "appears to be down" in low or "site appears to be down" in low:
        return "Host down or unreachable (wafw00f)"
    if "network is unreachable" in low:
        return "Network unreachable"
    if "max retries exceeded" in low or "failed to establish a new connection" in low:
        return "Connection failed"
    if "connection refused" in low:
        return "Connection refused"
    if "name or service not known" in low or "failed to resolve" in low:
        return "DNS resolution failed"
    if "timed out" in low or "timeout" in low:
        return "Timeout / no response"
    if "error:wafw00f" in low.replace(" ", ""):
        for line in reversed(clean_output.splitlines()):
            if "error:wafw00f" in line.lower().replace(" ", ""):
                return line.strip()[:220]

    for line in reversed(clean_output.splitlines()):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        l = s.lower()
        if "is behind" in l and "waf" in l:
            return s[:220]
        if "seems to be behind" in l:
            return s[:220]
        if "no waf detected" in l:
            return "No WAF (generic detection)"
    return "Inconclusive"


def _normalize_scan_url(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    token = line.split()[0]
    if token.startswith(("http://", "https://")):
        return token
    return f"https://{token}"


def _run_wafw00f(url: str) -> str:
    try:
        env = {
            **os.environ,
            "NO_COLOR": "1",
            "TERM": "dumb",
            "PYTHONWARNINGS": "ignore",
        }
        r = subprocess.run(
            ["wafw00f", url],
            capture_output=True,
            text=True,
            timeout=180,
            errors="replace",
            env=env,
        )
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        combined = "\n".join(x for x in (out, err) if x)
        combined = _format_waf_block_for_file(combined)
        return combined if combined else f"[wafw00f exit {r.returncode}, no output]"
    except FileNotFoundError:
        return "[error] wafw00f not found in PATH (pip install wafw00f)"
    except subprocess.TimeoutExpired:
        return "[error] wafw00f: timed out"
    except Exception as e:
        return f"[error] wafw00f: {e}"


def _output_indicates_waf(text: str) -> bool:
    low = text.lower()
    if "no waf detected" in low:
        return False
    if "appears to be down" in low or "network is unreachable" in low:
        return False
    if "max retries exceeded" in low or "failed to establish a new connection" in low:
        return False
    if "connection refused" in low or "name or service not known" in low:
        return False
    if "error:wafw00f" in low.replace(" ", "") and "is behind" not in low and "seems to be behind" not in low:
        return False
    return (
        "is behind" in low
        or "behind a waf" in low
        or "seems to be behind" in low
    )


def _remove_legacy_waf_txt(result_dir: str) -> None:
    legacy = os.path.join(result_dir, "waf.txt")
    if os.path.isfile(legacy):
        try:
            os.remove(legacy)
        except OSError:
            pass


def run_waf(live_file, result_dir, log_file):
    cprint("[*] WAF detection on live hosts...", "blue")
    os.makedirs(result_dir, exist_ok=True)
    _remove_legacy_waf_txt(result_dir)

    out_path = os.path.join(result_dir, OUT_FILE)
    detected = 0
    detail_blocks = []
    summary_rows = []

    if not os.path.exists(live_file):
        cprint(f"[!] Live file not found: {live_file}. Creating an empty file.", "yellow")
        os.makedirs(os.path.dirname(live_file) or ".", exist_ok=True)
        with open(live_file, "w"):
            pass

    if os.path.getsize(live_file) == 0:
        cprint(f"[!] Live file is empty: {live_file}. Skipping WAF detection.", "yellow")
        with open(out_path, "w", encoding="utf-8") as wf:
            wf.write(
                "# WAF Detection (wafw00f)\n"
                f"# Empty live file: {live_file}\n"
                "No hosts were scanned.\n"
            )
        return

    with open(live_file, encoding="utf-8", errors="ignore") as f:
        lines = [ln for ln in f if ln.strip()]

    for line in lines:
        scan_url = _normalize_scan_url(line)
        if not scan_url:
            continue
        cprint(f"[-] WAF scan: {scan_url}", "yellow")
        try:
            output = _run_wafw00f(scan_url)
            verdict = _extract_verdict(output)
            behind = _output_indicates_waf(output)
            summary_rows.append((scan_url, verdict, behind))
            detail_blocks.append(
                f"{'=' * 60}\nURL: {scan_url}\n{'-' * 60}\n{output}\n"
            )
            if behind:
                detected += 1
                cprint(f"[!] WAF detected: {scan_url}", "red")
        except Exception as e:
            cprint(f"[✘] WAF error for {line.strip()}: {e}", "red")
            summary_rows.append((scan_url, f"Error: {e}", False))
            detail_blocks.append(f"{'=' * 60}\nURL: {scan_url}\n[exception] {e}\n")

    with open(out_path, "w", encoding="utf-8") as wf:
        wf.write(
            "# WAF Detection (wafw00f)\n"
            "# Single report file (no separate waf.txt).\n"
            "# Section 1: summary — URL, verdict, behind_waf=yes|no\n"
            "# Section 2: raw wafw00f output per host (one run per live host).\n\n"
        )
        wf.write("=" * 60 + "\n")
        wf.write("# Summary (tab-separated)\n")
        wf.write("# URL<TAB>verdict<TAB>behind_waf=yes|no\n")
        wf.write("=" * 60 + "\n")
        if summary_rows:
            for url, verdict, behind in summary_rows:
                b = "yes" if behind else "no"
                wf.write(f"{url}\t{verdict}\tbehind_waf={b}\n")
        else:
            wf.write("(No valid URLs in the live file.)\n")

        wf.write("\n" + "=" * 60 + "\n")
        wf.write("# Details (wafw00f output per host)\n")
        wf.write("=" * 60 + "\n\n")
        if detail_blocks:
            wf.write("".join(detail_blocks))
        elif not summary_rows:
            wf.write("(No scans run.)\n")

    if detected == 0:
        cprint("[✓] No WAF detected on scanned hosts.", "green")
    else:
        cprint(f"[✓] WAF detected on {detected} host(s).", "red")


def run_waf_pipeline_step(live_file, result_dir, log_file, min_existing_bytes=80):
    """
    Dashboard/worker 'WAF Detection' step.
    If recon already wrote waf_detected.txt, skip a second wafw00f pass.
    """
    path = os.path.join(result_dir, OUT_FILE)
    if os.path.isfile(path) and os.path.getsize(path) >= min_existing_bytes:
        cprint(
            "[ℹ] WAF (pipeline): waf_detected.txt already present from recon; skipping duplicate run.",
            "blue",
        )
        return
    run_waf(live_file, result_dir, log_file)


run_waf_detection = run_waf


if __name__ == "__main__":
    import sys

    live_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_waf(live_file, result_dir, log_file)
