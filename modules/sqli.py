import os
import re
import subprocess

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def extract_parameter(url):
    if '?' in url:
        query = url.split('?', 1)[-1]
        params = query.split('&')
        if params:
            return params[0].split('=')[0]
    return "desconocido"

def extract_payload_and_evidence(sqlmap_output):
    payload_match = re.search(r"parameter '(.+?)' is vulnerable", sqlmap_output, re.IGNORECASE)
    payload = payload_match.group(1) if payload_match else "No detectado"

    # Buscamos evidencia de DBMS, user o DBs
    evidence_lines = []
    for line in sqlmap_output.splitlines():
        if any(kw in line.lower() for kw in ['dbms', 'user', 'database', 'available', 'web application']):
            evidence_lines.append(line.strip())

    return payload, "\n".join(evidence_lines).strip()

def run_sqli_scan(param_urls_file, result_dir, log_file):
    if not os.path.exists(param_urls_file):
        print(f"{RED}[✘] Archivo de URLs no encontrado: {param_urls_file}{RESET}")
        return None

    sqlmap_dir = os.path.join(result_dir, "sqlmap")
    os.makedirs(sqlmap_dir, exist_ok=True)

    sqli_file = os.path.join(result_dir, "sql_vulnerables.txt")

    with open(param_urls_file, "r") as urls, open(sqli_file, "w") as vuln_out, open(log_file, "a") as log_out:
        urls_list = [u.strip() for u in urls if u.strip()]
        total = len(urls_list)

        for idx, url in enumerate(urls_list, start=1):
            print(f"{BLUE}[SQLMap {idx}/{total}] Analizando: {url}{RESET}")
            try:
                output = subprocess.check_output(
                    [
                        "sqlmap", "-u", url,
                        "--batch", "--level=3", "--risk=2",
                        "--random-agent", "--dbs", "--current-user",
                        "--output-dir", sqlmap_dir
                    ],
                    stderr=subprocess.STDOUT,
                    timeout=120
                ).decode(errors="ignore")

                log_out.write(f"\n[SQLI] {url}\n{output}\n")

                if "is vulnerable" in output.lower() or "sql injection" in output.lower():
                    param = extract_parameter(url)
                    payload, evidence = extract_payload_and_evidence(output)

                    vuln_out.write(f"🔗 URL: {url}\n")
                    vuln_out.write(f"🧩 Parámetro afectado: {param}\n")
                    vuln_out.write(f"🎯 Payload: {payload}\n")
                    vuln_out.write(f"🧾 Evidencia:\n{evidence}\n")
                    vuln_out.write("-" * 50 + "\n\n")

            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[!] Timeout SQLMap para: {url}{RESET}")
            except Exception as e:
                print(f"{RED}[✘] Error en SQLMap para: {url}: {e}{RESET}")

    return sqli_file


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_sqli_scan(param_urls_file, result_dir, log_file)