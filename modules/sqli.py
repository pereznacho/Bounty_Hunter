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
    """
    Extrae el parámetro detectado vulnerable (si aparece en mensajes tipo "parameter 'x' is vulnerable")
    y líneas de evidencia relevantes (DBMS, user, database, available, web application, current user, fetching database names).
    """
    payload_match = re.search(r"parameter '(.+?)' is vulnerable", sqlmap_output, re.IGNORECASE)
    payload = payload_match.group(1) if payload_match else "No detectado"

    evidence_lines = []
    for line in sqlmap_output.splitlines():
        low = line.lower()
        if any(kw in low for kw in ['dbms', 'user', 'database', 'available databases', 'web application', 'current user', 'fetching database names']):
            evidence_lines.append(line.rstrip())

    return payload, "\n".join(evidence_lines).strip()

def extract_dbs_block(sqlmap_output):
    """
    Intenta capturar el bloque que lista las bases de datos tras la línea 'available databases [N]:'
    Si no encuentra nada, devuelve cadena vacía.
    """
    lines = sqlmap_output.splitlines()
    dbs_text = []
    for i, line in enumerate(lines):
        if re.search(r"available databases\s*\[\d+\]\s*:", line, re.IGNORECASE):
            # tomar las siguientes líneas hasta encontrar una línea que parezca un log con [INFO] o vacía o hasta 20 líneas
            j = i + 1
            while j < len(lines) and len(dbs_text) < 20:
                nxt = lines[j].strip()
                # si la línea empieza con algo que parezca timestamp/log, rompemos
                if re.match(r"^\[?\d{2}[:\-]\d{2}[:\d{2}].*", nxt) or re.match(r"^\[.*(info|warning|error|critical).*", nxt, re.IGNORECASE):
                    break
                if nxt == "":
                    break
                dbs_text.append(nxt)
                j += 1
            break

    # como fallback, intentar patrones alternativos
    if not dbs_text:
        # a veces sqlmap muestra: "available databases [2]:\n[*] information_schema\n[*] mysql"
        dbs = re.findall(r"^\s*[\*\-\[]*\s*([a-zA-Z0-9_\-]+)\s*$", sqlmap_output, re.MULTILINE)
        # filtrar nombres triviales (evitar líneas de logs)
        filtered = [d for d in dbs if len(d) <= 100 and not re.search(r'\d{2}:\d{2}', d)]
        if filtered:
            return "\n".join(filtered)
        return ""
    return "\n".join(dbs_text).strip()

def run_sqli_scan(param_urls_file, result_dir, log_file):
    sqli_file = os.path.join(result_dir, "sql_vulnerables.txt")
    
    # Verificar si el archivo param_urls.txt existe y no está vacío
    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        print(f"{YELLOW}[!] No se encontraron URLs con parámetros para analizar SQLi.{RESET}")
        # Crear archivo vacío para mantener consistencia
        os.makedirs(result_dir, exist_ok=True)
        with open(sqli_file, "w") as vuln_out:
            vuln_out.write("")
        return sqli_file

    sqlmap_dir = os.path.join(result_dir, "sqlmap")
    os.makedirs(sqlmap_dir, exist_ok=True)

    with open(param_urls_file, "r") as urls, open(sqli_file, "w") as vuln_out, open(log_file, "a") as log_out:
        urls_list = [u.strip() for u in urls if u.strip()]
        total = len(urls_list)

        for idx, url in enumerate(urls_list, start=1):
            print(f"{BLUE}[SQLMap {idx}/{total}] Analizando: {url}{RESET}")
            try:
                # Primera ejecución: detección y recogida general (incluye --dbs, pero puede no listar todo en salida)
                cmd = [
                    "sqlmap", "-u", url,
                    "--batch", "--level=3", "--risk=2",
                    "--random-agent", "--dbs", "--current-user",
                    "--output-dir", sqlmap_dir
                ]
                output = subprocess.check_output(
                    cmd,
                    stderr=subprocess.STDOUT,
                    timeout=180
                ).decode(errors="ignore")

                log_out.write(f"\n[SQLI - detect] {url}\n{output}\n")

                # Check heurístico de vulnerabilidad en el output capturado
                if "is vulnerable" in output.lower() or "sql injection" in output.lower() or re.search(r"heuristic .* test shows .* might be injectable", output, re.IGNORECASE):
                    param = extract_parameter(url)
                    payload, evidence = extract_payload_and_evidence(output)

                    # Ejecutar una pasada adicional enfocada a --dbs para asegurarnos de capturar listados completos
                    dbs_output = ""
                    try:
                        print(f"{BLUE}[SQLMap] Enumerando DBs para: {url}{RESET}")
                        cmd_dbs = [
                            "sqlmap", "-u", url,
                            "--batch", "--random-agent", "--dbs",
                            "--output-dir", sqlmap_dir
                        ]
                        dbs_run = subprocess.check_output(
                            cmd_dbs,
                            stderr=subprocess.STDOUT,
                            timeout=240
                        ).decode(errors="ignore")
                        log_out.write(f"\n[SQLI - dbs] {url}\n{dbs_run}\n")
                        dbs_output = extract_dbs_block(dbs_run)
                        # si el extractor no devolvió nada, pondremos todo el output como fallback (pero limitado)
                        if not dbs_output:
                            # intentar extraer manualmente líneas que contienen "available databases" y las inmediatas
                            dbs_output = extract_dbs_block(dbs_run)
                            if not dbs_output:
                                # fallback: tomar las 40 primeras líneas después de 'available databases' si aparecen en el texto crudo
                                m = re.search(r"(available databases\s*\[\d+\]\s*:.*)", dbs_run, re.IGNORECASE | re.DOTALL)
                                if m:
                                    snippet = m.group(1)
                                    # truncar a 2000 chars para evitar dumps gigantes
                                    dbs_output = snippet.strip()[:2000]
                                else:
                                    # como último recurso, buscar líneas que parezcan nombres de DBs
                                    dbs_output = "\n".join(re.findall(r"^\s*[\*\-\[]*\s*([a-zA-Z0-9_\-]+)\s*$", dbs_run, re.MULTILINE)[:20])

                    except subprocess.TimeoutExpired:
                        print(f"{YELLOW}[!] Timeout en enumeración --dbs para: {url}{RESET}")
                        log_out.write(f"\n[SQLI - dbs TIMEOUT] {url}\n")
                        dbs_output = "[!] Timeout al intentar enumerar bases de datos con sqlmap."
                    except Exception as e:
                        print(f"{YELLOW}[!] Error al obtener --dbs para: {url}: {e}{RESET}")
                        log_out.write(f"\n[SQLI - dbs ERROR] {url}\n{e}\n")

                    # Escribir evidencia completa en el archivo de vulnerabilidades
                    vuln_out.write(f"🔗 URL: {url}\n")
                    vuln_out.write(f"🧩 Parámetro afectado: {param}\n")
                    vuln_out.write(f"🎯 Payload detectado: {payload}\n")
                    vuln_out.write(f"🧾 Evidencia (extracto):\n{evidence}\n\n")

                    if dbs_output:
                        vuln_out.write("🗄️ Databases enumeradas (--dbs output):\n")
                        vuln_out.write(dbs_output + "\n\n")
                    else:
                        vuln_out.write("🗄️ Databases enumeradas (--dbs output): No se detectó listado en la salida.\n\n")

                    vuln_out.write("-" * 50 + "\n\n")

            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[!] Timeout SQLMap para: {url}{RESET}")
                log_out.write(f"\n[SQLI - TIMEOUT] {url}\n")
            except Exception as e:
                print(f"{RED}[✘] Error en SQLMap para: {url}: {e}{RESET}")
                log_out.write(f"\n[SQLI - ERROR] {url}\n{e}\n")

    return sqli_file


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_sqli_scan(param_urls_file, result_dir, log_file)