import os
import subprocess
from urllib.parse import urlparse, parse_qs
from termcolor import cprint

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def extract_param_name(url):
    try:
        parsed_url = urlparse(url)
        qs = parse_qs(parsed_url.query)
        if qs:
            return list(qs.keys())[0]
    except:
        pass
    return "desconocido"

def run_tplmap_scan(param_urls_file, result_dir, log_file):
    tplmap_results = os.path.join(result_dir, "tplmap_results.txt")
    
    # Verificar si el archivo param_urls.txt existe y no está vacío
    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        print(f"{YELLOW}[!] No se encontraron URLs con parámetros para analizar con Tplmap.{RESET}")
        # Crear archivo vacío para mantener consistencia
        with open(tplmap_results, "w") as tpl_out:
            tpl_out.write("")
        return

    tplmap_dir = "/usr/share/tplmap"
    if not os.path.isdir(tplmap_dir):
        print(f"{YELLOW}[!] Tplmap no está instalado en /usr/share/tplmap{RESET}")
        # Crear archivo vacío para mantener consistencia
        with open(tplmap_results, "w") as tpl_out:
            tpl_out.write("")
        return

    with open(param_urls_file, "r") as urls, open(tplmap_results, "w") as tpl_out, open(log_file, "a") as log_out:
        urls_list = [u.strip() for u in urls if u.strip()]
        total = len(urls_list)

        for idx, url in enumerate(urls_list, start=1):
            print(f"{BLUE}[Tplmap {idx}/{total}] Analizando: {url}{RESET}")
            try:
                output = subprocess.check_output(
                    ["python3", "tplmap.py", "-u", url, "--os-shell"],
                    cwd=tplmap_dir,
                    stderr=subprocess.STDOUT,
                    timeout=90
                ).decode(errors="ignore")

                log_out.write(f"\n[TPLMAP] {url}\n{output}\n")

                if "Template injection" in output or "shell available" in output:
                    param = extract_param_name(url)
                    payload = ""
                    for line in output.splitlines():
                        if "PAYLOAD:" in line:
                            payload = line.strip()

                    tpl_out.write(f"🔗 URL: {url}\n")
                    tpl_out.write(f"🧩 Parámetro afectado: {param}\n")
                    tpl_out.write(f"🎯 Payload: {payload or 'No detectado explícitamente'}\n")
                    tpl_out.write(f"🧾 Evidencia:\n{output.strip()}\n")
                    tpl_out.write("-" * 50 + "\n\n")

            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[!] Timeout Tplmap para: {url}{RESET}")
            except Exception as e:
                print(f"{RED}[✘] Error en Tplmap para: {url}: {e}{RESET}")


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_tplmap_scan(param_urls_file, result_dir, log_file)