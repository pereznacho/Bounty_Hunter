# modules/arjun.py

import os
import subprocess
from termcolor import cprint

GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"
RESET = "\033[0m"

def run_arjun(param_urls_file, result_dir, log_file):
    arjun_file = os.path.join(result_dir, "arjun_results.txt")
    temp_output = os.path.join(result_dir, "arjun_tmp.txt")

    # Verificar si el archivo param_urls.txt existe y no está vacío
    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[!] No se encontraron URLs con parámetros para analizar con Arjun.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(arjun_file, "w") as out:
            out.write("")
        return

    urls = [u.strip() for u in open(param_urls_file) if u.strip()]
    if not urls:
        cprint("[!] Lista de URLs vacía.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(arjun_file, "w") as out:
            out.write("")
        return

    with open(arjun_file, "w") as out, open(log_file, "a") as log:
        for idx, url in enumerate(urls, start=1):
            print(f"{BLUE}[Arjun {idx}/{len(urls)}] Analizando: {url}{RESET}")
            try:
                subprocess.run(
                    ["arjun", "-u", url, "-oT", temp_output, "--include", "GET"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60
                )

                if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
                    with open(temp_output, "r") as f:
                        lines = f.read().strip().splitlines()

                    if lines:
                        out.write("🔗 URL: " + url + "\n")
                        for line in lines:
                            out.write("🧩 Parámetro encontrado: " + line + "\n")
                        out.write("--------------------------------------------------\n")

                        log.write(f"[ARJUN] {url}\n")
                        log.write("\n".join(lines) + "\n\n")
                    os.remove(temp_output)

            except subprocess.TimeoutExpired:
                print(f"{RED}[!] Timeout de Arjun para: {url}{RESET}")
            except Exception as e:
                print(f"{RED}[✘] Error executing Arjun for {url}: {e}{RESET}")
    
    print(f"{GREEN}[✔] Arjun scan completed. Results in {arjun_file}{RESET}")
    return arjun_file


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_arjun(param_urls_file, result_dir, log_file)