import os
import subprocess
from urllib.parse import urlparse, parse_qs, urlencode

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"

def ensure_xsstrike_installed():
    xs_path = "/usr/share/XSStrike"
    if os.path.isdir(xs_path):
        print(f"{GREEN}[✔] XSStrike ya está instalado.{RESET}")
        return xs_path

    print(f"{BLUE}[+] Clonando XSStrike en /usr/share (requiere permisos root)...{RESET}")
    try:
        subprocess.run(
            ["sudo", "git", "clone", "https://github.com/s0md3v/XSStrike.git", xs_path],
            check=True
        )
        print(f"{GREEN}[✓] XSStrike instalado correctamente.{RESET}")
        return xs_path
    except subprocess.CalledProcessError:
        print(f"{RED}[✘] Error al clonar XSStrike con permisos de administrador.{RESET}")
        return None

def run_xss_scan(param_urls_file, result_dir, log_file):
    xsstrike_dir = ensure_xsstrike_installed()
    xss_file = os.path.join(result_dir, "xss_vulnerables.txt")

    # Asegurar que exista aunque esté vacío
    with open(xss_file, "w") as _:
        pass

    if not xsstrike_dir:
        return xss_file

    with open(param_urls_file, "r") as urls, open(xss_file, "w") as vuln_out, open(log_file, "a") as log_out:
        urls_list = [u.strip() for u in urls if u.strip()]
        total = len(urls_list)

        for idx, full_url in enumerate(urls_list, start=1):
            parsed = urlparse(full_url)
            qs = parse_qs(parsed.query)

            if not qs:
                continue

            for param in qs:
                single_param = {param: "test"}
                new_query = urlencode(single_param)
                modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                print(f"{BLUE}[XSStrike {idx}] Probando parámetro '{param}': {modified_url}{RESET}")
                try:
                    output = subprocess.check_output(
                        ["python3", os.path.join(xsstrike_dir, "xsstrike.py"), "-u", modified_url, "--fuzzer", "--skip-dom"],
                        stderr=subprocess.STDOUT,
                        timeout=60
                    ).decode()

                    log_out.write(f"\n[PARAM: {param}] {modified_url}\n{output}\n")

                    if "Vulnerable webpage:" in output:
                        vuln_out.write(modified_url + "\n")

                except subprocess.TimeoutExpired:
                    print(f"{RED}[!] Timeout XSStrike para: {modified_url}{RESET}")
                except Exception as e:
                    print(f"{RED}[✘] Error XSStrike para: {modified_url}: {e}{RESET}")

    return xss_file
