import os
import subprocess
import json
from termcolor import cprint
from urllib.parse import urlparse, parse_qs

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

def run_xss_scan(param_urls_file, result_dir, log_file):
    xsstrike_dir = "/usr/share/XSStrike"
    if not os.path.isdir(xsstrike_dir):
        print(f"{YELLOW}[!] XSStrike no está instalado en /usr/share/XSStrike{RESET}")
        return

    xss_output = os.path.join(result_dir, "xss_vulnerables.txt")

    with open(param_urls_file, "r") as urls, open(xss_output, "w") as xss_out, open(log_file, "a") as log_out:
        urls_list = [u.strip() for u in urls if u.strip()]
        total = len(urls_list)

        for idx, url in enumerate(urls_list, start=1):
            print(f"{BLUE}[XSStrike {idx}/{total}] Analizando: {url}{RESET}")
            try:
                result = subprocess.check_output(
                    ["python3", "xsstrike.py", "--crawl", "--blind", "--skip", "--url", url],
                    cwd=xsstrike_dir,
                    stderr=subprocess.STDOUT,
                    timeout=90
                ).decode(errors="ignore")

                log_out.write(f"\n[XSS] {url}\n{result}\n")

                if "Vulnerable" in result or "XSS found" in result:
                    param = extract_param_name(url)
                    lines = result.strip().splitlines()
                    payloads = [line for line in lines if "<script>" in line or "alert(" in line or "payload:" in line]

                    xss_out.write(f"🔗 URL: {url}\n")
                    xss_out.write(f"🧩 Parámetro afectado: {param}\n")
                    if payloads:
                        xss_out.write(f"🎯 Payload: {payloads[0].strip()}\n")
                    else:
                        xss_out.write("🎯 Payload: No identificado explícitamente\n")

                    xss_out.write(f"🧾 Evidencia:\n{result.strip()}\n")
                    xss_out.write("-" * 50 + "\n\n")

            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[!] Timeout XSStrike para: {url}{RESET}")
            except Exception as e:
                print(f"{RED}[✘] Error en XSStrike para: {url}: {e}{RESET}")


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_xss_scan(param_urls_file, result_dir, log_file)