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

def run_wfuzz_scan(param_urls_file, result_dir, log_file):
    if not os.path.exists(param_urls_file):
        print(f"{RED}[✘] Archivo no encontrado: {param_urls_file}{RESET}")
        return None

    wfuzz_out_file = os.path.join(result_dir, "wfuzz_results.txt")
    wordlist = "/usr/share/wordlists/dirb/common.txt"

    with open(param_urls_file, "r") as urls, open(wfuzz_out_file, "w") as wfuzz_out, open(log_file, "a") as log_out:
        urls_list = [u.strip() for u in urls if u.strip()]
        total = len(urls_list)

        for idx, url in enumerate(urls_list, start=1):
            param = extract_param_name(url)
            print(f"{BLUE}[Wfuzz {idx}/{total}] Analizando: {url}{RESET}")
            try:
                fuzz_url = url.replace(f"{param}=", f"{param}=FUZZ")

                output = subprocess.check_output(
                    ["wfuzz", "-w", wordlist, "--sc", "200", fuzz_url],
                    stderr=subprocess.STDOUT,
                    timeout=60
                ).decode(errors="ignore")

                log_out.write(f"\n[WFUZZ] {url}\n{output}\n")

                lines = [l for l in output.splitlines() if "200" in l]
                if lines:
                    wfuzz_out.write(f"🔗 URL: {url}\n")
                    wfuzz_out.write(f"🧩 Parámetro afectado: {param}\n")
                    wfuzz_out.write(f"🎯 Payloads útiles detectados:\n")
                    for line in lines:
                        wfuzz_out.write(f"   - {line.strip()}\n")
                    wfuzz_out.write(f"🧾 Evidencia:\n{output.strip()}\n")
                    wfuzz_out.write("-" * 50 + "\n\n")

            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[!] Timeout Wfuzz para: {url}{RESET}")
            except Exception as e:
                print(f"{RED}[✘] Error en Wfuzz para: {url}: {e}{RESET}")


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_wfuzz_scan(param_urls_file, result_dir, log_file)