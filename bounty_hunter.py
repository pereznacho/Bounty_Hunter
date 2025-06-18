#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
from termcolor import cprint
from datetime import datetime
from utils import install, reporter
from modules import xss, sqli

# ─── Colores ───────────────────────────────────────────
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
NC = "\033[0m"

# ─── Paths ─────────────────────────────────────────────
ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_PATH)

go_bin = os.path.expanduser("~/go/bin")
if go_bin not in os.environ["PATH"]:
    os.environ["PATH"] = f"{go_bin}:{os.environ['PATH']}"

# ─── Ctrl+C ────────────────────────────────────────────
skip_to_next = False

def handle_stage(stage_func, name):
    global skip_to_next
    print(f"{BLUE}[*] Ejecutando etapa: {name}{NC}")
    try:
        stage_func()
    except KeyboardInterrupt:
        print(f"\n{RED}[✘] Proceso interrumpido. ¿Qué deseas hacer?{NC}")
        print("1) Continuar con la siguiente etapa")
        print("2) Finalizar y guardar resultados")
        opcion = input("> Selección: ").strip()
        if opcion == "2":
            print(f"{RED}[✘] Tarea finalizada por el usuario. Resultados hasta el momento están guardados.{NC}")
            sys.exit(0)
        else:
            print(f"{YELLOW}[!] Continuando con la siguiente etapa...{NC}")
            skip_to_next = True

# ─── Etapas ────────────────────────────────────────────
def etapa_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file):
    from modules.recon import run_recon
    run_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file)

def etapa_waf(live_file, result_dir, log_file, mode, domain):
    from modules.waf import run_waf_detection
    if mode == "url":
        base_url = f"http://{domain}"
        live_temp = os.path.join(result_dir, "live_url_temp.txt")
        with open(live_temp, "w") as f:
            f.write(base_url + "\n")
        run_waf_detection(live_temp, result_dir, log_file)
        os.remove(live_temp)
    else:
        run_waf_detection(live_file, result_dir, log_file)

def etapa_nuclei(domain, result_dir):
    cprint("[*] Ejecutando Nuclei sobre HTTP y HTTPS...", "blue")
    output_file = os.path.join(result_dir, "nuclei_results.txt")

    targets = [f"http://{domain}", f"https://{domain}"]

    with open(output_file, "w") as out:
        for url in targets:
            cprint(f"[-] Analizando: {url}", "yellow")
            try:
                process = subprocess.Popen(
                    ["nuclei", "-u", url, "-silent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )

                has_output = False
                out.write(f"# Resultados para {url}:\n")

                for line in process.stdout:
                    print(line, end="")  # Mostrar en pantalla
                    out.write(line)      # Guardar en archivo
                    has_output = True

                process.wait()

                if has_output:
                    cprint(f"[✔] Vulnerabilidades encontradas en {url}", "red")
                    out.write("\n")
                else:
                    cprint(f"[✓] Sin hallazgos para {url}", "green")

            except Exception as e:
                cprint(f"[✘] Error al ejecutar Nuclei en {url}: {e}", "red")

    if os.path.getsize(output_file) == 0:
        os.remove(output_file)
        cprint("[✓] Nuclei no encontró vulnerabilidades.", "green")
    else:
        cprint(f"[✔] Resultados guardados en {output_file}", "green")

def etapa_xss(param_urls_file, result_dir, log_file):
    print(f"{BLUE}[*] Fuzzeando con XSStrike...{NC}")
    return xss.run_xss_scan(param_urls_file, result_dir, log_file)

def etapa_sqli(param_urls_file, result_dir, log_file):
    print(f"{BLUE}[*] Analizando con SQLMap...{NC}")
    return sqli.run_sqli_scan(param_urls_file, result_dir, log_file)

def etapa_ffuf(param_urls_file, result_dir):
    from modules.ffuf_fuzz import run_ffuf
    run_ffuf(param_urls_file, result_dir)

def etapa_wfuzz(param_urls_file, result_dir):
    from modules.wfuzz_fuzz import run_wfuzz
    run_wfuzz(param_urls_file, result_dir)

def etapa_dalfox(param_urls_file, result_dir):
    from modules.dalfox_scan import run_dalfox
    run_dalfox(param_urls_file, result_dir)

def etapa_tplmap(param_urls_file, result_dir):
    from modules.tplmap import run_tplmap
    run_tplmap(param_urls_file, result_dir)

def etapa_gf(param_urls_file, result_dir):
    from modules.gf_qsreplace import run_gf_qsreplace
    run_gf_qsreplace(param_urls_file, result_dir)

# ─── Contador de líneas ───────────────────────────────
def count_lines(filepath):
    return sum(1 for _ in open(filepath)) if filepath and os.path.exists(filepath) else 0

# ─── Banner ────────────────────────────────────────────
def print_banner():
    os.system("clear")
    print(f"""{GREEN}
██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{BLUE}                        BugBounty Automation Tool - by Ignacio Pérez{NC}
""")

# ─── Main ──────────────────────────────────────────────
def main():
    global skip_to_next
    print_banner()
    parser = argparse.ArgumentParser(description="BugBounty Automation Tool")
    parser.add_argument("-d", "--domain", help="Dominio objetivo (modo dominio)")
    parser.add_argument("-u", "--url", help="URL objetivo (modo URL)")
    args = parser.parse_args()

    if not args.domain and not args.url:
        print(f"{RED}❌ Debes proporcionar un dominio o una URL.{NC}")
        sys.exit(1)

    mode = "domain" if args.domain else "url"
    domain = args.domain or args.url.split("/")[2]
    target_url = args.url if args.url else f"http://{args.domain}"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = os.path.join("results", f"{domain}_{timestamp}")
    os.makedirs(result_dir, exist_ok=True)

    subs_file = os.path.join(result_dir, "subdomains.txt")
    live_file = os.path.join(result_dir, "live.txt")
    urls_file = os.path.join(result_dir, "urls.txt")
    param_urls_file = os.path.join(result_dir, "param_urls.txt")
    log_file = os.path.join(result_dir, "log.txt")

    print(f"{BLUE}[*] Verificando herramientas necesarias...{NC}")
    install.main()

    stats = {}
    etapas = [
        ("Recon", lambda: etapa_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file)),
        ("Nuclei Scan", lambda: etapa_nuclei(domain, result_dir)),
        ("WAF Detection", lambda: etapa_waf(live_file, result_dir, log_file, mode, domain)),
        ("XSStrike (XSS)", lambda: stats.update({"XSS vulnerabilidades": count_lines(etapa_xss(param_urls_file, result_dir, log_file))})),
        ("SQLMap (SQLi)", lambda: stats.update({"SQLi vulnerabilidades": count_lines(etapa_sqli(param_urls_file, result_dir, log_file))})),
        ("FFUF", lambda: etapa_ffuf(param_urls_file, result_dir)),
        ("WFUZZ", lambda: etapa_wfuzz(param_urls_file, result_dir)),
        ("Dalfox", lambda: etapa_dalfox(param_urls_file, result_dir)),
        ("Tplmap", lambda: etapa_tplmap(param_urls_file, result_dir)),
        ("GF + qsreplace", lambda: etapa_gf(param_urls_file, result_dir)),
    ]

    for name, func in etapas:
        skip_to_next = False
        handle_stage(func, name)
        if skip_to_next:
            continue

    print(f"{BLUE}[*] Generando reporte Markdown...{NC}")
    md_path = reporter.generate_markdown_report(domain, stats, result_dir)
    print(f"{GREEN}[✔] Todo listo. Reporte generado en: {md_path}{NC}")

if __name__ == "__main__":
    main()
