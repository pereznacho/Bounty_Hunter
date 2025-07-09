#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
from termcolor import cprint
from datetime import datetime
from utils import install, reporter
from modules import xss, sqli
from urllib.parse import urlparse
from modules.ffuf import run_ffuf
from modules.nuclei_scan import run_nuclei_scan

# Colores
RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
NC = "\033[0m"

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_PATH)

go_bin = os.path.expanduser("~/go/bin")
if go_bin not in os.environ["PATH"]:
    os.environ["PATH"] = f"{go_bin}:{os.environ['PATH']}"

skip_to_next = False

from urllib.parse import urlparse

def get_safe_name_from_target(target):
    parsed = urlparse(target if "://" in target else "http://" + target)
    hostname = parsed.hostname
    if not hostname:
        return "invalid_target"
    return hostname.replace(":", "_").replace("/", "_")

def handle_stage(stage_func, name):
    global skip_to_next
    print(f"==> START: {name}", flush=True)
    print(f"{BLUE}[*] Ejecutando etapa: {name}{NC}")
    while True:
        try:
            stage_func()
            break
        except KeyboardInterrupt:
            print(f"\n{RED}[✘] Proceso interrumpido. ¿Qué deseas hacer?{NC}")
            print("1) Continuar con la siguiente etapa")
            print("2) Repetir esta etapa")
            print("3) Finalizar y guardar resultados")

            opcion = input("> Selección: ").strip()

            if opcion == "1":
                print(f"{YELLOW}[!] Continuando con la siguiente etapa...{NC}")
                skip_to_next = True
                break
            elif opcion == "3":
                print(f"{RED}[✘] Tarea finalizada por el usuario. Resultados hasta el momento están guardados.{NC}")
                sys.exit(0)
            elif opcion == "2":
                print(f"{BLUE}[*] Repitiendo la etapa actual...{NC}")
                continue
            else:
                print(f"{RED}[!] Opción inválida. Intenta nuevamente.{NC}")
    print(f"==> END: {name}", flush=True)

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


def etapa_xss(param_urls_file, result_dir, log_file):
    print(f"{BLUE}[*] Fuzzeando con XSStrike...{NC}")
    return xss.run_xss_scan(param_urls_file, result_dir, log_file)

def etapa_sqli(param_urls_file, result_dir, log_file):
    print(f"{BLUE}[*] Analizando con SQLMap...{NC}")
    return sqli.run_sqli_scan(param_urls_file, result_dir, log_file)

def etapa_ffuf(param_urls_file, result_dir, log_file):
    from modules.ffuf import run_ffuf
    run_ffuf(param_urls_file, result_dir, log_file)

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

def count_lines(filepath):
    return sum(1 for _ in open(filepath)) if filepath and os.path.exists(filepath) else 0

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

def main():
    global skip_to_next
    print_banner()
    parser = argparse.ArgumentParser(description="BugBounty Automation Tool")
    parser.add_argument("-d", "--domain", help="Dominio objetivo (modo dominio)")
    parser.add_argument("-u", "--url", help="URL objetivo (modo URL)")
    parser.add_argument("--output", help="Ruta del directorio de resultados")
    parser.add_argument("--start-from", help="Nombre de etapa desde la que continuar")
    args = parser.parse_args()

    if not args.domain and not args.url:
        print(f"{RED}❌ Debes proporcionar un dominio o una URL.{NC}")
        sys.exit(1)

    mode = "domain" if args.domain else "url"
    target = args.domain if args.domain else args.url
    safe_name = get_safe_name_from_target(target)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = os.path.abspath(args.output) if args.output else os.path.join("results", f"{safe_name}_{timestamp}")
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
        ("Recon", lambda: etapa_recon(mode, safe_name, args.url, result_dir, subs_file, live_file, urls_file, param_urls_file)),
        ("Nuclei Scan", lambda: run_nuclei_scan(mode, safe_name, result_dir, log_file)),
        ("WAF Detection", lambda: etapa_waf(live_file, result_dir, log_file, mode, safe_name)),
        ("XSStrike (XSS)", lambda: stats.update({"XSS vulnerabilidades": count_lines(etapa_xss(param_urls_file, result_dir, log_file))})),
        ("SQLMap (SQLi)", lambda: stats.update({"SQLi vulnerabilidades": count_lines(etapa_sqli(param_urls_file, result_dir, log_file))})),
        ("FFUF", lambda: etapa_ffuf(param_urls_file, result_dir, os.path.join(result_dir, "log.txt"))),
        ("WFUZZ", lambda: etapa_wfuzz(param_urls_file, result_dir)),
        ("Dalfox", lambda: etapa_dalfox(param_urls_file, result_dir)),
        ("Tplmap", lambda: etapa_tplmap(param_urls_file, result_dir)),
        ("GF + qsreplace", lambda: etapa_gf(param_urls_file, result_dir)),
    ]

    start_index = 0
    if args.start_from:
        stage_names = [et[0] for et in etapas]
        if args.start_from in stage_names:
            start_index = stage_names.index(args.start_from)

    for name, func in etapas[start_index:]:
        skip_to_next = False
        handle_stage(func, name)
        if skip_to_next:
            continue

    print(f"{BLUE}[*] Generando reporte Markdown...{NC}")
    md_path = reporter.generate_markdown_report(safe_name, stats, result_dir)
    print(f"{GREEN}[✔] Todo listo. Reporte generado en: {md_path}{NC}")

if __name__ == "__main__":
    main()
