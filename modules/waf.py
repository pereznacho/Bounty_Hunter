import os
from termcolor import cprint
from utils.helpers import run_command

def run_waf(live_file, result_dir, log_file):
    cprint("[*] Detectando WAFs en subdominios activos...", "blue")
    waf_file = os.path.join(result_dir, "waf_detected.txt")
    detected = 0

    # Asegura existencia del archivo aunque esté vacío
    if not os.path.exists(live_file):
        cprint(f"[!] Archivo {live_file} no encontrado. Creando archivo vacío.", "yellow")
        with open(live_file, "w") as f:
            pass

    if os.path.getsize(live_file) == 0:
        cprint(f"[!] El archivo {live_file} está vacío. No se ejecutará detección de WAFs.", "yellow")
        return

    with open(live_file) as f, open(waf_file, "w") as waf_out:
        for line in f:
            try:
                domain = line.strip().split("/")[2]
                base_url = f"http://{domain}"
                cprint(f"[-] Analizando WAF en: {base_url}", "yellow")
                output = run_command(f"wafw00f {base_url}", silent=True)
                if "is behind a" in output:
                    waf_out.write(f"{base_url}\n")
                    detected += 1
                    cprint(f"[!] WAF detectado: {base_url}", "red")
            except Exception as e:
                cprint(f"[✘] Error en WAF para: {line.strip()}: {e}", "red")

    if detected == 0:
        cprint("[✓] No se detectaron WAFs en los subdominios analizados.", "green")
    else:
        cprint(f"[✓] WAFs detectados en {detected} subdominios.", "red")


if __name__ == "__main__":
    import sys
    live_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_waf(live_file, result_dir, log_file)