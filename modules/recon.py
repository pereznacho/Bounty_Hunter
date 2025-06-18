import os
from termcolor import cprint
from utils.helpers import run_command, get_httpx_binary

def run_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file):
    httpx_bin = get_httpx_binary()

    if mode == "domain":
        cprint("[*] Subdomain enum con subfinder + assetfinder...", "blue")
        run_command(f"subfinder -d {domain} -silent > {result_dir}/_raw1.txt", silent=True)
        run_command(f"assetfinder --subs-only {domain} > {result_dir}/_raw2.txt", silent=True)
        run_command(f"cat {result_dir}/_raw1.txt {result_dir}/_raw2.txt | sort -u > {subs_file}")

        cprint("[*] Verificando subdominios vivos con httpx...", "blue")
        subs_httpx = subs_file + ".httpx"
        valid_lines = 0
        with open(subs_file, "r") as infile, open(subs_httpx, "w") as outfile:
            for line in infile:
                line = line.strip()
                if line:
                    if not line.startswith("http"):
                        line = f"http://{line}"
                    outfile.write(line + "\n")
                    valid_lines += 1
        if valid_lines == 0:
            cprint("[!] No se encontraron subdominios válidos para enviar a httpx. Saltando etapa.", "yellow")
            with open(live_file, "w") as lf:
                lf.write("")
        else:
            run_command(f"{httpx_bin} -l {subs_httpx} --silent > {live_file}", silent=True)
            if not os.path.exists(live_file) or os.path.getsize(live_file) == 0:
                cprint("[✘] httpx no devolvió subdominios vivos.", "red")
        os.remove(subs_httpx)

    cprint("[*] Recolectando URLs con gau + waybackurls...", "blue")
    run_command(f"gau {domain} >> {urls_file}", silent=True)
    run_command(f"waybackurls {domain} >> {urls_file}", silent=True)

    cprint("[*] Ejecutando Katana...", "blue")
    katana_input = live_file if mode == "domain" else target_url
    if mode == "domain" and os.path.exists(live_file):
        with open(live_file) as f:
            for url in f:
                run_command(f"katana -u {url.strip()} -silent >> {urls_file}", silent=True)
    else:
        run_command(f"katana -u {katana_input} -silent >> {urls_file}", silent=True)

    run_command(f"sort -u {urls_file} -o {urls_file}")
    run_command(f"grep '=' {urls_file} > {param_urls_file}")

    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[✘] No se encontraron URLs con parámetros. Finalizando.", "red")
        exit(1)

    url_count = sum(1 for _ in open(param_urls_file))
    cprint(f"[✔] URLs con parámetros encontradas: {url_count}", "green")
