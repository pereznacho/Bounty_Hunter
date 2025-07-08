import os
from urllib.parse import urlparse, parse_qs
from termcolor import cprint
from utils.helpers import run_command, get_httpx_binary

def get_unique_param_urls(input_file, output_file):
    seen_params = set()
    unique_lines = []

    with open(input_file, "r", encoding="utf-8", errors="ignore") as infile:
        for line in infile:
            url = line.strip()
            if not url or "?" not in url:
                continue

            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                for param in qs:
                    key = param.lower()
                    if key not in seen_params:
                        seen_params.add(key)
                        unique_lines.append(url)
                        break
            except Exception:
                continue

    with open(output_file, "w") as out:
        out.write("\n".join(unique_lines) + "\n")


def run_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file):
    httpx_bin = get_httpx_binary()
    raw_urls_file = os.path.join(result_dir, "raw_urls.txt")

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

        # Ahora recon de URLs sobre cada subdominio vivo
        cprint("[*] Ejecutando recon de URLs sobre dominios vivos...", "blue")
        if os.path.exists(live_file):
            with open(live_file) as f:
                for url in f:
                    url = url.strip()
                    run_command(f"katana -u {url} -silent >> {raw_urls_file}", silent=True)
                    run_command(f"gau {url} >> {raw_urls_file}", silent=True)
                    run_command(f"waybackurls {url} >> {raw_urls_file}", silent=True)
        else:
            cprint("[!] live_file vacío. No hay URLs para recon.", "yellow")

    else:
        # MODO URL → simular live_file con la URL
        cprint("[*] Preparando live_file para URL...", "blue")
        with open(live_file, "w") as lf:
            lf.write(target_url + "\n")

        cprint("[*] Ejecutando Katana sobre la URL...", "blue")
        run_command(f"katana -u {target_url} -silent >> {raw_urls_file}", silent=True)

        cprint("[*] Ejecutando gau sobre la URL...", "blue")
        run_command(f"gau {target_url} >> {raw_urls_file}", silent=True)

        cprint("[*] Ejecutando waybackurls sobre la URL...", "blue")
        run_command(f"waybackurls {target_url} >> {raw_urls_file}", silent=True)

    # Filtrar duplicados
    run_command(f"sort -u {raw_urls_file} -o {raw_urls_file}")

    cprint("[*] Filtrando URLs únicas por nombre de parámetro...", "blue")
    get_unique_param_urls(raw_urls_file, urls_file)

    # Copiar también para param_urls_file
    run_command(f"cp {urls_file} {param_urls_file}")

    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[✘] No se encontraron URLs con parámetros.", "red")
    else:
        url_count = sum(1 for _ in open(param_urls_file))
        cprint(f"[✔] URLs con parámetros encontradas: {url_count}", "green")


if __name__ == "__main__":
    import sys
    mode = sys.argv[1]
    domain = sys.argv[2]
    target_url = sys.argv[3]
    result_dir = sys.argv[4]
    subs_file = sys.argv[5]
    live_file = sys.argv[6]
    urls_file = sys.argv[7]
    param_urls_file = sys.argv[8]

    run_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file)