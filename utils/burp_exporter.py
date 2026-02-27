import os
from urllib.parse import urlparse

def export_to_burp_txt(result_dir, output_file="burp_export.txt"):
    """
    Combina todas las URLs únicas encontradas en los archivos .txt
    y genera un archivo de texto plano para importar en Burp Suite Scope.
    """

    candidate_files = [
        "subdomains.txt",
        "live.txt",
        "urls.txt",
        "raw_urls.txt",
        "param_urls.txt"
    ]

    urls_set = set()

    for fname in candidate_files:
        path = os.path.join(result_dir, fname)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    url = line.strip()
                    if not url:
                        continue

                    # Si es dominio, convertirlo a URL http://dominio/
                    if not url.startswith("http"):
                        url = f"http://{url}/"

                    urls_set.add(url)

    if not urls_set:
        print("[!] No se encontraron URLs para exportar.")
        # Igual genera archivo vacío para evitar errores posteriores
        output_path = os.path.join(result_dir, output_file)
        open(output_path, "w").close()
        return output_path

    output_path = os.path.join(result_dir, output_file)

    with open(output_path, "w", encoding="utf-8") as f:
        for url in sorted(urls_set):
            f.write(url + "\n")

    print(f"[✔] Exportación a Burp generada: {output_path}")
    return output_path