import os

GREEN = "\033[32m"
RESET = "\033[0m"

def generate_markdown_report(target, stats, output_dir):
    report_path = os.path.join(output_dir, "reporte.md")
    
    with open(report_path, "w") as f:
        # Encabezado
        f.write(f"# 🕵️ Bounty Hunter Report\n\n")
        f.write(f"**Objetivo:** `{target}`\n\n")

        # Resumen
        f.write("## 📊 Resumen\n")
        if stats:
            f.write("| Métrica | Cantidad |\n|--------|----------|\n")
            for key, value in stats.items():
                f.write(f"| {key} | {value} |\n")
        else:
            f.write("_No se detectaron vulnerabilidades._\n")

        # Resultados detallados
        f.write("\n## 📁 Resultados por herramienta\n")
        for file in sorted(os.listdir(output_dir)):
            if file.endswith(".txt") and file != "log.txt":
                file_path = os.path.join(output_dir, file)
                if os.path.getsize(file_path) > 0:
                    with open(file_path, "r") as content_file:
                        content = content_file.read().strip()
                        if content:
                            f.write(f"\n### {file}\n")
                            f.write("```txt\n")
                            f.write(content + "\n")
                            f.write("```\n")
    
    print(f"{GREEN}[✔] Reporte Markdown generado en: {report_path}{RESET}")
    return report_path
