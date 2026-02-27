import os

GREEN = "\033[32m"
RESET = "\033[0m"

def generate_markdown_report(target, stats, output_dir):
    # Verificar que el directorio existe antes de generar el reporte
    if not os.path.exists(output_dir):
        print(f"[⚠️] Directorio {output_dir} no existe - creándolo")
        os.makedirs(output_dir, exist_ok=True)
    
    report_path = os.path.join(output_dir, "reporte.md")

    with open(report_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(f"# 🕵️ Bounty Hunter Report\n\n")
        f.write(f"**🎯 Objetivo:** `{target}`\n\n")

        f.write("## 📊 Resumen\n")
        if stats:
            f.write("| Métrica | Cantidad |\n|--------|----------|\n")
            for key, value in stats.items():
                f.write(f"| {key} | {value} |\n")
        else:
            f.write("_No se detectaron vulnerabilidades._\n")

        f.write("\n## 📁 Resultados detallados por herramienta\n")
        for file in sorted(os.listdir(output_dir)):
            if file.endswith(".txt") and os.path.getsize(os.path.join(output_dir, file)) > 0:
                f.write(f"\n### 📄 {file}\n")
                with open(os.path.join(output_dir, file), "r", encoding="utf-8", errors="ignore") as content_file:
                    content = content_file.read().strip()
                    f.write("```txt\n")
                    f.write(content + "\n")
                    f.write("```\n")

    print(f"{GREEN}[✔] Reporte Markdown generado en: {report_path}{RESET}")
    return report_path