# 🕵️ Bounty Hunter

**Bounty Hunter** es una herramienta de automatización para procesos de reconocimiento y explotación en programas de Bug Bounty. Desarrollada en Bash por Ignacio Pérez, permite realizar desde la enumeración de subdominios hasta la detección de vulnerabilidades XSS y SQLi de forma automática, generando además un reporte final en formato Markdown listo para documentar hallazgos o subir a plataformas como [Espengler](https://github.com/pereznacho/espengler).

---

## 🚀 Funcionalidades principales

* Enumeración de subdominios activos (modo dominio)
* Detección de WAFs con `wafw00f`
* Descubrimiento de endpoints y parámetros con `katana`
* Fuzzing automatizado con `XSStrike` para detectar XSS
* Auditoría de inyecciones SQL con `sqlmap`
* Reporte final en consola, archivo `.txt` y `.md` ordenado
* Verificación automática de herramientas necesarias

---

## 📦 Requisitos

Antes de usar la herramienta, asegurate de tener instaladas las siguientes dependencias:

* `bash`
* `git`
* `curl`
* `subfinder`
* `katana`
* `wafw00f` → `pip install wafw00f`
* `sqlmap` → [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
* `XSStrike` (se clona automáticamente si no está)

---

## 🛠️ Instalación

```bash
git clone https://github.com/pereznacho/Bounty_Hunter.git
cd bounty-hunter
chmod +x bounty_hunter.sh
```

---

## ⚙️ Uso

```bash
# Modo dominio
./bounty_hunter.sh -d ejemplo.com

# Modo URL directa
./bounty_hunter.sh -u "http://example.com/index.php?id=1"
```

La herramienta detectará automáticamente qué modo estás utilizando y ejecutará el flujo adecuado.

---

## 📁 Estructura de resultados

Los resultados se almacenan en el directorio `./recon/[DOMINIO]` e incluyen:

| Archivo               | Contenido                                                   |
| --------------------- | ----------------------------------------------------------- |
| `subdomains.txt`      | Subdominios encontrados                                     |
| `live_subdomains.txt` | Subdominios activos                                         |
| `urls.txt`            | Endpoints detectados con Katana                             |
| `param_urls.txt`      | URLs con parámetros                                         |
| `xss_vulnerables.txt` | Detalles de vulnerabilidades XSS encontradas                |
| `sql_vulnerables.txt` | Detalles de inyecciones SQL detectadas                      |
| `waf_detection.txt`   | Resultados de detección de WAFs                             |
| `summary.txt`         | Resumen final en texto plano                                |
| `resultados.md`       | Informe completo en formato Markdown (ideal para Espengler) |

---

## 🧠 Consideraciones

* Esta herramienta está diseñada con fines educativos y para ser utilizada en entornos de pruebas controlados o con autorización explícita.
* El uso en sistemas sin permiso puede ser ilegal.

---

## 📜 Licencia

Este proyecto se publica bajo la licencia MIT. Puedes usarlo, modificarlo y distribuirlo libremente, siempre respetando los créditos.

---

## ❤️ Créditos

Desarrollado por [Ignacio Pérez](https://github.com/[TU_USUARIO]) como aporte a la comunidad de ciberseguridad y hacking ético.
