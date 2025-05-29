#!/bin/bash

# ========================
# 🎯 BugBounty Automation Tool - Modo dominio o URL
# ========================

# Colores
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
NC="\e[0m"

# Banner
clear
echo -e "${YELLOW}"
echo "██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗"
echo "██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
echo "██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
echo "██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
echo "██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
echo "╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
echo -e "${BLUE}                            BugBounty Automation Tool - by Ignacio Pérez${NC}\n"

# Interrupciones controladas
handle_interrupt() {
    echo -e "\n${RED}[✘] Proceso interrumpido. ¿Qué deseas hacer?${NC}"
    echo "1) Continuar con la siguiente etapa"
    echo "2) Finalizar y guardar resultados"
    read -p "> Selección: " option

    if [[ "$option" == "1" ]]; then
        echo -e "${YELLOW}[!] Continuando con la siguiente etapa...${NC}"
    else
        echo -e "${RED}[✘] Tarea finalizada por el usuario. Resultados hasta el momento están guardados.${NC}"
        exit 1
    fi
}

trap 'handle_interrupt' SIGINT

#================== CONFIGURACIÓN ==================#
TOOLS=(
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "assetfinder:github.com/tomnomnom/assetfinder"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    "gau:github.com/tomnomnom/gau"
    "waybackurls:github.com/tomnomnom/waybackurls"
    "gospider:github.com/jaeles-project/gospider"
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx"
    "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx"
    "cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck"
    "unfurl:github.com/tomnomnom/unfurl"
    "qsreplace:github.com/1ndianl33t/qsreplace"
    "ffuf:github.com/tomnomnom/ffuf"
    "dalfox:github.com/hahwul/dalfox/v2"
)

BIN_DIR="$HOME/go/bin"
export PATH=$PATH:$BIN_DIR

check_or_install() {
    local name=$(echo "$1" | cut -d':' -f1)
    local repo=$(echo "$1" | cut -d':' -f2)

    if ! command -v "$name" &>/dev/null; then
        echo -e "${RED}[+] $name no está instalado. Instalando...${NC}"
        go install "$repo@latest"
    fi
}

echo -e "${BLUE}[*] Verificando herramientas necesarias...${NC}"
for tool in "${TOOLS[@]}"; do
    check_or_install "$tool"
done

# ========= Argumentos ========= #
if [[ "$1" == "-d" && -n "$2" ]]; then
    MODE="domain"
    DOMAIN="$2"
elif [[ "$1" == "-u" && -n "$2" ]]; then
    MODE="url"
    TARGET_URL="$2"
    DOMAIN=$(echo "$TARGET_URL" | awk -F/ '{print $3}')
else
    echo -e "${RED}[!] Uso inválido. Ejemplos:${NC}"
    echo -e "${YELLOW}    ./bounty_hunter.sh -d dominio.com${NC}"
    echo -e "${YELLOW}    ./bounty_hunter.sh -u \"http://example.com/index.php?id=1\"${NC}"
    exit 1
fi

# ========= Directorios ========= #
PROJECT_DIR="./recon/$DOMAIN"
mkdir -p "$PROJECT_DIR"
SUBS_FILE="$PROJECT_DIR/subdomains.txt"
LIVE_FILE="$PROJECT_DIR/live_subdomains.txt"
GAU_FILE="$PROJECT_DIR/gau.txt"
WAYBACK_FILE="$PROJECT_DIR/wayback.txt"
URLS_FILE="$PROJECT_DIR/urls.txt"
PARAM_URLS_FILE="$PROJECT_DIR/param_urls.txt"
QSREPLACED_FILE="$PROJECT_DIR/qsreplaced.txt"
UNFURL_FILE="$PROJECT_DIR/param_keys.txt"
KATANA_FILE="$PROJECT_DIR/katana.txt"
GOSPIDER_FILE="$PROJECT_DIR/gospider.txt"
NUCLEI_FILE="$PROJECT_DIR/nuclei.txt"
FFUF_FILE="$PROJECT_DIR/ffuf.txt"
WAF_LOG="$PROJECT_DIR/waf_detection.txt"
XSS_FILE="$PROJECT_DIR/xss_vulnerables.txt"
SQLI_FILE="$PROJECT_DIR/sql_vulnerables.txt"
SUMMARY="$PROJECT_DIR/summary.txt"
MD_FILE="$PROJECT_DIR/resultados.md"
LOG_FILE="$PROJECT_DIR/output.log"

> "$URLS_FILE"
> "$PARAM_URLS_FILE"
> "$XSS_FILE"
> "$SQLI_FILE"
> "$WAF_LOG"

echo -e "${GREEN}[✔] Objetivo: $DOMAIN${NC}"
[[ "$MODE" == "url" ]] && echo -e "${GREEN}[✔] URL objetivo: $TARGET_URL${NC}"

# ========= Modo DOMINIO ========= #
if [[ "$MODE" == "domain" ]]; then
    echo -e "${BLUE}[*] Subdomain enum con subfinder + assetfinder...${NC}"
    
    subfinder -d "$DOMAIN" -silent > "$PROJECT_DIR/_raw_subs1.txt"
    assetfinder --subs-only "$DOMAIN" > "$PROJECT_DIR/_raw_subs2.txt"

    cat "$PROJECT_DIR/_raw_subs1.txt" "$PROJECT_DIR/_raw_subs2.txt" | \
        grep -Eo "([a-zA-Z0-9_-]+\.)+$DOMAIN" | \
        sort -u > "$SUBS_FILE"

    SUBTOTAL=$(wc -l < "$SUBS_FILE")
    echo -e "${GREEN}[✔] Subdominios válidos encontrados: $SUBTOTAL${NC}"

    echo -e "${BLUE}[*] Verificando subdominios vivos con httpx...${NC}"
    httpx -l "$SUBS_FILE" -silent > "$LIVE_FILE"
    sort -u "$LIVE_FILE" -o "$LIVE_FILE"
    LIVE_TOTAL=$(wc -l < "$LIVE_FILE")
    echo -e "${GREEN}[✔] Subdominios activos: $LIVE_TOTAL${NC}"

    echo -e "${BLUE}[*] Recolectando URLs con gau + waybackurls...${NC}"
    gau "$DOMAIN" > "$GAU_FILE"
    waybackurls "$DOMAIN" > "$WAYBACK_FILE"

    if [[ -s "$GAU_FILE" || -s "$WAYBACK_FILE" ]]; then
        cat "$GAU_FILE" "$WAYBACK_FILE" | sort -u > "$URLS_FILE"
        echo -e "${GREEN}[✔] URLs recolectadas guardadas en: $URLS_FILE${NC}"
    else
        echo -e "${YELLOW}[!] gau y waybackurls no devolvieron resultados.${NC}"
    fi

    echo -e "${BLUE}[*] Ejecutando dnsx y cdncheck...${NC}"
    dnsx -l "$SUBS_FILE" -o "$PROJECT_DIR/dnsx.txt"
    cdncheck -i "$LIVE_FILE" -o "$PROJECT_DIR/cdncheck.txt"
fi

# ========= Katana ========= #
echo -e "${BLUE}[*] Obteniendo URLs con Katana...${NC}"
if [[ "$MODE" == "domain" && -f "$LIVE_FILE" ]]; then
    while read -r live; do
        katana -u "$live" -jc -kf all -d 3 -silent >> "$URLS_FILE" 2>/dev/null
    done < "$LIVE_FILE"
elif [[ "$MODE" == "url" ]]; then
    katana -u "$TARGET_URL" -jc -kf all -d 3 -silent >> "$URLS_FILE" 2>/dev/null
fi

cp "$URLS_FILE" "$KATANA_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"
grep '=' "$URLS_FILE" > "$PARAM_URLS_FILE"
URL_COUNT=$(wc -l < "$PARAM_URLS_FILE")
if [ "$URL_COUNT" -eq 0 ]; then
    echo -e "${RED}[✘] No se encontraron URLs con parámetros. Saliendo...${NC}"
    exit 1
fi
echo -e "${GREEN}[✔] URLs con parámetros encontradas: $URL_COUNT${NC}"

qsreplace "test" < "$URLS_FILE" > "$QSREPLACED_FILE"
unfurl --unique keys < "$URLS_FILE" > "$UNFURL_FILE"

# ========= Gospider ========= #
echo -e "${BLUE}[*] Ejecutando gospider...${NC}"
TARGET_GOSPIDER="$TARGET_URL"
[[ "$MODE" == "domain" ]] && TARGET_GOSPIDER="http://$DOMAIN"
gospider -s "$TARGET_GOSPIDER" -t 10 --js --robots --sitemap --subs -d 2 > "$GOSPIDER_FILE"
grep -Eo '(http|https)://[^"]+' "$GOSPIDER_FILE" | sort -u > "$PROJECT_DIR/gospider_urls.txt"

# ========= ffuf ========= #
echo -e "${BLUE}[*] Ejecutando ffuf...${NC}"
ffuf -u "$TARGET_URL/FUZZ" -w /usr/share/wordlists/dirb/common.txt -of json > "$FFUF_FILE"

# ========= nuclei ========= #
NUCLEI_TEMPLATES="$HOME/.config/nuclei/templates"
[[ ! -d "$NUCLEI_TEMPLATES" ]] && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_TEMPLATES" &>/dev/null
echo -e "${BLUE}[*] Escaneando con nuclei...${NC}"
if [[ "$MODE" == "domain" && -f "$LIVE_FILE" ]]; then
    nuclei -l "$LIVE_FILE" -t "$NUCLEI_TEMPLATES" -o "$NUCLEI_FILE" -silent
else
    echo "$TARGET_URL" > "$PROJECT_DIR/tmp_single_target.txt"
    nuclei -l "$PROJECT_DIR/tmp_single_target.txt" -t "$NUCLEI_TEMPLATES" -o "$NUCLEI_FILE" -silent
    rm -f "$PROJECT_DIR/tmp_single_target.txt"
fi

# ========= WAF Detection ========= #
echo -e "${BLUE}[*] Detectando WAFs...${NC}"
DETECTED_WAFS=0
while read -r url; do
    wafw00f "$url" 2>/dev/null | tee -a "$LOG_FILE" | grep -iq "is behind a" && {
        echo "$url" >> "$WAF_LOG"
        ((DETECTED_WAFS++))
    }
done < "$PARAM_URLS_FILE"

# ========= XSStrike ========= #
echo -e "${BLUE}[*] Fuzzeando con XSStrike...${NC}"
XS_PATH="/usr/share/XSStrike"
[[ ! -d "$XS_PATH" ]] && git clone https://github.com/s0md3v/XSStrike.git "$XS_PATH" &>/dev/null
> "$XSS_FILE"
current_xss=0
while read -r url; do
    ((current_xss++))
    echo -e "${YELLOW}[XSStrike $current_xss/$URL_COUNT] Probando: $url${NC}"
    result=$(python3 "$XS_PATH/xsstrike.py" -u "$url" --crawl 2>/dev/null)
    echo "$result" | tee -a "$LOG_FILE"
    echo "$result" | grep -iq "Vulnerable webpage:" && {
        echo "$url" >> "$XSS_FILE"
    }
done < "$PARAM_URLS_FILE"

XSS_TOTAL=$(grep -c "http" "$XSS_FILE" 2>/dev/null || echo 0)

# ========= SQLMap ========= #
echo -e "${BLUE}[*] Revisando con SQLMap...${NC}"
> "$SQLI_FILE"
total_sql=0
while read -r url; do
    ((total_sql++))
    echo -e "${YELLOW}[SQLMap $total_sql/$URL_COUNT] Analizando: $url${NC}"
    mkdir -p "$PROJECT_DIR/sqlmap"
    sqlmap_output=$(sqlmap -u "$url" --batch --level=3 --risk=2 --dbs --random-agent --output-dir="$PROJECT_DIR/sqlmap" 2>&1)
    echo "$sqlmap_output" >> "$LOG_FILE"
    echo "$sqlmap_output" | grep -Ei "parameter '[^']+' is vulnerable|is vulnerable|sql injection" && {
        echo "$url" >> "$SQLI_FILE"
    }
done < "$PARAM_URLS_FILE"

SQLI_TOTAL=$(grep -c "http" "$SQLI_FILE" 2>/dev/null || echo 0)

# ========= Reporte Markdown ========= #
echo -e "${BLUE}[*] Generando reporte Markdown...${NC}"
{
echo "# 🕵️ Bounty Hunter Report"
echo "**Objetivo:** \`$DOMAIN\`"
echo "## 📊 Resumen"
echo "| Métrica | Cantidad |"
echo "|---------|----------|"
[[ "$MODE" == "domain" ]] && echo "| Subdominios encontrados | $SUBTOTAL |"
[[ "$MODE" == "domain" ]] && echo "| Subdominios activos     | $LIVE_TOTAL |"
echo "| URLs con parámetros     | $URL_COUNT |"
echo "| XSS vulnerabilidades    | $XSS_TOTAL |"
echo "| SQLi vulnerabilidades   | $SQLI_TOTAL |"
echo "| WAFs detectados         | $DETECTED_WAFS |"
} > "$MD_FILE"

echo -e "${GREEN}[✔] Todo listo. Resultados en: $PROJECT_DIR${NC}"
