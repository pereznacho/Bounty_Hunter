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

# Banner de inicio
clear
echo -e "${YELLOW}"

echo "██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗" 
echo "██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
echo "██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
echo "██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
echo "██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
echo "╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
echo ""
echo -e "${BLUE}                            BugBounty Automation Tool - by Ignacio Pérez${NC}"
echo "" 


trap "echo -e '\n${RED}[✘] Proceso interrumpido por el usuario. Saliendo...${NC}'; exit 1" SIGINT

# Verificación de argumentos
if [[ "$1" == "-d" && -n "$2" ]]; then
    MODE="domain"
    DOMAIN="$2"
elif [[ "$1" == "-u" && -n "$2" ]]; then
    MODE="url"
    TARGET_URL="$2"
else
    echo -e "${RED}[!] Uso inválido. Ejemplos:${NC}"
    echo -e "${YELLOW}    ./bugbounty_automation.sh -d dominio.com${NC}"
    echo -e "${YELLOW}    ./bugbounty_automation.sh -u \"http://example.com/index.php?id=1\"${NC}"
    exit 1
fi

# Configuración común
if [[ "$MODE" == "domain" ]]; then
    PROJECT_DIR="./recon/$DOMAIN"
else
    DOMAIN=$(echo "$TARGET_URL" | awk -F/ '{print $3}')
    PROJECT_DIR="./recon/$DOMAIN"
fi

SUBS_FILE="$PROJECT_DIR/subdomains.txt"
LIVE_FILE="$PROJECT_DIR/live_subdomains.txt"
URLS_FILE="$PROJECT_DIR/urls.txt"
PARAM_URLS_FILE="$PROJECT_DIR/param_urls.txt"
LOG_FILE="$PROJECT_DIR/output.log"
XSS_FILE="$PROJECT_DIR/xss_vulnerables.txt"
SQLI_FILE="$PROJECT_DIR/sql_vulnerables.txt"
SUMMARY="$PROJECT_DIR/summary.txt"

mkdir -p "$PROJECT_DIR"

# ===== MODO COMPLETO: DOMINIO =====
if [[ "$MODE" == "domain" ]]; then
    echo -e "${BLUE}[*] Buscando subdominios para: $DOMAIN...${NC}"
    subfinder -d "$DOMAIN" -silent > "$SUBS_FILE"
    SUBTOTAL=$(wc -l < "$SUBS_FILE")
    echo -e "${GREEN}[✔] Subdominios encontrados: $SUBTOTAL${NC}"

    echo -e "${BLUE}[*] Verificando subdominios activos...${NC}"
    > "$LIVE_FILE"
    COUNT=0
    while read -r sub; do
        COUNT=$((COUNT+1))
        for proto in http https; do
            url="${proto}://${sub}"
            echo -e "${YELLOW}[${COUNT}/${SUBTOTAL}] → Probando: $url${NC}"
            status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url")
            if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" ]]; then
                echo "$url" >> "$LIVE_FILE"
                echo -e "${GREEN}[✔] Activo ($status): $url${NC}"
            else
                echo -e "${RED}[✘] Inactivo ($status): $url${NC}"
            fi
        done
    done < "$SUBS_FILE"

    sort -u "$LIVE_FILE" -o "$LIVE_FILE"
    LIVE_TOTAL=$(wc -l < "$LIVE_FILE")
    echo -e "${GREEN}[✔] Subdominios activos: $LIVE_TOTAL${NC}"
fi


# ===== Paso 3: Recolección con Katana =====
echo -e "${BLUE}[*] Obteniendo URLs con Katana...${NC}"
> "$URLS_FILE"

if [[ "$MODE" == "domain" ]]; then
    while read -r live; do
        echo -e "${YELLOW}[Katana] Analizando: $live${NC}"
        katana -u "$live" -jc -kf all -d 3 -silent >> "$URLS_FILE" 2>/dev/null
    done < "$LIVE_FILE"
else
    echo -e "${YELLOW}[Katana] Analizando: $TARGET_URL${NC}"
    katana -u "$TARGET_URL" -jc -kf all -d 3 -silent >> "$URLS_FILE" 2>/dev/null
fi

sort -u "$URLS_FILE" -o "$URLS_FILE"
grep '=' "$URLS_FILE" > "$PARAM_URLS_FILE"
URL_COUNT=$(wc -l < "$PARAM_URLS_FILE")

if [ "$URL_COUNT" -eq 0 ]; then
    echo -e "${RED}[✘] No se encontraron URLs con parámetros para analizar. Saliendo...${NC}"
    exit 1
fi

echo -e "${GREEN}[✔] URLs con parámetros encontradas: $URL_COUNT${NC}"


# ===== Verificación de wafw00f =====
if ! command -v wafw00f &> /dev/null; then
    echo -e "${BLUE}[*] wafw00f no está instalado. Instalando...${NC}"
    pip install wafw00f &>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✔] wafw00f instalado correctamente.${NC}"
    else
        echo -e "${RED}[✘] Error al instalar wafw00f. Debes instalarlo manualmente.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[✔] wafw00f está disponible en el sistema.${NC}"
fi

# ===== Paso adicional: Detección de WAF con wafw00f =====
echo -e "${BLUE}[*] Iniciando detección de WAFs con wafw00f...${NC}"
WAF_LOG="$PROJECT_DIR/waf_detection.txt"
> "$WAF_LOG"

DETECTED_WAFS=0

while read -r url; do
    echo -e "${YELLOW}[WAF] Analizando: $url${NC}"
    result=$(wafw00f "$url" 2>/dev/null)

    if echo "$result" | grep -iq "is behind a"; then
        echo -e "${RED}[⚠] WAF detectado en: $url${NC}"
        echo "$result" >> "$WAF_LOG"
        DETECTED_WAFS=$((DETECTED_WAFS + 1))
    else
        echo -e "${GREEN}[✔] Sin WAF detectado: $url${NC}"
    fi
done < "$PARAM_URLS_FILE"

echo -e "${BLUE}[i] Total de WAFs detectados: $DETECTED_WAFS${NC}"



# ===== Verificación de XSStrike =====
XS_PATH="/usr/share/XSStrike"

if [ ! -d "$XS_PATH" ]; then
    echo -e "${BLUE}[*] XSStrike no encontrado en $XS_PATH. Descargando...${NC}"
    git clone https://github.com/s0md3v/XSStrike.git "$XS_PATH" &>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✔] XSStrike clonado correctamente en $XS_PATH${NC}"
    else
        echo -e "${RED}[✘] Error al clonar XSStrike. Verifica tu conexión o permisos.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[✔] XSStrike ya está instalado en: $XS_PATH${NC}"
fi



# ===== Paso 4: Fuzz con XSStrike =====
echo -e "${BLUE}[*] Fuzzeando con XSStrike...${NC}"
> "$XSS_FILE"
current_xss=0

while read -r url; do
    ((current_xss++))
    echo -e "${YELLOW}[XSStrike $current_xss/$URL_COUNT] Probando: $url${NC}"

    result=$(python /usr/share/XSStrike/xsstrike.py -u "$url" --crawl 2>/dev/null)
    echo "$result" | tee -a "$LOG_FILE"

    if echo "$result" | grep -iq "Vulnerable webpage:"; then
        echo -e "${RED}[XSS] Vulnerabilidad encontrada en: $url${NC}"
        echo -e "${YELLOW}🧪 Payloads detectados:${NC}"
        echo "$result" | grep -A5 "Vulnerable webpage:"

        {
            echo "========================================"
            echo "💥 URL vulnerable a XSS:"
            echo "$url"
            echo "🧪 Payloads detectados:"
            echo "$result" | grep -A5 "Vulnerable webpage:"
            echo "========================================"
            echo ""
        } >> "$XSS_FILE"
    fi
done < "$PARAM_URLS_FILE"

XSS_TOTAL=$(grep -c "💥 URL vulnerable" "$XSS_FILE" 2>/dev/null || echo 0)

# ===== Paso 5: SQLMap =====
echo -e "${BLUE}[*] Revisando con SQLMap...${NC}"
> "$SQLI_FILE"
total_sql=0

while read -r url; do
    ((total_sql++))
    echo -e "${YELLOW}[SQLMap $total_sql/$URL_COUNT] Analizando: $url${NC}"

    output_dir="$PROJECT_DIR/sqlmap"
    mkdir -p "$output_dir"

    sqlmap_output=$(sqlmap -u "$url" --batch --level=3 --risk=2 --random-agent --dbs --output-dir="$output_dir" 2>&1)
    echo "$sqlmap_output" >> "$LOG_FILE"

    # Detectar vulnerabilidad buscando frases comunes
    if echo "$sqlmap_output" | grep -Ei "parameter '[^']+' is vulnerable|is vulnerable|sql injection"; then
        echo -e "${RED}[SQLi] Vulnerabilidad detectada en: $url${NC}"

        # Extraer payload
        payload=$(echo "$sqlmap_output" | grep -i "Payload:" | head -n1 | cut -d ":" -f2- | xargs)

        # Extraer parámetros si están
        param=$(echo "$sqlmap_output" | grep -i "parameter" | head -n1)

        # Extraer bases de datos listadas
        dbs=$(echo "$sqlmap_output" | awk '/available databases/,0' | grep -E "^\[\*\]")

        {
            echo "========================================"
            echo "💥 URL vulnerable a SQLi:"
            echo "$url"
            echo "🧪 Payload utilizado:"
            echo "$payload"
            echo "🧩 Parámetro:"
            echo "$param"
            echo "📚 Bases de datos encontradas:"
            echo "$dbs"
            echo "========================================"
            echo ""
        } >> "$SQLI_FILE"
    fi
done < "$PARAM_URLS_FILE"

SQLI_TOTAL=$(grep -c "💥 URL vulnerable" "$SQLI_FILE" 2>/dev/null || echo 0)

# ===== Paso 6: Resumen final =====
echo -e "${BLUE}[*] Generando resumen final...${NC}"

{
    echo "----------------------------------------------"
    echo "Resumen para: $DOMAIN"
    echo "----------------------------------------------"
    [[ "$MODE" == "domain" ]] && echo -e "🔹 Subdominios encontrados\t:\t$SUBTOTAL"
    [[ "$MODE" == "domain" ]] && echo -e "🔹 Subdominios activos    \t:\t$LIVE_TOTAL"
    echo -e "🔹 URLs con parámetros    \t:\t$URL_COUNT"
    echo -e "🔹 XSS vulnerabilidades   \t:\t$XSS_TOTAL"
    echo -e "🔹 SQLi vulnerabilidades  \t:\t$SQLI_TOTAL"
    echo -e "🔹 WAFs detectados        \t:\t$DETECTED_WAFS"
    echo "----------------------------------------------"
} | column -t -s $'\t' | tee "$SUMMARY"

# Sugerencia si hay WAFs detectados
if [[ "$DETECTED_WAFS" -gt 0 ]]; then
    echo -e "${YELLOW}[!] Se detectaron WAFs en algunas URLs. Verifica $PROJECT_DIR/waf_detection.txt${NC}"
fi

echo -e "${GREEN}[✔] Todos los resultados están en: $PROJECT_DIR${NC}"

# ===== Generación de archivo Markdown =====
MD_FILE="$PROJECT_DIR/resultados.md"
echo -e "${BLUE}[*] Generando archivo Markdown: $MD_FILE${NC}"

{
echo "# 🕵️ Bounty Hunter Report"
echo ""
echo "**Objetivo:** \`$DOMAIN\`"
echo ""
echo "## 📊 Resumen"
echo "| Métrica                  | Cantidad |"
echo "|--------------------------|----------|"
[[ "$MODE" == "domain" ]] && echo "| Subdominios encontrados  | $SUBTOTAL |"
[[ "$MODE" == "domain" ]] && echo "| Subdominios activos      | $LIVE_TOTAL |"
echo "| URLs con parámetros      | $URL_COUNT |"
echo "| XSS vulnerabilidades     | $XSS_TOTAL |"
echo "| SQLi vulnerabilidades    | $SQLI_TOTAL |"
echo "| WAFs detectados          | $DETECTED_WAFS |"

echo ""
[[ "$MODE" == "domain" ]] && echo "## 🌐 Subdominios encontrados" && echo '```' && cat "$SUBS_FILE" && echo '```'
[[ "$MODE" == "domain" ]] && echo "" && echo "## ✅ Subdominios activos" && echo '```' && cat "$LIVE_FILE" && echo '```'

echo ""
echo "## 🔍 URLs con parámetros"
echo '```'
cat "$PARAM_URLS_FILE"
echo '```'

# === XSS Detallado
if [[ "$XSS_TOTAL" -gt 0 ]]; then
    echo ""
    echo "## 🧪 XSS Vulnerabilidades"
    echo ""
    awk '/💥 URL vulnerable a XSS:/,/========================================/' "$XSS_FILE" |
    sed 's/^/    /' |
    sed 's/========================================/---/' |
    sed 's/💥 /- /;s/🧪 /  * /' |
    awk '{print}' >> "$MD_FILE"
fi

# === SQLi Detallado
if [[ "$SQLI_TOTAL" -gt 0 ]]; then
    echo ""
    echo "## 💉 SQLi Vulnerabilidades"
    echo ""
    awk '/💥 URL vulnerable a SQLi:/,/========================================/' "$SQLI_FILE" |
    sed 's/^/    /' |
    sed 's/========================================/---/' |
    sed 's/💥 /- /;s/🧪 /  * /;s/🧩 /  * /;s/📚 /  * /' |
    awk '{print}' >> "$MD_FILE"
fi

# === WAFs
if [[ "$DETECTED_WAFS" -gt 0 ]]; then
    echo ""
    echo "## 🛡️ Detecciones de WAF"
    echo '```'
    cat "$WAF_LOG"
    echo '```'
fi

} > "$MD_FILE"

echo -e "${GREEN}[✔] Archivo Markdown generado: $MD_FILE${NC}"
