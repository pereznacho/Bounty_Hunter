"""
Filtros personalizados para las plantillas Jinja2
"""
import re
from bs4 import BeautifulSoup
from starlette.templating import Jinja2Templates

def clean_nuclei_output(content: str) -> str:
    """
    Limpia la salida de nuclei removiendo etiquetas HTML y códigos ANSI
    """
    # Remover todas las etiquetas HTML
    content = re.sub(r'<[^>]+>', '', content)
    # Remover códigos ANSI de colores (tanto \x1b como [)
    content = re.sub(r'\x1b\[[0-9;]*m', '', content)
    # Remover códigos ANSI sin el escape (\x1b)
    content = re.sub(r'\[[0-9;]*m', '', content)
    return content

def clean_html_malformed_spans(html_content: str) -> str:
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.prettify()

def clean_xss_output(content: str) -> str:
    """
    Limpia la salida de XSS removiendo tags HTML malformados y códigos ANSI,
    preservando solo el contenido de texto limpio
    """
    # Primero remover todos los códigos ANSI
    content = re.sub(r'\x1b\[[0-9;]*m', '', content)
    
    # Remover todas las etiquetas HTML existentes (incluidas las malformadas)
    content = re.sub(r'<[^>]*>', '', content)
    
    # Limpiar patrones específicos de XSS tools
    content = re.sub(r'\[[\+\-\!]*\]', '', content)  # Remover [++], [!], etc.
    
    # Limpiar múltiples espacios y líneas vacías
    content = re.sub(r'\n\s*\n', '\n', content)  # Múltiples líneas vacías
    content = re.sub(r' +', ' ', content)  # Múltiples espacios
    
    # Limpiar líneas que solo contienen espacios o símbolos
    lines = content.split('\n')
    cleaned_lines = []
    for line in lines:
        line = line.strip()
        if line and not re.match(r'^[-=_\s]*$', line):  # Ignorar líneas solo con separadores
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def setup_template_filters(templates: Jinja2Templates):
    """
    Configura todos los filtros personalizados para las plantillas Jinja2
    """
    templates.env.filters["clean_nuclei"] = clean_nuclei_output
    templates.env.filters["clean_html"] = clean_html_malformed_spans
    templates.env.filters["clean_xss"] = clean_xss_output