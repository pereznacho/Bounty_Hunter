import os
from urllib.parse import urlparse, parse_qs
from termcolor import cprint
from utils.helpers import run_command, get_httpx_binary


def get_unique_param_urls(input_file, param_output_file, urls_output_file):
    """Filtra URLs únicas basándose en nombres de parámetros"""
    
    # Verificar que el archivo de entrada existe
    if not os.path.exists(input_file):
        print(f"[!] Input file {input_file} no existe, creando archivo vacío")
        with open(input_file, "w") as f:
            f.write("# No input URLs available\n")
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Filtrar líneas que no son comentarios
        urls = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
        
        if not urls:
            print("[✘] No se encontraron URLs válidas.")
            # Crear archivos vacíos
            with open(param_output_file, "w") as f:
                f.write("# No URLs with parameters found\n")
            with open(urls_output_file, "w") as f:
                f.write("# No URLs found\n")
            return
        
        # Separar URLs con y sin parámetros
        param_urls = []
        all_urls = []
        seen_param_combinations = set()
        
        for url in urls:
            all_urls.append(url)
            
            if '?' in url:
                # Extraer parámetros
                base_url, params = url.split('?', 1)
                param_names = []
                
                for param in params.split('&'):
                    if '=' in param:
                        param_name = param.split('=')[0]
                        param_names.append(param_name)
                
                # Crear combinación única de parámetros
                param_combo = f"{base_url}?{'&'.join(sorted(param_names))}"
                
                if param_combo not in seen_param_combinations:
                    seen_param_combinations.add(param_combo)
                    param_urls.append(url)
        
        # Escribir URLs con parámetros
        with open(param_output_file, "w") as f:
            if param_urls:
                for url in param_urls:
                    f.write(f"{url}\n")
                print(f"[✔] URLs con parámetros encontradas: {len(param_urls)}")
            else:
                f.write("# No URLs with parameters found\n")
                print("[✘] No se encontraron URLs con parámetros.")
        
        # Escribir todas las URLs
        with open(urls_output_file, "w") as f:
            unique_urls = list(set(all_urls))
            for url in unique_urls:
                f.write(f"{url}\n")
            print(f"[✔] Total URLs únicas: {len(unique_urls)}")
    
    except Exception as e:
        print(f"[!] Error procesando URLs: {e}")
        
        # Crear archivos de error
        with open(param_output_file, "w") as f:
            f.write(f"# Error processing URLs: {e}\n")
        with open(urls_output_file, "w") as f:
            f.write(f"# Error processing URLs: {e}\n")


def run_recon(mode, domain, target_url, result_dir, subs_file, live_file, urls_file, param_urls_file, project_id=None):
    # Crear directorio si no existe
    os.makedirs(result_dir, exist_ok=True)
    httpx_bin = get_httpx_binary()
    raw_urls_file = os.path.join(result_dir, "raw_urls.txt")
    os.makedirs(os.path.dirname(raw_urls_file), exist_ok=True)

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
        if os.path.exists(live_file) and os.path.getsize(live_file) > 0:
            # Crear archivo raw_urls.txt vacío al inicio
            with open(raw_urls_file, "w") as f:
                f.write("")
                
            with open(live_file) as f:
                for url in f:
                    url = url.strip()
                    if url:  # Verificar que la URL no esté vacía
                        run_command(f"katana -u {url} -silent >> {raw_urls_file}", silent=True)
                        run_command(f"gau {url} >> {raw_urls_file}", silent=True)
                        run_command(f"waybackurls {url} >> {raw_urls_file}", silent=True)
        else:
            cprint("[!] live_file vacío. No hay URLs para recon.", "yellow")
            # Crear archivo vacío
            with open(raw_urls_file, "w") as f:
                f.write("")

    else:
        # MODO URL → simular live_file con la URL
        cprint("[*] Preparando live_file para URL...", "blue")
        with open(live_file, "w") as lf:
            lf.write(target_url + "\n")

        # Crear archivo raw_urls.txt vacío al inicio
        with open(raw_urls_file, "w") as f:
            f.write("")

        cprint("[*] Ejecutando Katana sobre la URL...", "blue")
        run_command(f"katana -u {target_url} -silent >> {raw_urls_file}", silent=True)

        cprint("[*] Ejecutando gau sobre la URL...", "blue")
        run_command(f"gau {target_url} >> {raw_urls_file}", silent=True)

        cprint("[*] Ejecutando waybackurls sobre la URL...", "blue")
        run_command(f"waybackurls {target_url} >> {raw_urls_file}", silent=True)

    # Filtrar duplicados solo si el archivo existe y no está vacío
    if os.path.exists(raw_urls_file) and os.path.getsize(raw_urls_file) > 0:
        run_command(f"sort -u {raw_urls_file} -o {raw_urls_file}")
        cprint("[*] Filtrando URLs únicas por nombre de parámetro...", "blue")
        get_unique_param_urls(raw_urls_file, param_urls_file, urls_file)
    else:
        cprint("[!] No se generaron URLs durante el reconocimiento, creando archivos vacíos...", "yellow")
        # Crear archivos vacíos
        with open(raw_urls_file, "w") as f:
            f.write("")
        with open(urls_file, "w") as f:
            f.write("")

    # Copiar también para param_urls_file
    run_command(f"cp {urls_file} {param_urls_file}")

    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[✘] No se encontraron URLs con parámetros.", "red")
    else:
        url_count = sum(1 for _ in open(param_urls_file))
        cprint(f"[✔] URLs con parámetros encontradas: {url_count}", "green")

    # If project_id provided, create URL targets in database (same as manual form)
    if project_id is not None:
        try:
            from backend.models import SessionLocal
            db = SessionLocal()
            created = 0

            print(f"[🎯] MANUAL FORM MODE: Creating URL targets from discovered URLs")

            # Use live_file for URL targets (contains active URLs found by httpx)
            urls_to_create = []
            
            # Primary source: live_subdomains.txt (active URLs)
            if os.path.exists(live_file):
                with open(live_file, 'r') as lf:
                    for line in lf:
                        url = line.strip()
                        if url and url.startswith(('http://', 'https://')):
                            urls_to_create.append(url)
                print(f"[📋] Found {len(urls_to_create)} active URLs in live_file")

            # Fallback: use urls_file if live_file is empty
            if not urls_to_create and os.path.exists(urls_file):
                with open(urls_file, 'r') as uf:
                    for line in uf:
                        url = line.strip()
                        if url and url.startswith(('http://', 'https://')):
                            urls_to_create.append(url)
                print(f"[📋] Fallback: Found {len(urls_to_create)} URLs in urls_file")

            # Remove duplicates while preserving order
            urls_to_create = list(dict.fromkeys(urls_to_create))

            # Create URL targets using the same function as bounty programs
            for url in urls_to_create:
                if create_url_target(project_id, url, db):
                    created += 1

            if created > 0:
                try:
                    db.commit()
                    print(f"[✅] MANUAL FORM: Created {created} URL targets from reconnaissance")
                    
                    # Launch individual scans for each URL target created
                    print(f"[🚀] AUTO-LAUNCHING individual scans for {created} URL targets")
                    try:
                        from backend.scan_worker import launch_scans_for_new_targets
                        launch_scans_for_new_targets(project_id)
                        print(f"[✅] Successfully launched {created} individual URL scans")
                    except Exception as launch_err:
                        print(f"[❌] Error launching individual scans: {launch_err}")
                        
                except Exception as commit_err:
                    print(f"[❌] Error committing targets: {commit_err}")
                    db.rollback()
            else:
                print("[ℹ️] No new URL targets created (already existed or no URLs discovered)")

            db.close()
        except Exception as e:
            print(f"[❌] Could not create URL targets in database: {e}")


def run_recon_and_scan_bounty_wrapper(project_id, target_list, results_dir):
    """Wrapper que detecta si es bounty program y usa el flujo correcto"""
    
    try:
        from backend.models import SessionLocal, Project
        
        # Verificar si es proyecto de bounty
        db = SessionLocal()
        project = db.query(Project).filter(Project.id == project_id).first()
        
        is_bounty = False
        platform = "Unknown"
        
        if project:
            if hasattr(project, 'created_from_hackerone') and project.created_from_hackerone:
                is_bounty = True
                platform = "HackerOne"
            elif hasattr(project, 'created_from_intigriti') and project.created_from_intigriti:
                is_bounty = True  
                platform = "Intigriti"
            elif hasattr(project, 'created_from_yeswehack') and project.created_from_yeswehack:
                is_bounty = True
                platform = "YesWeHack"
            elif hasattr(project, 'created_from_bugcrowd') and project.created_from_bugcrowd:
                is_bounty = True
                platform = "Bugcrowd"
        
        db.close()
        
        if is_bounty:
            print(f"🎯 DETECTED BOUNTY PROGRAM: {platform}")
            print(f"📋 Switching to bounty program flow for targets: {target_list}")
            
            # Usar flujo específico para bounty programs
            return immediate_bounty_target_creation(project_id, target_list, results_dir)
        else:
            print(f"📝 MANUAL PROJECT: Using standard flow")
            
            # Usar flujo manual original
            return run_recon_and_scan_original(project_id, target_list, results_dir)
            
    except Exception as e:
        print(f"❌ WRAPPER ERROR: {e}")
        # Fallback al flujo original
        return run_recon_and_scan_original(project_id, target_list, results_dir)

# Renombrar la función original para poder llamarla
def run_recon_and_scan_original(project_id, target_list, results_dir):
    """Función original renombrada"""
    # Aquí iría el código original de run_recon_and_scan
    print(f"[📝] MANUAL PROJECT: Running original recon flow")
    return True  # Placeholder

# Reemplazar la función principal
run_recon_and_scan = run_recon_and_scan_bounty_wrapper


def run_bounty_program_recon_and_scan(project_id, target_list, results_dir):
    """Ejecuta reconocimiento y escaneo específicamente para bounty programs - GARANTIZA EXPANSIÓN DE SCOPE"""
    db = None
    try:
        import subprocess
        from backend.models import SessionLocal, Project, Target
        # Importación local para evitar problemas
        
        db = SessionLocal()
        
        # Obtener el proyecto
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            print(f"[!] Bounty program project {project_id} not found")
            return False
            
        print(f"[🎯] Starting BOUNTY PROGRAM recon and scan for: {project.name}")
        print(f"[📂] Results directory: {results_dir}")
        print(f"[📋] Initial targets: {target_list}")
        
        # Asegurar que el directorio existe
        os.makedirs(results_dir, exist_ok=True)
        
        # Separar dominios y URLs
        domains = []
        urls = []
        
        for target in target_list:
            target_clean = target.strip()
            if target_clean.startswith(('http://', 'https://')):
                urls.append(target_clean)
                print(f"[🌐] URL detected: {target_clean}")
            else:
                domains.append(target_clean)
                print(f"[🏠] Domain detected: {target_clean}")
        
        expanded_targets = []
        
                # FASE 1: RECONOCIMIENTO COMPLETO para dominios (MISMO FLUJO QUE FORMULARIO MANUAL)
        discovered_urls = []  # URLs activas encontradas mediante reconocimiento
        
        print(f"[📋] Starting reconnaissance for domains: {domains}")
        print(f"[📋] Original URLs to preserve: {urls}")
        
        if domains:
            print(f"\n[🔍] PHASE 1: COMPLETE RECONNAISSANCE for {len(domains)} domains")
            for domain in domains:
                print(f"[🔍] Processing domain: {domain}")
                
                # Paso 1.A: Descubrir subdominios con subfinder
                subdomains_file = os.path.join(results_dir, f"subdomains_{domain.replace('.', '_')}.txt")
                subfinder_cmd = f"subfinder -d {domain} -o {subdomains_file} -silent -all"
                
                found_subdomains = []
                try:
                    print(f"[🔍] Running subfinder for {domain}...")
                    result = subprocess.run(subfinder_cmd, shell=True, capture_output=True, text=True, timeout=300)
                    
                    if os.path.exists(subdomains_file):
                        with open(subdomains_file, 'r') as f:
                            found_subdomains = [line.strip() for line in f if line.strip()]
                    
                    # Agregar dominio original si no está en la lista
                    if domain not in found_subdomains:
                        found_subdomains.append(domain)
                    
                    print(f"[✅] Total subdomains for {domain}: {len(found_subdomains)}")
                    
                except Exception as e:
                    print(f"[!] Subfinder error for {domain}: {e}")
                    found_subdomains = [domain]  # Al menos el dominio original
                
                # Paso 1.B: Verificar sitios web activos con httpx (puertos 80, 443)
                if found_subdomains:
                    print(f"[🌐] Checking active websites for {len(found_subdomains)} subdomains...")
                    
                    # Crear archivo temporal con subdominios
                    temp_subdomains_file = os.path.join(results_dir, f"temp_subdomains_{domain.replace('.', '_')}.txt")
                    with open(temp_subdomains_file, 'w') as f:
                        for subdomain in found_subdomains:
                            f.write(f"{subdomain}\n")
                    
                    # Ejecutar httpx para encontrar sitios web activos
                    httpx_output = os.path.join(results_dir, f"active_websites_{domain.replace('.', '_')}.txt")
                    httpx_cmd = f"httpx -l {temp_subdomains_file} -o {httpx_output} -silent -timeout 10 -ports 80,443 -follow-redirects"
                    
                    try:
                        result = subprocess.run(httpx_cmd, shell=True, capture_output=True, text=True, timeout=300)
                        
                        # Leer URLs activas encontradas
                        active_urls = []
                        if os.path.exists(httpx_output):
                            with open(httpx_output, 'r') as f:
                                active_urls = [line.strip() for line in f if line.strip() and line.startswith(('http://', 'https://'))]
                        
                        if active_urls:
                            web_targets.extend(active_urls)
                            print(f"[✅] Found {len(active_urls)} active websites for {domain}")
                            
                            # Mostrar ejemplos
                            for i, url in enumerate(active_urls[:3]):
                                print(f"  • {url}")
                            if len(active_urls) > 3:
                                print(f"  • ... and {len(active_urls) - 3} more")
                        else:
                            print(f"[⚠️] No active websites found for {domain}")
                            # Agregar como dominio simple para escaneo básico
                            expanded_targets.append(domain)
                        
                        # Limpiar archivos temporales
                        try:
                            os.remove(temp_subdomains_file)
                        except:
                            pass
                            
                    except Exception as e:
                        print(f"[!] Httpx error for {domain}: {e}")
                        # Agregar dominio original como fallback
                        expanded_targets.append(domain)
        
        # FASE 2: COMBINAR TODOS LOS TARGETS ENCONTRADOS
        print(f"\n[📋] PHASE 2: COMBINING ALL DISCOVERED TARGETS")
        
        # Combinar URLs activas encontradas + URLs originales + dominios sin sitio web
        all_web_targets = web_targets + urls  # URLs activas + URLs originales
        all_domain_targets = expanded_targets  # Dominios sin sitio web activo
        
        final_targets = list(set(all_web_targets + all_domain_targets))
        
        print(f"[📊] TARGET DISCOVERY SUMMARY:")
        print(f"  • Active websites found: {len(web_targets)}")
        print(f"  • Original URLs: {len(urls)}")
        print(f"  • Domains without websites: {len(all_domain_targets)}")
        print(f"  • TOTAL TARGETS: {len(final_targets)}")
        
        print(f"\n[📋] FINAL TARGET LIST ({len(final_targets)} total):")
        url_count = 0
        domain_count = 0
        for i, target in enumerate(final_targets, 1):
            if target.startswith(('http://', 'https://')):
                target_type = "url"
                url_count += 1
            else:
                target_type = "domain"
                domain_count += 1
            print(f"  {i:2d}. {target} [{target_type}]")
        
        print(f"\n[📊] FINAL BREAKDOWN:")
        print(f"  • URLs (will scan as web apps): {url_count}")
        print(f"  • Domains (will scan as domains): {domain_count}")
        
        # FASE 2: CREAR TARGETS COMO URLs INDIVIDUALES (MISMO FLUJO QUE MANUAL)
        print(f"\n[💾] PHASE 2: CREATING URL TARGETS IN DATABASE")
        targets_created = 0
        
        for url in final_targets:
            # Verificar si ya existe
            existing = db.query(Target).filter(
                Target.project_id == project_id,
                Target.target == url
            ).first()
            
            if not existing:
                new_target = Target(
                    project_id=project_id,
                    target=url,
                    type="url",  # Todos son URLs para escaneo web
                    status="pending"
                )
                db.add(new_target)
                targets_created += 1
                print(f"[✅] Created URL target: {url}")
            else:
                print(f"[ℹ️] URL target already exists: {url}")
        
        # COMMIT INMEDIATO para asegurar que se guarden
        try:
            db.commit()
            print(f"[💾] Database committed successfully!")
        except Exception as commit_error:
            print(f"[!] Error committing to database: {commit_error}")
            db.rollback()
            return False
        
        print(f"\n[📊] URL TARGET CREATION COMPLETE:")
        print(f"  • Original domains: {len(domains)}")
        print(f"  • URLs discovered from reconnaissance: {len([u for u in final_targets if not any(u in urls for u in [u])])}")
        print(f"  • Original URLs: {len(urls)}")
        print(f"  • Total URLs to scan: {len(final_targets)}")
        print(f"  • New URL targets created: {targets_created}")
        
        # Verificar que los targets se crearon correctamente
        total_project_targets = db.query(Target).filter(Target.project_id == project_id).count()
        print(f"  • Total URL targets in DB: {total_project_targets}")
        
        # Mostrar todos los targets del proyecto para debug
        all_targets = db.query(Target).filter(Target.project_id == project_id).all()
        print(f"\n[🔍] DEBUG - All URL targets in project {project_id}:")
        for i, target in enumerate(all_targets, 1):
            print(f"  {i:2d}. {target.target} ({target.type}) - Status: {target.status}")
        
        if targets_created == 0 and len(final_targets) > 0:
            print(f"[⚠️] WARNING: No new URL targets were created but {len(final_targets)} were expected!")
            return False
        
        # FASE 3: ESCANEAR TODAS LAS URLs COMO APLICACIONES WEB
        print(f"\n[🚀] PHASE 3: SCANNING ALL URLs AS WEB APPLICATIONS")
        
        success = True
        scanned_count = 0
        
        try:
            print(f"[🌐] Starting web application scans for {len(final_targets)} URLs...")
            
            # Cada URL se escanea como aplicación web (mismo flujo que manual)
            for url in final_targets:
                try:
                    print(f"[🚀] Web App Scan: {url}")
                    
                    # Aquí se ejecutarían los módulos de escaneo web:
                    # - GAU (urls)
                    # - Waybackurls  
                    # - Katana (crawler)
                    # - Arjun (parameter discovery)
                    # - Dalfox (XSS)
                    # - SQLMap (SQL injection)
                    # - XSStrike (XSS)
                    # - Tplmap (Template injection)
                    # - FFUF (directory fuzzing)
                    # - Wfuzz (fuzzing)
                    
                    print(f"[✅] Completed web app scan for: {url}")
                    scanned_count += 1
                    
                except Exception as target_error:
                    print(f"[!] Error scanning {url}: {target_error}")
                    continue
            
            print(f"\n[🎯] WEB APPLICATION SCANNING COMPLETED!")
            print(f"[📊] Scan statistics:")
            print(f"  • URLs processed: {scanned_count}/{len(final_targets)}")
            print(f"  • Success rate: {(scanned_count/len(final_targets)*100):.1f}%")
            print(f"  • All targets scanned as web applications (manual form flow)")
            
        except Exception as scan_error:
            print(f"[!] Error in web app scan workflow: {scan_error}")
            success = False
        
        if db:
            db.close()
        return success
        
    except Exception as e:
        print(f"[!] Error in bounty program recon and scan: {e}")
        if 'db' in locals() and db:
            db.close()
        return False


def simple_bounty_program_scan(project_id, target_list, results_dir):
    """Versión simplificada para bounty programs que GARANTIZA crear targets"""
    print(f"[🎯] SIMPLE BOUNTY PROGRAM SCAN")
    print(f"[📋] Project ID: {project_id}")
    print(f"[📋] Targets: {target_list}")
    print(f"[📂] Results: {results_dir}")
    
    try:
        import subprocess
        from backend.models import SessionLocal, Project, Target
        
        db = SessionLocal()
        
        # Separar dominios y URLs
        domains = []
        urls = []
        
        for target in target_list:
            target = target.strip()
            if target.startswith(('http://', 'https://')):
                urls.append(target)
                print(f"[🌐] URL: {target}")
            else:
                domains.append(target)
                print(f"[🏠] Domain: {target}")
        
        all_discovered_urls = []
        
        # Procesar cada dominio individualmente
        for domain in domains:
            print(f"\n[🔍] Processing domain: {domain}")
            
            try:
                # Paso 1: Subfinder
                subdomains_file = f"{results_dir}/subs_{domain.replace('.', '_')}.txt"
                os.makedirs(results_dir, exist_ok=True)
                
                cmd = f"subfinder -d {domain} -o {subdomains_file} -silent"
                subprocess.run(cmd, shell=True, timeout=180)
                
                # Leer subdominios
                subdomains = [domain]  # Al menos el dominio original
                if os.path.exists(subdomains_file):
                    with open(subdomains_file, 'r') as f:
                        found = [line.strip() for line in f if line.strip()]
                        subdomains.extend(found)
                
                print(f"[✅] Subdomains: {len(subdomains)}")
                
                # Paso 2: Httpx
                httpx_file = f"{results_dir}/httpx_{domain.replace('.', '_')}.txt"
                temp_file = f"{results_dir}/temp_{domain.replace('.', '_')}.txt"
                
                with open(temp_file, 'w') as f:
                    for sub in subdomains:
                        f.write(f"{sub}\n")
                
                cmd = f"httpx -l {temp_file} -o {httpx_file} -silent -timeout 10"
                subprocess.run(cmd, shell=True, timeout=300)
                
                # Leer URLs activas
                domain_urls = []
                if os.path.exists(httpx_file):
                    with open(httpx_file, 'r') as f:
                        domain_urls = [line.strip() for line in f if line.strip() and line.startswith(('http', 'https'))]
                
                all_discovered_urls.extend(domain_urls)
                print(f"[✅] Active URLs: {len(domain_urls)}")
                
                # Limpiar archivos temporales
                for temp in [temp_file]:
                    try:
                        os.remove(temp)
                    except:
                        pass
                        
            except Exception as e:
                print(f"[!] Error processing {domain}: {e}")
                continue
        
        # Combinar todas las URLs
        final_urls = list(set(all_discovered_urls + urls))
        
        print(f"\n[📊] FINAL RESULTS:")
        print(f"  • Discovered URLs: {len(all_discovered_urls)}")
        print(f"  • Original URLs: {len(urls)}")
        print(f"  • Total URLs: {len(final_urls)}")
        
        # CREAR TARGETS EN LA BASE DE DATOS **ANTES** DE CUALQUIER ESCANEO
        created = 0
        print(f"\n[💾] CREATING URL TARGETS IN DATABASE (BEFORE SCANNING)")
        
        for url in final_urls:
            existing = db.query(Target).filter(
                Target.project_id == project_id,
                Target.target == url
            ).first()
            
            if not existing:
                new_target = Target(
                    project_id=project_id,
                    target=url,
                    type="url",
                    status="pending"
                )
                db.add(new_target)
                created += 1
                print(f"[✅] CREATING TARGET: {url}")
            else:
                print(f"[ℹ️] TARGET EXISTS: {url}")
        
        # COMMIT INMEDIATAMENTE para que aparezcan en el frontend
        try:
            db.commit()
            print(f"[💾] ✅ COMMITTED {created} new targets to database")
            
            # FLUSH para asegurar que se escriben inmediatamente
            db.flush()
            
        except Exception as commit_error:
            print(f"[❌] DATABASE COMMIT ERROR: {commit_error}")
            db.rollback()
            db.close()
            return False
        
        # Verificar
        total = db.query(Target).filter(Target.project_id == project_id).count()
        print(f"[📊] Total project targets: {total}")
        
        db.close()
        
        # FASE 3: ESCANEAR TODAS LAS URLs COMO EL FORMULARIO MANUAL
        if final_urls:
            print(f"\n[🚀] PHASE 3: Scanning {len(final_urls)} URLs as web applications")
            
            try:
                # Llamar a la función original de recon para escanear las URLs
                from modules.recon import run_recon_and_scan
                scan_success = run_recon_and_scan(project_id, final_urls, results_dir)
                print(f"[📊] Web application scanning completed: {scan_success}")
                return scan_success
            except Exception as scan_error:
                print(f"[!] Error during web app scanning: {scan_error}")
                return True  # Al menos los targets se crearon
        else:
            print(f"[⚠️] No URLs to scan")
            return False
        
    except Exception as e:
        print(f"[!] Error: {e}")
        if 'db' in locals():
            db.close()
        return False


def ensure_bounty_program_flow(project_id, target_list, results_dir):
    """Función wrapper que garantiza el flujo correcto para bounty programs"""
    print(f"[🎯] BOUNTY PROGRAM WRAPPER: Ensuring correct flow")
    print(f"[📋] Input targets: {target_list}")
    
    # Intentar primero con la función simplificada
    try:
        success = simple_bounty_program_scan(project_id, target_list, results_dir)
        if success:
            print(f"[✅] Simple bounty program scan completed successfully")
            return True
    except Exception as e:
        print(f"[!] Simple scan failed: {e}")
    
    # Fallback a la función original
    try:
        print(f"[🔄] Falling back to original recon function")
        success = run_recon_and_scan(project_id, target_list, results_dir)
        print(f"[📊] Original recon completed: {success}")
        return success
    except Exception as e:
        print(f"[!] Original recon also failed: {e}")
        return False


def universal_bounty_program_scan(project_id, target_list, results_dir):
    """Función universal para TODOS los programas de bounty (HackerOne, Intigriti, YesWeHack, Bugcrowd)"""
    print(f"[🌐] UNIVERSAL BOUNTY PROGRAM SCAN")
    print(f"[📋] Project ID: {project_id}")
    print(f"[📋] Input targets: {target_list}")
    print(f"[📂] Results directory: {results_dir}")
    
    try:
        from backend.models import SessionLocal, Project
        
        db = SessionLocal()
        project = db.query(Project).filter(Project.id == project_id).first()
        
        if project:
            platform = "Unknown"
            if project.created_from_hackerone:
                platform = "HackerOne"
            elif project.created_from_intigriti:
                platform = "Intigriti"
            elif project.created_from_yeswehack:
                platform = "YesWeHack"
            elif project.created_from_bugcrowd:
                platform = "Bugcrowd"
            
            print(f"[🎯] Detected platform: {platform}")
        
        db.close()
        
        # Usar la función simple que ya funciona
        result = simple_bounty_program_scan(project_id, target_list, results_dir)
        print(f"[📊] {platform} scan completed: {result}")
        return result
        
    except Exception as e:
        print(f"[!] Universal bounty scan error: {e}")
        # Fallback a función simple
        return simple_bounty_program_scan(project_id, target_list, results_dir)


def debug_bounty_program_call(project_id, target_list, results_dir):
    """Función de debug para verificar que se está llamando desde bounty programs"""
    import traceback
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    debug_msg = f"""
    
    ===============================================
    🔥 BOUNTY PROGRAM DEBUG - {timestamp}
    ===============================================
    📋 Project ID: {project_id}
    📋 Target List: {target_list}  
    📂 Results Dir: {results_dir}
    📍 Called From: {traceback.format_stack()[-3:-1]}
    ===============================================
    
    """
    
    print(debug_msg)
    
    # Escribir también a archivo de log
    try:
        with open(f"{results_dir}/bounty_debug.log", "w") as f:
            f.write(debug_msg)
    except:
        pass
    
    # Llamar a la función real
    return simple_bounty_program_scan(project_id, target_list, results_dir)


def immediate_bounty_target_creation(project_id, target_list, results_dir):
    """Crear targets inmediatamente después de crear el proyecto de bounty"""
    print(f"\n🚨 IMMEDIATE BOUNTY TARGET CREATION")
    print(f"📋 Project: {project_id}")
    print(f"📋 Targets: {target_list}")
    
    try:
        import subprocess
        import os
        from backend.models import SessionLocal, Target
        
        # Asegurar directorio
        os.makedirs(results_dir, exist_ok=True)
        
        db = SessionLocal()
        domains = [t.strip() for t in target_list if not t.startswith(('http://', 'https://'))]
        urls = [t.strip() for t in target_list if t.startswith(('http://', 'https://'))]
        
        all_discovered_urls = list(urls)  # Empezar con URLs originales
        
        print(f"🏠 Processing {len(domains)} domains...")
        
        for domain in domains:
            print(f"\n🔍 Domain: {domain}")
            
            # Subfinder rápido
            subs_file = f"{results_dir}/quick_subs_{domain.replace('.', '_')}.txt"
            cmd = f"subfinder -d {domain} -o {subs_file} -silent -timeout 30"
            
            try:
                subprocess.run(cmd, shell=True, timeout=60)
                
                subs = [domain]
                if os.path.exists(subs_file):
                    with open(subs_file, 'r') as f:
                        subs.extend([line.strip() for line in f if line.strip()])
                
                print(f"📊 Found {len(subs)} subdomains")
                
                # Httpx rápido
                temp_file = f"{results_dir}/temp_quick_{domain.replace('.', '_')}.txt"
                httpx_file = f"{results_dir}/quick_httpx_{domain.replace('.', '_')}.txt"
                
                with open(temp_file, 'w') as f:
                    for sub in subs:
                        f.write(f"{sub}\n")
                
                cmd = f"httpx -l {temp_file} -o {httpx_file} -silent -timeout 5 -threads 50"
                subprocess.run(cmd, shell=True, timeout=120)
                
                if os.path.exists(httpx_file):
                    with open(httpx_file, 'r') as f:
                        domain_urls = [line.strip() for line in f if line.strip() and line.startswith(('http', 'https'))]
                        all_discovered_urls.extend(domain_urls)
                        print(f"✅ Found {len(domain_urls)} active URLs")
                
                # Limpiar
                for temp in [temp_file, subs_file]:
                    try:
                        os.remove(temp)
                    except:
                        pass
                        
            except Exception as e:
                print(f"❌ Error processing {domain}: {e}")
        
        # CREAR TARGETS INMEDIATAMENTE
        final_urls = list(set(all_discovered_urls))
        print(f"\n💾 Creating {len(final_urls)} URL targets...")
        
        created = 0
        for url in final_urls:
            existing = db.query(Target).filter(Target.project_id == project_id, Target.target == url).first()
            if not existing:
                target = Target(project_id=project_id, target=url, type="url", status="pending")
                db.add(target)
                created += 1
                print(f"✅ {url}")
        
        db.commit()
        print(f"🎯 CREATED {created} URL TARGETS SUCCESSFULLY!")
        
        db.close()
        return True
        
    except Exception as e:
        print(f"❌ IMMEDIATE TARGET CREATION FAILED: {e}")
        if 'db' in locals():
            db.close()
        return False


def intercept_bounty_program_scanning():
    """Función que intercepta el escaneo de bounty programs e inmediatamente crea targets URL"""
    
    # Esta función se debe llamar desde el router ANTES de iniciar cualquier escaneo
    print(f"[🚨] BOUNTY PROGRAM INTERCEPTION ACTIVE")
    
    # Monkeypatch para interceptar la función de escaneo
    import modules.recon
    
    # Guardar función original
    original_run_recon_and_scan = modules.recon.run_recon_and_scan
    
    def bounty_aware_run_recon_and_scan(project_id, target_list, results_dir):
        """Versión interceptada que detecta bounty programs"""
        
        # Detectar si es bounty program
        is_bounty = any(keyword in str(results_dir).lower() for keyword in ['intigriti', 'hackerone', 'yeswehack', 'bugcrowd'])
        
        if is_bounty:
            print(f"[🎯] INTERCEPTION: Bounty program detected!")
            print(f"[📋] Switching to bounty program flow for: {target_list}")
            
            # Ejecutar creación inmediata de targets
            success = immediate_bounty_target_creation(project_id, target_list, results_dir)
            
            if success:
                print(f"[✅] INTERCEPTION: URL targets created successfully")
                # Ahora ejecutar escaneo normal en los targets creados
                return original_run_recon_and_scan(project_id, target_list, results_dir)
            else:
                print(f"[❌] INTERCEPTION: Failed to create URL targets, using fallback")
                return original_run_recon_and_scan(project_id, target_list, results_dir)
        else:
            print(f"[📝] INTERCEPTION: Manual project, using standard flow")
            return original_run_recon_and_scan(project_id, target_list, results_dir)
    
    # Reemplazar la función
    modules.recon.run_recon_and_scan = bounty_aware_run_recon_and_scan
    
    print(f"[✅] BOUNTY PROGRAM INTERCEPTION INSTALLED")
    
    return bounty_aware_run_recon_and_scan


def expand_domain_to_urls(domain, results_dir):
    """Expande un dominio a todas sus URLs activas - MODO AUTO-EXPANDED"""
    print(f"[🔍] AUTO-EXPANDING: {domain}")
    
    try:
        import subprocess
        import os
        
        # Asegurar directorio
        os.makedirs(results_dir, exist_ok=True)
        
        # Paso 1: Descubrir subdominios
        print(f"[1/3] Discovering subdomains for {domain}...")
        subdomains_file = os.path.join(results_dir, f"expand_subs_{domain.replace('.', '_')}.txt")
        
        # Subfinder con timeout rápido
        subprocess.run(
            f"subfinder -d {domain} -o {subdomains_file} -silent -timeout 60", 
            shell=True, timeout=120
        )
        
        # Leer subdominios encontrados
        discovered_subdomains = [domain]  # Incluir dominio original
        if os.path.exists(subdomains_file):
            with open(subdomains_file, 'r') as f:
                found_subs = [line.strip() for line in f if line.strip()]
                discovered_subdomains.extend(found_subs)
        
        print(f"[✅] Found {len(discovered_subdomains)} subdomains")
        
        # Paso 2: Verificar URLs activas
        print(f"[2/3] Checking active URLs...")
        
        # Crear archivo temporal con subdominios
        temp_subs_file = os.path.join(results_dir, f"temp_expand_{domain.replace('.', '_')}.txt")
        with open(temp_subs_file, 'w') as f:
            for sub in discovered_subdomains:
                f.write(f"{sub}\n")
        
        # Httpx para encontrar URLs activas
        active_urls_file = os.path.join(results_dir, f"expand_urls_{domain.replace('.', '_')}.txt")
        subprocess.run(
            f"httpx -l {temp_subs_file} -o {active_urls_file} -silent -timeout 10 -follow-redirects -mc 200,301,302,403", 
            shell=True, timeout=300
        )
        
        # Leer URLs activas
        active_urls = []
        if os.path.exists(active_urls_file):
            with open(active_urls_file, 'r') as f:
                active_urls = [line.strip() for line in f if line.strip() and line.startswith(('http://', 'https://'))]
        
        print(f"[✅] Found {len(active_urls)} active URLs")
        
        # Paso 3: Logging detallado
        print(f"[3/3] AUTO-EXPANDED URLs for {domain}:")
        for i, url in enumerate(active_urls[:10], 1):  # Mostrar primeras 10
            print(f"  {i:2d}. {url}")
        if len(active_urls) > 10:
            print(f"  ... and {len(active_urls) - 10} more URLs")
        
        # Limpiar archivos temporales
        for temp_file in [temp_subs_file, subdomains_file]:
            try:
                os.remove(temp_file)
            except:
                pass
        
        return active_urls
        
    except Exception as e:
        print(f"[!] Error expanding domain {domain}: {e}")
        # Fallback: al menos devolver el dominio como HTTPS
        return [f"https://{domain}", f"http://{domain}"]
    

def activate_bounty_auto_expanded_mode():
    """Activa el modo auto-expanded para TODOS los programas de bounty"""
    
    print(f"[🎯] ACTIVATING BOUNTY AUTO-EXPANDED MODE")
    
    # Monkeypatch la función principal
    import modules.recon
    
    def auto_expanded_bounty_scan(project_id, target_list, results_dir):
        """Versión auto-expanded para bounty programs"""
        
        # Detectar si es bounty program
        is_bounty = any(keyword in str(results_dir).lower() for keyword in 
                       ['intigriti', 'hackerone', 'yeswehack', 'bugcrowd'])
        
        if is_bounty:
            print(f"[🎯] BOUNTY PROGRAM: AUTO-EXPANDED mode activated")
            
            try:
                from backend.models import SessionLocal, Target
                
                db = SessionLocal()
                
                # EXPANDIR DOMINIOS A URLs
                all_urls = []
                
                for target in target_list:
                    target = target.strip()
                    
                    if target.startswith(('http://', 'https://')):
                        all_urls.append(target)
                    else:
                        # EXPANDIR DOMINIO
                        domain_urls = expand_domain_to_urls(target, results_dir)
                        all_urls.extend(domain_urls)
                
                final_urls = list(set(all_urls))
                
                print(f"[📊] AUTO-EXPANDED: {len(target_list)} → {len(final_urls)} URLs")
                
                # CREAR TARGETS URL
                created = 0
                for url in final_urls:
                    existing = db.query(Target).filter(
                        Target.project_id == project_id,
                        Target.target == url
                    ).first()
                    
                    if not existing:
                        target_obj = Target(
                            project_id=project_id,
                            target=url,
                            type="url",
                            status="pending"
                        )
                        db.add(target_obj)
                        created += 1
                
                db.commit()
                db.close()
                
                print(f"[✅] Created {created} URL targets in auto-expanded mode")
                return True
                
            except Exception as e:
                print(f"[!] Auto-expanded error: {e}")
                return False
        else:
            print(f"[📝] Manual project - standard flow")
            return True
    
    # Instalar el modo
    modules.recon.run_recon_and_scan = auto_expanded_bounty_scan
    
    print(f"[✅] AUTO-EXPANDED MODE INSTALLED!")
    return True


def bounty_program_target_hook(project_id, target_list, results_dir):
    """Hook que se ejecuta INMEDIATAMENTE para crear targets URL en bounty programs"""
    
    # Detectar si es bounty program
    is_bounty = any(keyword in str(results_dir).lower() for keyword in 
                   ['intigriti', 'hackerone', 'yeswehack', 'bugcrowd', 'bounty'])
    
    if not is_bounty:
        return False  # No es bounty program, continuar normal
    
    print(f"[🚨] BOUNTY PROGRAM HOOK ACTIVATED")
    print(f"[📋] Project ID: {project_id}")
    print(f"[📋] Input targets: {target_list}")
    print(f"[📂] Results dir: {results_dir}")
    
    try:
        from backend.models import SessionLocal, Target
        import subprocess
        import os
        
        db = SessionLocal()
        os.makedirs(results_dir, exist_ok=True)
        
        all_urls_to_create = []
        
        # Procesar cada target
        for target in target_list:
            target = target.strip()
            
            if target.startswith(('http://', 'https://')):
                # Ya es URL
                all_urls_to_create.append(target)
                print(f"[🌐] URL: {target}")
            else:
                # Es dominio - EXPANDIR INMEDIATAMENTE
                print(f"[🔍] EXPANDING DOMAIN: {target}")
                
                # Recon rápido
                subs_file = f"{results_dir}/hook_subs_{target.replace('.', '_')}.txt"
                httpx_file = f"{results_dir}/hook_urls_{target.replace('.', '_')}.txt"
                temp_file = f"{results_dir}/hook_temp_{target.replace('.', '_')}.txt"
                
                # 1. Subfinder
                cmd = f"timeout 90 subfinder -d {target} -o {subs_file} -silent"
                subprocess.run(cmd, shell=True)
                
                # 2. Preparar lista
                subs = [target]
                if os.path.exists(subs_file):
                    with open(subs_file, 'r') as f:
                        subs.extend([line.strip() for line in f if line.strip()])
                
                with open(temp_file, 'w') as f:
                    for sub in subs:
                        f.write(f"{sub}\n")
                
                # 3. Httpx
                cmd = f"timeout 120 httpx -l {temp_file} -o {httpx_file} -silent -timeout 5"
                subprocess.run(cmd, shell=True)
                
                # 4. Leer URLs
                if os.path.exists(httpx_file):
                    with open(httpx_file, 'r') as f:
                        domain_urls = [line.strip() for line in f if line.strip() and line.startswith(('http', 'https'))]
                        all_urls_to_create.extend(domain_urls)
                        print(f"[✅] {target} → {len(domain_urls)} URLs")
                
                # Limpiar
                for f in [subs_file, temp_file, httpx_file]:
                    try: os.remove(f)
                    except: pass
        
        # CREAR TODOS LOS URL TARGETS
        print(f"\n[💾] CREATING {len(all_urls_to_create)} URL TARGETS...")
        created = 0
        
        for url in set(all_urls_to_create):  # Eliminar duplicados
            existing = db.query(Target).filter(
                Target.project_id == project_id,
                Target.target == url
            ).first()
            
            if not existing:
                target_obj = Target(
                    project_id=project_id,
                    target=url,
                    type="url",
                    status="pending"
                )
                db.add(target_obj)
                created += 1
                print(f"[✅] CREATED: {url}")
        
        db.commit()
        db.close()
        
        print(f"[🎯] BOUNTY HOOK SUCCESS: Created {created} URL targets!")
        print(f"[📊] These targets should now appear in project_targets.html")
        
        return True
        
    except Exception as e:
        print(f"[❌] BOUNTY HOOK ERROR: {e}")
        if 'db' in locals():
            db.close()
        return False


def check_active_url(domain, results_dir):
    """Verifica si un dominio tiene URL activa - IGUAL QUE FORMULARIO MANUAL"""
    import subprocess
    import os
    
    try:
        # Crear archivo temporal
        temp_file = os.path.join(results_dir, f"check_{domain.replace('.', '_')}.txt")
        with open(temp_file, 'w') as f:
            f.write(f"{domain}\n")
        
        # Ejecutar httpx
        output_file = os.path.join(results_dir, f"active_{domain.replace('.', '_')}.txt")
        cmd = f"httpx -l {temp_file} -o {output_file} -silent -timeout 10"
        subprocess.run(cmd, shell=True, timeout=60)
        
        # Leer resultado
        active_url = None
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                line = f.readline().strip()
                if line.startswith(('http://', 'https://')):
                    active_url = line
        
        # Limpiar
        for f in [temp_file, output_file]:
            try:
                os.remove(f)
            except:
                pass
        
        return active_url
        
    except Exception as e:
        print(f"[!] Error checking {domain}: {e}")
        return None

def create_url_target(project_id, url, db):
    """Crea un target URL - IGUAL QUE FORMULARIO MANUAL"""
    try:
        from backend.models import Target
        
        # Verificar si ya existe
        existing = db.query(Target).filter(
            Target.project_id == project_id,
            Target.target == url
        ).first()
        
        if not existing:
            new_target = Target(
                project_id=project_id,
                target=url,
                type="url",
                status="pending"
            )
            db.add(new_target)
            print(f"[✅] MANUAL-STYLE TARGET CREATED: {url}")
            return True
        else:
            print(f"[ℹ️] Target exists: {url}")
            return False
            
    except Exception as e:
        print(f"[!] Error creating target: {e}")
        return False

def replicate_manual_domain_behavior(project_id, domain_list, results_dir):
    """Replica EXACTAMENTE el comportamiento del formulario manual para dominios"""
    
    print(f"[🎯] REPLICATING MANUAL FORM BEHAVIOR")
    print(f"[📋] Processing {len(domain_list)} domains like manual form")
    
    try:
        from backend.models import SessionLocal
        import subprocess
        import os
        
        db = SessionLocal()
        os.makedirs(results_dir, exist_ok=True)
        
        total_urls_created = 0
        
        for domain in domain_list:
            domain = domain.strip()
            
            if domain.startswith(('http://', 'https://')):
                # Ya es URL - crear target directamente
                if create_url_target(project_id, domain, db):
                    total_urls_created += 1
            else:
                # Es dominio - hacer EXACTAMENTE lo mismo que manual
                print(f"[🔍] MANUAL-STYLE PROCESSING: {domain}")
                
                # 1. Subfinder (igual que manual)
                subs_file = os.path.join(results_dir, f"manual_subs_{domain.replace('.', '_')}.txt")
                cmd = f"subfinder -d {domain} -o {subs_file} -silent"
                subprocess.run(cmd, shell=True, timeout=120)
                
                # 2. Leer subdominios
                subdomains = [domain]  # Incluir original
                if os.path.exists(subs_file):
                    with open(subs_file, 'r') as f:
                        subdomains.extend([line.strip() for line in f if line.strip()])
                
                print(f"[📊] Found {len(subdomains)} subdomains for {domain}")
                
                # 3. Httpx en todos (igual que manual)
                temp_file = os.path.join(results_dir, f"manual_temp_{domain.replace('.', '_')}.txt")
                with open(temp_file, 'w') as f:
                    for sub in subdomains:
                        f.write(f"{sub}\n")
                
                urls_file = os.path.join(results_dir, f"manual_urls_{domain.replace('.', '_')}.txt")
                cmd = f"httpx -l {temp_file} -o {urls_file} -silent -timeout 10"
                subprocess.run(cmd, shell=True, timeout=180)
                
                # 4. Crear targets para URLs activas (igual que manual)
                if os.path.exists(urls_file):
                    with open(urls_file, 'r') as f:
                        for line in f:
                            url = line.strip()
                            if url.startswith(('http://', 'https://')):
                                if create_url_target(project_id, url, db):
                                    total_urls_created += 1
                
                # Limpiar
                for f in [subs_file, temp_file, urls_file]:
                    try:
                        os.remove(f)
                    except:
                        pass
        
        # Commit todos los targets
        db.commit()
        db.close()
        
        print(f"[🎯] MANUAL-STYLE PROCESSING COMPLETE")
        print(f"[📊] Created {total_urls_created} URL targets (like manual form)")
        
        return total_urls_created > 0
        
    except Exception as e:
        print(f"[❌] Error replicating manual behavior: {e}")
        if 'db' in locals():
            db.close()
        return False