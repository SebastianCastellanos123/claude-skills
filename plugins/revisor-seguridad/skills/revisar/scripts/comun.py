"""Utilidades compartidas: recorrer archivos, enmascarar secretos, normalizar rutas.

Solo usa la librería estándar de Python (3.10+), para que el revisor funcione
sin instalar nada y sin enviar el código a ningún lado.
"""

import os
import re
import subprocess

# Carpetas que no son código del usuario (dependencias, compilados, cachés).
CARPETAS_IGNORADAS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
    ".svelte-kit", ".vercel", ".turbo", ".output", "coverage", "target",
    "venv", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".idea",
    ".vscode", "Pods", ".gradle", ".dart_tool",
}

# Archivos generados que producen ruido (hashes de integridad, código minificado).
ARCHIVOS_IGNORADOS = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
    "bun.lockb", "uv.lock",
}
SUFIJOS_IGNORADOS = (".min.js", ".min.css", ".map", ".snap")

EXTENSIONES_BINARIAS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz", ".pdf",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".jar", ".class", ".so", ".dll",
    ".exe", ".dylib", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3",
    ".mp4", ".mov", ".avi", ".wav", ".sqlite", ".db", ".pyc", ".wasm",
}

TAMANO_MAXIMO = 1_000_000  # bytes; archivos más grandes casi nunca son código escrito a mano

# Un archivo .env "real" (no las plantillas .env.example y compañía).
_PLANTILLAS_ENV = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")
_RE_ENV = re.compile(r"(^|/)\.env(\.[^/]+)?$")


def es_archivo_env(ruta):
    """True para .env, .env.local, .env.production...; False para .env.example."""
    ruta = ruta.replace("\\", "/")
    if not _RE_ENV.search(ruta):
        return False
    return not ruta.lower().endswith(_PLANTILLAS_ENV)


def ejecutar(comando, cwd, timeout=60):
    """Ejecuta un comando y devuelve (código, stdout). Nunca usa shell=True."""
    try:
        r = subprocess.run(
            comando, cwd=cwd, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def es_repo_git(raiz):
    codigo, salida = ejecutar(["git", "rev-parse", "--is-inside-work-tree"], raiz)
    return codigo == 0 and salida.strip() == "true"


def es_ignorado(ruta_relativa):
    partes = ruta_relativa.split("/")
    if any(p in CARPETAS_IGNORADAS for p in partes[:-1]):
        return True
    nombre = partes[-1]
    if nombre in ARCHIVOS_IGNORADOS or nombre.endswith(SUFIJOS_IGNORADOS):
        return True
    return os.path.splitext(nombre)[1].lower() in EXTENSIONES_BINARIAS


def listar_archivos(raiz, usar_git):
    """Archivos que importan: en un repo git, los versionados y los nuevos que
    no están en .gitignore (es decir, lo que terminaría en GitHub). Fuera de git,
    todo menos las carpetas ignoradas y los .env (que se revisan aparte)."""
    rutas = []
    if usar_git:
        codigo, salida = ejecutar(
            ["git", "-c", "core.quotepath=off", "ls-files", "-co", "--exclude-standard", "-z"],
            raiz,
        )
        if codigo == 0:
            rutas = [r for r in salida.split("\0") if r]
    if not rutas and not usar_git:
        for actual, carpetas, archivos in os.walk(raiz):
            carpetas[:] = [c for c in carpetas if c not in CARPETAS_IGNORADAS]
            for nombre in archivos:
                completa = os.path.join(actual, nombre)
                relativa = os.path.relpath(completa, raiz).replace("\\", "/")
                if not es_archivo_env(relativa):
                    rutas.append(relativa)
    return sorted(r for r in rutas if not es_ignorado(r))


def leer_texto(raiz, ruta_relativa):
    """Devuelve el contenido como texto, o None si es binario, enorme o ilegible."""
    completa = os.path.join(raiz, ruta_relativa)
    try:
        if os.path.getsize(completa) > TAMANO_MAXIMO:
            return None
        with open(completa, "rb") as f:
            datos = f.read()
    except OSError:
        return None
    if b"\0" in datos[:8192]:
        return None
    return datos.decode("utf-8", errors="replace")


def enmascarar(valor):
    """Nunca mostramos un secreto completo: solo el inicio y su largo."""
    valor = valor.strip()
    if len(valor) <= 8:
        return valor[:2] + "…"
    return f"{valor[:6]}…({len(valor)} caracteres)"


def numero_de_linea(texto, posicion):
    return texto.count("\n", 0, posicion) + 1


def linea_en(texto, numero):
    lineas = texto.splitlines()
    return lineas[numero - 1] if 0 < numero <= len(lineas) else ""
