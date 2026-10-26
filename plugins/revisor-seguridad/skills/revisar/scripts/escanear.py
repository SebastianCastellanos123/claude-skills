#!/usr/bin/env python3
"""Revisión determinista de seguridad de un proyecto.

Uso:
    python escanear.py RUTA_DEL_PROYECTO [--salida hallazgos.json] [--sin-red] [--sin-historial]

Escribe un JSON con:
  - hallazgos: problemas encontrados ("confirmado") o sospechas que Claude debe
    verificar leyendo el código ("revisar").
  - rutas: inventario de endpoints para que Claude decida cuáles necesitan login.
  - verificaciones: qué se revisó, qué no aplica y qué no se pudo verificar.

No modifica el proyecto, no ejecuta su código y no envía nada a internet,
salvo la consulta de dependencias (nombres y versiones) que se apaga con --sin-red.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from comun import CARPETAS_IGNORADAS, ejecutar, es_archivo_env, es_repo_git, leer_texto, listar_archivos  # noqa: E402
from dependencias import auditar  # noqa: E402
from detectores import (  # noqa: E402
    _RE_ENV_PUBLICA, analizar_reglas_firebase, analizar_reglas_rtdb, analizar_sql,
    detectar_cookies, detectar_cors, detectar_secretos, detectar_sql, es_relleno,
    hallazgo, inventariar_rutas,
)
from historial import env_en_historial, escanear_historial  # noqa: E402

VERSION = "0.1.0"
EXT_CODIGO = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".php", ".rb", ".go", ".java",
    ".kt", ".cs", ".vue", ".svelte", ".astro", ".json",
}
ORDEN_SEVERIDAD = {"critica": 0, "alta": 1, "media": 2, "baja": 3}
_RE_LINEA_ENV = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def variables_con_valor(texto):
    """Nombres de variables de un .env que tienen un valor real (sin mostrar el valor)."""
    nombres = []
    for linea in texto.splitlines():
        m = _RE_LINEA_ENV.match(linea)
        if m:
            valor = m.group(2).strip().strip("'\"")
            if valor and not es_relleno(valor):
                nombres.append(m.group(1))
    return nombres


def _usa(raiz, archivos, textos, paquetes, carpetas):
    if any(os.path.isdir(os.path.join(raiz, c)) for c in carpetas):
        return True
    for ruta in archivos:
        if ruta.rsplit("/", 1)[-1] in ("package.json", "requirements.txt", "pyproject.toml"):
            if any(p in (textos.get(ruta) or "") for p in paquetes):
                return True
    return False


def _env_en_disco(raiz):
    """Todos los .env que existen (incluidos los ignorados), solo para leer nombres."""
    for actual, carpetas, nombres in os.walk(raiz):
        carpetas[:] = [c for c in carpetas if c not in CARPETAS_IGNORADAS]
        for nombre in nombres:
            relativa = os.path.relpath(os.path.join(actual, nombre), raiz).replace("\\", "/")
            if es_archivo_env(relativa):
                yield relativa


def escanear(raiz, sin_red=False, sin_historial=False):
    raiz = os.path.abspath(raiz)
    git = es_repo_git(raiz)
    archivos = listar_archivos(raiz, git)
    versionados = set()
    if git:
        _, salida = ejecutar(["git", "-c", "core.quotepath=off", "ls-files", "-z"], raiz)
        versionados = {r for r in salida.split("\0") if r}

    hallazgos, rutas, notas = [], [], []
    verificaciones = {}
    textos = {ruta: leer_texto(raiz, ruta) for ruta in archivos}

    # 1. Archivos .env que se van (o se fueron) a git
    env_reportados = set()
    for ruta in archivos:
        if not es_archivo_env(ruta) or textos[ruta] is None:
            continue
        nombres = variables_con_valor(textos[ruta])
        contiene = f" Contiene valores para: {', '.join(nombres[:12])}." if nombres else ""
        if ruta in versionados:
            hallazgos.append(hallazgo("env_versionado", "critica" if nombres else "alta", ruta, None, ruta,
                                      f"`{ruta}` está versionado en git.{contiene}"))
        else:
            hallazgos.append(hallazgo("env_sin_ignorar", "alta" if nombres else "media", ruta, None, ruta,
                                      f"`{ruta}` no está en .gitignore: el próximo `git add .` lo sube.{contiene}"))
        env_reportados.add(ruta)
    if git and not sin_historial:
        for ruta, commit in env_en_historial(raiz, versionados):
            hallazgos.append(hallazgo("env_en_historial", "alta", ruta, None, f"{ruta} (commit {commit})",
                                      f"`{ruta}` se subió en el commit {commit}. Ya no está, pero sigue en el historial."))
    if not git and any(True for _ in _env_en_disco(raiz)):
        gitignore = leer_texto(raiz, ".gitignore") or ""
        if not re.search(r"(?m)^\s*/?\.env", gitignore):
            hallazgos.append(hallazgo("env_sin_ignorar", "alta", ".env", None, ".env",
                                      "Hay archivos .env y el .gitignore no los excluye.", estado="revisar"))
    verificaciones["env"] = {"estado": "revisado", "detalle": "Archivos .env versionados, sin ignorar o en el historial"}

    # Variables públicas con nombre de secreto, también en .env ignorados (solo se leen nombres).
    for ruta in _env_en_disco(raiz):
        texto = leer_texto(raiz, ruta) or ""
        for m in _RE_ENV_PUBLICA.finditer(texto):
            linea = texto.count("\n", 0, m.start()) + 1
            hallazgos.append(hallazgo("secreto_en_frontend", "critica", ruta, linea, m.group(1),
                                      f"`{m.group(1)}`: el prefijo hace que el framework la meta en el JavaScript que descarga cualquier visitante"))

    # 2. Secretos en el código actual
    for ruta in archivos:
        texto = textos[ruta]
        if texto is None or ruta in env_reportados:
            continue
        hallazgos += detectar_secretos(ruta, texto, notas)
    verificaciones["secretos"] = {"estado": "revisado", "detalle": f"{len(archivos)} archivos (los que irían a git)"}

    # 3. Secretos en el historial
    if not git:
        verificaciones["historial"] = {"estado": "no_aplica", "detalle": "La carpeta no es un repositorio git"}
    elif sin_historial:
        verificaciones["historial"] = {"estado": "no_verificado", "detalle": "Se usó --sin-historial"}
    else:
        actuales = {h["evidencia"] for h in hallazgos if h["tipo"] == "secreto"}
        del_historial, error = escanear_historial(raiz, actuales)
        hallazgos += del_historial
        verificaciones["historial"] = ({"estado": "no_verificado", "detalle": error} if error
                                       else {"estado": "revisado", "detalle": "Todos los commits de todas las ramas"})

    # 4. Supabase
    sql = [(r, textos[r]) for r in archivos if r.endswith(".sql") and textos[r]]
    usa_supabase = _usa(raiz, archivos, textos, ["supabase"], ["supabase"])
    hallazgos_sql = analizar_sql(sql)
    if not usa_supabase:
        # Sin Supabase, una tabla sin RLS en Postgres normal no es un problema por sí sola.
        hallazgos_sql = [h for h in hallazgos_sql if h["tipo"] != "tabla_sin_rls"]
    hallazgos += hallazgos_sql
    hay_tablas = any(re.search(r"(?i)create\s+table", t) for _, t in sql)
    if usa_supabase and hay_tablas:
        verificaciones["supabase"] = {"estado": "revisado", "detalle": f"RLS y políticas en {len(sql)} archivos .sql"}
    elif usa_supabase:
        verificaciones["supabase"] = {
            "estado": "no_verificado",
            "detalle": "Usas Supabase pero las tablas no están en el repositorio (¿las creaste desde el panel?). "
                       "En el SQL Editor de Supabase corre: select tablename, rowsecurity from pg_tables "
                       "where schemaname = 'public'; cualquier fila con rowsecurity = false es un problema.",
        }
    else:
        verificaciones["supabase"] = {"estado": "no_aplica", "detalle": "No se detectó Supabase"}

    # 5. Firebase
    reglas = 0
    for ruta in archivos:
        texto = textos[ruta] or ""
        nombre = ruta.rsplit("/", 1)[-1]
        if nombre.endswith(".rules") and re.search(r"service\s+(cloud\.firestore|firebase\.storage)", texto):
            hallazgos += analizar_reglas_firebase(ruta, texto)
            reglas += 1
        elif nombre.endswith("rules.json") and ('".read"' in texto or '".write"' in texto):
            hallazgos += analizar_reglas_rtdb(ruta, texto)
            reglas += 1
    usa_firebase = _usa(raiz, archivos, textos, ['"firebase"', "firebase-admin", "firebase_admin"], [])
    if reglas:
        verificaciones["firebase"] = {"estado": "revisado", "detalle": f"{reglas} archivo(s) de reglas"}
    elif usa_firebase:
        verificaciones["firebase"] = {"estado": "no_verificado",
                                      "detalle": "Usas Firebase pero no hay firestore.rules/storage.rules en el repositorio. "
                                                 "Revisa las reglas en la consola de Firebase."}
    else:
        verificaciones["firebase"] = {"estado": "no_aplica", "detalle": "No se detectó Firebase"}

    # 6. CORS, SQL, cookies y rutas en el código
    codigo = [r for r in archivos if os.path.splitext(r)[1].lower() in EXT_CODIGO and textos[r]]
    for ruta in codigo:
        texto = textos[ruta]
        hallazgos += detectar_cors(ruta, texto)
        if not ruta.endswith(".json"):
            hallazgos += detectar_sql(ruta, texto)
            hallazgos += detectar_cookies(ruta, texto)
            rutas += inventariar_rutas(ruta, texto)
    for clave in ("cors", "sql", "cookies"):
        verificaciones[clave] = {"estado": "revisado", "detalle": f"Patrones en {len(codigo)} archivos de código"}
    verificaciones["rutas"] = {
        "estado": "pendiente_claude" if rutas else "no_aplica",
        "detalle": f"{len(rutas)} rutas encontradas; Claude debe revisar cuáles necesitan login" if rutas
                   else "No encontré rutas de servidor reconocibles",
    }

    # 7. Dependencias
    dep_hallazgos, verificaciones["dependencias"], dep_notas = auditar(raiz, sin_red)
    hallazgos += dep_hallazgos
    notas += dep_notas

    # Un mismo secreto en varios archivos es un solo problema (una sola clave que rotar):
    # se reporta una vez y se anotan los demás lugares.
    unicos, vistos = [], {}
    for h in hallazgos:
        if h["tipo"] in ("secreto", "secreto_en_frontend", "secreto_en_historial"):
            clave = (h["tipo"], h["evidencia"])
        else:
            clave = (h["tipo"], h["archivo"], h["evidencia"])
        if clave in vistos:
            primero = vistos[clave]
            if h["archivo"] != primero["archivo"]:
                primero.setdefault("tambien_en", []).append(h["archivo"])
            continue
        vistos[clave] = h
        unicos.append(h)
    unicos.sort(key=lambda h: (ORDEN_SEVERIDAD[h["severidad"]], h["estado"] != "confirmado", h["archivo"], h["linea"] or 0))
    for i, h in enumerate(unicos, 1):
        h["id"] = f"H{i:02d}"

    return {
        "herramienta": "revisor-seguridad",
        "version": VERSION,
        "proyecto": os.path.basename(raiz),
        "fecha": datetime.date.today().isoformat(),
        "es_repo_git": git,
        "hallazgos": unicos,
        "rutas": rutas,
        "verificaciones": verificaciones,
        "notas": notas,
    }


def ruta_salida_por_defecto(raiz):
    """Fuera del proyecto, para no dejar archivos con hallazgos dentro del repo."""
    huella = hashlib.sha1(os.path.abspath(raiz).encode("utf-8")).hexdigest()[:10]
    carpeta = os.path.join(tempfile.gettempdir(), "revisor-seguridad", f"{os.path.basename(os.path.abspath(raiz))}-{huella}")
    os.makedirs(carpeta, exist_ok=True)
    return os.path.join(carpeta, "hallazgos.json")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Revisión determinista de seguridad (revisor-seguridad)")
    p.add_argument("proyecto", nargs="?", default=".")
    p.add_argument("--salida", help="Dónde guardar el JSON (por defecto, una carpeta temporal fuera del proyecto)")
    p.add_argument("--sin-red", action="store_true", help="No consultar vulnerabilidades de dependencias")
    p.add_argument("--sin-historial", action="store_true", help="No revisar el historial de git")
    args = p.parse_args(argv)
    if not os.path.isdir(args.proyecto):
        print(f"No existe la carpeta {args.proyecto}", file=sys.stderr)
        return 2

    resultado = escanear(args.proyecto, args.sin_red, args.sin_historial)
    salida = args.salida or ruta_salida_por_defecto(args.proyecto)
    with open(salida, "w", encoding="utf-8") as f:
        json.dump(resultado, f, ensure_ascii=False, indent=2)

    hallazgos = resultado["hallazgos"]
    confirmados = sum(h["estado"] == "confirmado" for h in hallazgos)
    por_revisar = sum(h["estado"] == "revisar" for h in hallazgos)
    print(f"Resultado guardado en: {salida}")
    print(f"Hallazgos confirmados: {confirmados} · por revisar: {por_revisar} · rutas a revisar: {len(resultado['rutas'])}")
    for clave, v in resultado["verificaciones"].items():
        print(f"  - {clave}: {v['estado']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
