"""Dependencias con vulnerabilidades conocidas, usando la herramienta oficial de
cada ecosistema (npm audit, pnpm audit, pip-audit).

Lo que sale de tu computador: estas herramientas consultan su base de
vulnerabilidades con los NOMBRES Y VERSIONES de tus dependencias. Tu código no
se envía. Con --sin-red esta revisión se salta.

Nunca se instala nada ni se ejecutan scripts del proyecto.
"""

import json
import os
import shutil

from comun import CARPETAS_IGNORADAS, ejecutar
from detectores import hallazgo

_SEVERIDAD = {"critical": "critica", "high": "alta", "moderate": "media", "medium": "media", "low": "baja"}


def _buscar(raiz, nombre, profundidad=3):
    encontrados = []
    for actual, carpetas, archivos in os.walk(raiz):
        nivel = os.path.relpath(actual, raiz).count(os.sep) if actual != raiz else 0
        carpetas[:] = [c for c in carpetas if c not in CARPETAS_IGNORADAS] if nivel < profundidad else []
        if nombre in archivos:
            encontrados.append(os.path.relpath(os.path.join(actual, nombre), raiz).replace("\\", "/"))
    return sorted(encontrados)


def parsear_npm_audit(texto, archivo):
    """Formato de npm 7+ (`vulnerabilities`) y el antiguo/pnpm (`advisories`)."""
    try:
        datos = json.loads(texto)
    except json.JSONDecodeError:
        return None
    resultados = []
    if isinstance(datos.get("vulnerabilities"), dict):
        for nombre, v in sorted(datos["vulnerabilities"].items()):
            severidad = _SEVERIDAD.get(v.get("severity"))
            if not severidad:
                continue
            avisos = [x for x in v.get("via", []) if isinstance(x, dict)]
            titulos = "; ".join(sorted({a.get("title", "") for a in avisos if a.get("title")}))
            enlaces = sorted({a.get("url", "") for a in avisos if a.get("url")})
            arreglo = v.get("fixAvailable")
            if isinstance(arreglo, dict):
                arreglo = f"actualizar {arreglo.get('name')} a {arreglo.get('version')}"
            elif arreglo is True:
                arreglo = "`npm audit fix`"
            else:
                arreglo = "sin versión corregida todavía"
            detalle = f"{nombre} {v.get('range', '')}".strip()
            detalle += f": {titulos}" if titulos else " (vulnerable a través de otra dependencia)"
            h = hallazgo("dependencia_vulnerable", severidad, archivo, None, f"{nombre} {v.get('range', '')}", detalle)
            h.update({"paquete": nombre, "arreglo": arreglo, "enlaces": enlaces[:3], "directa": bool(v.get("isDirect"))})
            resultados.append(h)
    elif isinstance(datos.get("advisories"), dict):
        por_paquete = {}
        for a in datos["advisories"].values():
            por_paquete.setdefault(a.get("module_name", "?"), []).append(a)
        orden = ["baja", "media", "alta", "critica"]
        for nombre, avisos in sorted(por_paquete.items()):
            severidades = [_SEVERIDAD.get(a.get("severity")) for a in avisos]
            severidades = [s for s in severidades if s]
            if not severidades:
                continue
            severidad = max(severidades, key=orden.index)
            titulos = "; ".join(sorted({a.get("title", "") for a in avisos}))
            parche = avisos[0].get("patched_versions", "")
            h = hallazgo("dependencia_vulnerable", severidad, archivo, None, nombre, f"{nombre}: {titulos}")
            h.update({"paquete": nombre, "arreglo": f"versiones corregidas: {parche}" if parche else "",
                      "enlaces": [a.get("url") for a in avisos if a.get("url")][:3]})
            resultados.append(h)
    return resultados


def parsear_pip_audit(texto, archivo):
    try:
        datos = json.loads(texto)
    except json.JSONDecodeError:
        return None
    dependencias = datos.get("dependencies", datos) if isinstance(datos, dict) else datos
    resultados = []
    for d in dependencias or []:
        vulns = d.get("vulns") or []
        if not vulns:
            continue
        ids = ", ".join(v.get("id", "") for v in vulns)
        arreglos = sorted({f for v in vulns for f in v.get("fix_versions", [])})
        # pip-audit no trae severidad: la tratamos como alta y Claude puede ajustarla leyendo el aviso.
        h = hallazgo("dependencia_vulnerable", "alta", archivo, None, f"{d.get('name')}=={d.get('version')}",
                     f"{d.get('name')} {d.get('version')}: {ids}")
        h.update({"paquete": d.get("name"), "arreglo": f"actualizar a {arreglos[0]}" if arreglos else "",
                  "enlaces": [f"https://osv.dev/vulnerability/{v.get('id')}" for v in vulns][:3]})
        resultados.append(h)
    return resultados


def auditar(raiz, sin_red=False):
    """Devuelve (hallazgos, verificacion, notas)."""
    hallazgos, pendientes, revisados, notas = [], [], [], []
    hay_node = bool(_buscar(raiz, "package.json"))
    hay_python = bool(_buscar(raiz, "requirements.txt") or _buscar(raiz, "pyproject.toml"))
    if not hay_node and not hay_python:
        return [], {"estado": "no_aplica", "detalle": "No encontré package.json ni requirements.txt"}, []
    if sin_red:
        return [], {"estado": "no_verificado", "detalle": "Se usó --sin-red: las dependencias no se consultaron"}, []

    npm = shutil.which("npm")
    for lock in _buscar(raiz, "package-lock.json"):
        carpeta = os.path.join(raiz, os.path.dirname(lock))
        if not npm:
            pendientes.append(f"{lock}: npm no está instalado")
            continue
        _, salida = ejecutar([npm, "audit", "--json", "--package-lock-only"], carpeta, timeout=120)
        resultado = parsear_npm_audit(salida, lock)
        if resultado is None:
            pendientes.append(f"{lock}: npm audit no respondió (¿sin internet?)")
            continue
        hallazgos += resultado
        revisados.append(f"{lock} (npm audit)")
    for lock in _buscar(raiz, "pnpm-lock.yaml"):
        pnpm = shutil.which("pnpm")
        if not pnpm:
            pendientes.append(f"{lock}: instala pnpm y corre `pnpm audit`")
            continue
        _, salida = ejecutar([pnpm, "audit", "--json"], os.path.join(raiz, os.path.dirname(lock)), timeout=120)
        resultado = parsear_npm_audit(salida, lock)
        if resultado is None:
            pendientes.append(f"{lock}: pnpm audit no respondió")
            continue
        hallazgos += resultado
        revisados.append(f"{lock} (pnpm audit)")
    for paquete in _buscar(raiz, "package.json"):
        carpeta = os.path.dirname(paquete)
        locks = [os.path.join(carpeta, n).replace("\\", "/").lstrip("/") for n in ("package-lock.json", "pnpm-lock.yaml")]
        if any(os.path.exists(os.path.join(raiz, l)) for l in locks):
            continue
        if os.path.exists(os.path.join(raiz, carpeta, "yarn.lock")):
            pendientes.append(f"{paquete}: usa yarn; corre `yarn npm audit` (yarn 2+) o `yarn audit`")
        else:
            pendientes.append(f"{paquete}: no hay lockfile; corre `npm install --package-lock-only` y vuelve a revisar")

    pip_audit = shutil.which("pip-audit")
    for req in _buscar(raiz, "requirements.txt"):
        if not pip_audit:
            pendientes.append(f"{req}: instala pip-audit (`pip install pip-audit`) para revisarlo")
            continue
        # --no-deps --disable-pip: no crea entornos ni instala nada; solo consulta versiones exactas.
        _, salida = ejecutar([pip_audit, "-r", os.path.join(raiz, req), "--format", "json",
                              "--no-deps", "--disable-pip", "--progress-spinner", "off"], raiz, timeout=180)
        resultado = parsear_pip_audit(salida, req)
        if resultado is None:
            pendientes.append(f"{req}: pip-audit no pudo revisarlo (necesita versiones fijas con ==)")
            continue
        hallazgos += resultado
        revisados.append(f"{req} (pip-audit)")
    if hay_python and not _buscar(raiz, "requirements.txt"):
        pendientes.append("pyproject.toml: exporta requirements.txt con versiones fijas y usa pip-audit")

    if revisados:
        notas.append("Para revisar dependencias se consultó la base de vulnerabilidades del ecosistema "
                     "con los nombres y versiones de tus paquetes (no con tu código).")
    if revisados and not pendientes:
        verificacion = {"estado": "revisado", "detalle": ", ".join(revisados)}
    elif revisados:
        verificacion = {"estado": "parcial", "detalle": ", ".join(revisados) + ". Falta: " + "; ".join(pendientes)}
    else:
        verificacion = {"estado": "no_verificado", "detalle": "; ".join(pendientes)}
    return hallazgos, verificacion, notas
