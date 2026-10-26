"""Revisa el historial de git: secretos que se borraron del código pero siguen
en commits viejos, y archivos .env que alguna vez se subieron.

Borrar un secreto en un commit nuevo no lo elimina: cualquiera que clone el
repositorio puede verlo con `git log -p`. Por eso se revisa aparte.
"""

import re

from comun import es_ignorado, ejecutar, es_archivo_env
from detectores import detectar_secretos

_RE_ARCHIVO = re.compile(r"^\+\+\+ b/(.+)$")


def _cambios_por_commit(salida):
    """Itera (commit, archivo, texto_agregado) a partir de `git log -p`."""
    commit, archivo, agregadas = None, None, []
    for linea in salida.split("\n"):
        if linea.startswith("\0"):
            if archivo and agregadas:
                yield commit, archivo, "\n".join(agregadas)
            commit, archivo, agregadas = linea[1:].strip(), None, []
            continue
        m = _RE_ARCHIVO.match(linea)
        if m:
            if archivo and agregadas:
                yield commit, archivo, "\n".join(agregadas)
            archivo, agregadas = m.group(1), []
        elif linea.startswith("+") and not linea.startswith("+++") and archivo:
            agregadas.append(linea[1:])
    if archivo and agregadas:
        yield commit, archivo, "\n".join(agregadas)


def escanear_historial(raiz, evidencias_actuales):
    """Devuelve (hallazgos, error). `evidencias_actuales` son las evidencias de
    secretos que ya están en el código de hoy, para no repetirlas."""
    codigo, salida = ejecutar(
        ["git", "-c", "core.quotepath=off", "log", "--all", "-p", "--no-color", "--unified=0",
         "--no-ext-diff", "--no-renames", "--pretty=format:%x00%h"],
        raiz, timeout=180,
    )
    if codigo is None:
        return [], "git log tardó demasiado o no se pudo ejecutar"
    if codigo != 0:
        return [], None  # repositorio sin commits todavía

    encontrados = {}
    for commit, archivo, texto in _cambios_por_commit(salida):
        # Los .env tienen su propio hallazgo (versionado o en el historial) que ya pide rotar todo.
        if es_ignorado(archivo) or es_archivo_env(archivo):
            continue
        for h in detectar_secretos(archivo, texto):
            if h["tipo"] != "secreto" or h["evidencia"] in evidencias_actuales:
                continue
            # git log va del más nuevo al más viejo: nos quedamos con el commit más viejo.
            h.update({
                "tipo": "secreto_en_historial", "linea": None, "commit": commit,
                "detalle": f"{h['detalle']} (agregado en el commit {commit}; ya no está en el código actual, pero sigue en el historial)",
            })
            encontrados[h["evidencia"]] = h
    return list(encontrados.values()), None


def env_en_historial(raiz, versionados):
    """Archivos .env que se subieron alguna vez y hoy ya no están versionados."""
    codigo, salida = ejecutar(
        ["git", "-c", "core.quotepath=off", "log", "--all", "--diff-filter=A",
         "--name-only", "--pretty=format:%x00%h"],
        raiz, timeout=120,
    )
    if codigo != 0:
        return []
    resultado, commit = {}, None
    for linea in salida.split("\n"):
        if linea.startswith("\0"):
            commit = linea[1:].strip()
        elif linea.strip() and es_archivo_env(linea.strip()) and linea.strip() not in versionados:
            resultado[linea.strip()] = commit
    return sorted(resultado.items())
