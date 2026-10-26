#!/usr/bin/env python3
"""Arma un proyecto de ejemplo en una carpeta temporal, listo para revisar.

    python pruebas/revisor-seguridad/construir.py vulnerable [DESTINO]

- Cambia los marcadores @@...@@ por claves falsas con formato realista. Se
  generan aquí, por partes, para que ninguna cadena con formato de clave real
  quede en el repositorio (GitHub las bloquearía con razón).
- Renombra dot.env -> .env, dot.gitignore -> .gitignore, etc.
- Crea un repositorio git con commits. En el ejemplo vulnerable, lo que está en
  historial/ se sube en el primer commit y se borra en el segundo, para probar
  la revisión del historial.
"""

import base64
import json
import os
import random
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
EJEMPLOS = os.path.join(AQUI, "ejemplos")


def _aleatorio(generador, n, alfabeto="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(generador.choice(alfabeto) for _ in range(n))


def _b64(datos):
    return base64.urlsafe_b64encode(json.dumps(datos, separators=(",", ":")).encode()).decode().rstrip("=")


def claves_falsas(semilla=7):
    g = random.Random(semilla)

    def jwt(rol):
        return ".".join([
            _b64({"alg": "HS256", "typ": "JWT"}),
            _b64({"iss": "supabase", "ref": "abcdefghijklmnop", "role": rol, "iat": 1700000000, "exp": 2000000000}),
            _aleatorio(g, 43),
        ])

    return {
        "STRIPE_LIVE": "sk" + "_live_" + _aleatorio(g, 24),
        "GITHUB_TOKEN": "gh" + "p_" + _aleatorio(g, 36),
        "OPENAI": "sk" + "-proj-" + _aleatorio(g, 48),
        "SERVICE_ROLE_JWT": jwt("service" + "_role"),
        "ANON_JWT": jwt("anon"),
        "FIREBASE_KEY": "AI" + "za" + _aleatorio(g, 35),
        "DB_PASS": _aleatorio(g, 20),
    }


def _git(destino, *args):
    subprocess.run(
        ["git", "-c", "user.name=Pruebas", "-c", "user.email=pruebas@example.com",
         "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
        cwd=destino, check=True, capture_output=True,
    )


def construir(nombre, destino=None):
    origen = os.path.join(EJEMPLOS, nombre)
    if not os.path.isdir(origen):
        raise SystemExit(f"No existe el ejemplo {nombre!r}")
    destino = destino or os.path.join(tempfile.mkdtemp(prefix="revisor-"), nombre)
    claves = claves_falsas()

    def copiar(desde, hacia):
        for actual, carpetas, archivos in os.walk(desde):
            if actual == desde and "historial" in carpetas:
                carpetas.remove("historial")  # solo existe en commits viejos
            relativa = os.path.relpath(actual, desde)
            for archivo in archivos:
                final = "." + archivo[4:] if archivo.startswith("dot.") else archivo
                ruta = os.path.normpath(os.path.join(hacia, relativa, final))
                os.makedirs(os.path.dirname(ruta), exist_ok=True)
                with open(os.path.join(actual, archivo), encoding="utf-8") as f:
                    texto = f.read()
                for marcador, valor in claves.items():
                    texto = texto.replace(f"@@{marcador}@@", valor)
                with open(ruta, "w", encoding="utf-8", newline="\n") as f:
                    f.write(texto)

    os.makedirs(destino, exist_ok=True)
    historial = os.path.join(origen, "historial")
    copiar(origen, destino)

    _git(destino, "init", "-q", "-b", "main")
    if os.path.isdir(historial):
        copiar(historial, destino)
        _git(destino, "add", "-A")
        _git(destino, "commit", "-q", "-m", "Primera versión")
        for actual, _, archivos in os.walk(historial):
            for archivo in archivos:
                relativa = os.path.relpath(os.path.join(actual, archivo), historial)
                _git(destino, "rm", "-q", relativa.replace("\\", "/"))
        _git(destino, "commit", "-q", "-m", "Quitar claves del código")
    else:
        _git(destino, "add", "-A")
        _git(destino, "commit", "-q", "-m", "Primera versión")
    return destino


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    print(construir(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
