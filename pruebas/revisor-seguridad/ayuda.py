"""Comunes a las pruebas: deja importables los scripts de la skill."""

import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(os.path.dirname(AQUI))
SCRIPTS = os.path.join(RAIZ, "plugins", "revisor-seguridad", "skills", "revisar", "scripts")

for ruta in (SCRIPTS, AQUI):
    if ruta not in sys.path:
        sys.path.insert(0, ruta)


def silencio():
    """Calla stdout y stderr de los scripts de línea de comandos durante una prueba."""
    import contextlib
    import io
    pila = contextlib.ExitStack()
    pila.enter_context(contextlib.redirect_stdout(io.StringIO()))
    pila.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return pila
