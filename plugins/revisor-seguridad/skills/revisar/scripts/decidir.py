#!/usr/bin/env python3
"""Registra las decisiones de Claude sobre el JSON de escanear.py, sin editarlo a mano.

    python decidir.py JSON confirmar H03 [--severidad media --motivo "..."] [--nota "..."] [--arreglo "..."]
    python decidir.py JSON descartar H05 --motivo "por qué no es un problema"
    python decidir.py JSON agregar --tipo ruta_sin_auth --severidad alta --archivo src/api.js --linea 28 \
        --detalle "GET /api/admin/usuarios devuelve emails sin verificar sesión" [--arreglo "..."]
    python decidir.py JSON agregar --tipo manual --titulo "..." --por-que "..." --como "..." ...
    python decidir.py JSON rutas-revisadas --detalle "9 rutas revisadas a mano"

Cada decisión queda en el JSON (con el motivo cuando corresponde) y el reporte
la muestra, para que el usuario pueda ver por qué se descartó algo.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from catalogo import CATALOGO  # noqa: E402

SEVERIDADES = ("critica", "alta", "media", "baja")


def _buscar(datos, identificador):
    for h in datos["hallazgos"]:
        if h["id"] == identificador:
            return h
    raise SystemExit(f"No existe el hallazgo {identificador}")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Decisiones sobre los hallazgos de revisor-seguridad")
    p.add_argument("json")
    sub = p.add_subparsers(dest="accion", required=True)

    c = sub.add_parser("confirmar")
    c.add_argument("id")
    c.add_argument("--severidad", choices=SEVERIDADES)
    c.add_argument("--motivo", help="Obligatorio si cambias la severidad")
    c.add_argument("--nota")
    c.add_argument("--arreglo")

    d = sub.add_parser("descartar")
    d.add_argument("id")
    d.add_argument("--motivo", required=True)

    a = sub.add_parser("agregar")
    a.add_argument("--tipo", required=True, help="Un tipo del catálogo o 'manual'")
    a.add_argument("--severidad", required=True, choices=SEVERIDADES)
    a.add_argument("--archivo", required=True)
    a.add_argument("--linea", type=int)
    a.add_argument("--detalle", required=True)
    a.add_argument("--arreglo")
    a.add_argument("--titulo")
    a.add_argument("--por-que", dest="por_que")
    a.add_argument("--como")

    r = sub.add_parser("rutas-revisadas")
    r.add_argument("--detalle", required=True)

    args = p.parse_args(argv)
    with open(args.json, encoding="utf-8") as f:
        datos = json.load(f)

    if args.accion == "confirmar":
        h = _buscar(datos, args.id)
        if args.severidad and args.severidad != h["severidad"]:
            if not args.motivo:
                raise SystemExit("Para cambiar la severidad hace falta --motivo")
            h["severidad_original"], h["severidad"] = h["severidad"], args.severidad
            h["motivo_severidad"] = args.motivo
        h["estado"] = "confirmado"
        for campo in ("nota", "arreglo"):
            if getattr(args, campo):
                h[campo] = getattr(args, campo)
        print(f"{h['id']} confirmado ({h['severidad']})")
    elif args.accion == "descartar":
        h = _buscar(datos, args.id)
        h["estado"], h["motivo"] = "descartado", args.motivo
        print(f"{h['id']} descartado")
    elif args.accion == "agregar":
        if args.tipo not in CATALOGO and not (args.titulo and args.por_que and args.como):
            raise SystemExit("Un tipo fuera del catálogo necesita --titulo, --por-que y --como")
        numero = 1 + max([int(h["id"][1:]) for h in datos["hallazgos"]] or [0])
        h = {
            "id": f"H{numero:02d}", "tipo": args.tipo, "severidad": args.severidad, "estado": "confirmado",
            "archivo": args.archivo, "linea": args.linea, "evidencia": "", "detalle": args.detalle,
            "origen": "claude",
        }
        for campo in ("arreglo", "titulo", "por_que", "como"):
            if getattr(args, campo):
                h[campo] = getattr(args, campo)
        datos["hallazgos"].append(h)
        print(f"{h['id']} agregado ({h['severidad']})")
    elif args.accion == "rutas-revisadas":
        datos["verificaciones"]["rutas"] = {"estado": "revisado", "detalle": args.detalle}
        print("Rutas marcadas como revisadas")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
