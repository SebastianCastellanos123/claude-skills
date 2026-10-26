#!/usr/bin/env python3
"""Convierte el JSON revisado en un reporte en Markdown con la nota de 0 a 100.

Uso:
    python reporte.py hallazgos.json [--salida reporte.md]

La nota se calcula aquí y no a mano, para que sea siempre la misma con los
mismos hallazgos:
  - Empieza en 100. Cada hallazgo confirmado resta según su severidad:
    crítico 25, alto 15, medio 8, bajo 3.
  - Las dependencias vulnerables restan como máximo 30 en total (suelen venir
    muchas juntas y se arreglan con una sola actualización).
  - Si hay al menos un hallazgo crítico, la nota no pasa de 40.
  - Los hallazgos "revisar" no restan hasta que se confirmen; los
    "descartados" nunca restan (y el reporte dice por qué se descartaron).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from catalogo import CATALOGO, LIMITES, REVISIONES, SEVERIDADES  # noqa: E402

PESOS = {"critica": 25, "alta": 15, "media": 8, "baja": 3}
TOPE_DEPENDENCIAS = 30
TOPE_CON_CRITICOS = 40
CATEGORIA = {
    "secreto": "secretos", "secreto_en_frontend": "secretos",
    "secreto_en_historial": "historial", "env_en_historial": "historial",
    "env_versionado": "env", "env_sin_ignorar": "env",
    "tabla_sin_rls": "supabase", "rls_desactivado": "supabase", "politica_abierta": "supabase",
    "firebase_abierto": "firebase", "cors_abierto": "cors", "sql_concatenado": "sql",
    "cookie_insegura": "cookies", "dependencia_vulnerable": "dependencias",
    "ruta_sin_auth": "rutas", "acceso_sin_dueno": "rutas",
}
ESTADOS = {
    "revisado": "Revisado",
    "parcial": "Revisado en parte",
    "no_aplica": "No aplica",
    "no_verificado": "No verificado",
    "pendiente_claude": "Sin revisar",
}


class ErrorDeDatos(ValueError):
    pass


def validar(datos):
    for h in datos.get("hallazgos", []):
        if h.get("severidad") not in PESOS:
            raise ErrorDeDatos(f"{h.get('id', '?')}: severidad inválida {h.get('severidad')!r}")
        if h.get("estado") not in ("confirmado", "revisar", "descartado"):
            raise ErrorDeDatos(f"{h.get('id', '?')}: estado inválido {h.get('estado')!r}")
        if h["estado"] == "descartado" and not h.get("motivo"):
            raise ErrorDeDatos(f"{h.get('id', '?')}: un hallazgo descartado necesita 'motivo'")
        if h.get("tipo") not in CATALOGO and not all(h.get(c) for c in ("titulo", "por_que", "como")):
            raise ErrorDeDatos(f"{h.get('id', '?')}: tipo {h.get('tipo')!r} sin 'titulo', 'por_que' y 'como'")


def calcular_nota(hallazgos):
    confirmados = [h for h in hallazgos if h["estado"] == "confirmado"]
    descuento_dep = sum(PESOS[h["severidad"]] for h in confirmados if h["tipo"] == "dependencia_vulnerable")
    descuento = sum(PESOS[h["severidad"]] for h in confirmados if h["tipo"] != "dependencia_vulnerable")
    nota = 100 - descuento - min(descuento_dep, TOPE_DEPENDENCIAS)
    if any(h["severidad"] == "critica" for h in confirmados):
        nota = min(nota, TOPE_CON_CRITICOS)
    return max(0, nota)


def nivel(nota):
    if nota >= 90:
        return "Bien"
    if nota >= 70:
        return "Mejorable"
    if nota > TOPE_CON_CRITICOS:
        return "Riesgoso"
    return "Crítico"


def _ubicacion(h):
    if h.get("commit") and not h.get("linea"):
        return f"`{h['archivo']}` (commit {h['commit']})"
    return f"`{h['archivo']}:{h['linea']}`" if h.get("linea") else f"`{h['archivo']}`"


def _texto(h, campo):
    return h.get(campo) or CATALOGO.get(h["tipo"], {}).get(campo, "")


def generar(datos):
    validar(datos)
    hallazgos = datos.get("hallazgos", [])
    nota = calcular_nota(hallazgos)
    confirmados = [h for h in hallazgos if h["estado"] == "confirmado"]
    pendientes = [h for h in hallazgos if h["estado"] == "revisar"]
    descartados = [h for h in hallazgos if h["estado"] == "descartado"]
    conteo = {s: sum(h["severidad"] == s for h in confirmados) for s in PESOS}
    resumen = " · ".join(f"{SEVERIDADES[s].capitalize()}s: {conteo[s]}" for s in PESOS)

    md = [f"# Reporte de seguridad: {datos.get('proyecto', 'proyecto')}", ""]
    md.append(f"## Nota: {nota}/100 · {nivel(nota)}")
    md.append("")
    md.append(resumen + (f" · Sin confirmar: {len(pendientes)}" if pendientes else ""))
    md.append("")
    md.append(f"Revisado el {datos.get('fecha', '')} con revisor-seguridad {datos.get('version', '')}.")
    md.append("")
    md.append("### Para compartir")
    md.append("")
    md.append("Este resumen no revela detalles de los problemas; el resto del reporte sí, así que no lo "
              "publiques hasta arreglarlos.")
    md.append("")
    partes = [f"{conteo[s]} {SEVERIDADES[s].lower()}{'s' if conteo[s] != 1 else ''}" for s in PESOS if conteo[s]]
    md.append(f"> Mi proyecto sacó **{nota}/100** en la revisión de seguridad de revisor-seguridad"
              + (f" ({', '.join(partes)})." if partes else ", sin hallazgos de los errores más comunes."))
    md.append("")

    md.append("## Hallazgos")
    md.append("")
    if not confirmados:
        md.append("No se encontraron problemas de los tipos que revisa esta herramienta.")
        md.append("")
    for i, h in enumerate(confirmados, 1):
        md.append(f"### {i}. [{SEVERIDADES[h['severidad']]}] {_texto(h, 'titulo')}")
        md.append("")
        md.append(f"**Dónde:** {_ubicacion(h)}"
                  + (f" (también en {', '.join(f'`{x}`' for x in h['tambien_en'])})" if h.get("tambien_en") else ""))
        md.append("")
        que = h.get("detalle") or h.get("evidencia", "")
        if h.get("nota"):
            que += f". {h['nota']}" if not que.endswith(".") else f" {h['nota']}"
        md.append(f"**Qué está mal:** {que}")
        md.append("")
        md.append(f"**Por qué es peligroso:** {_texto(h, 'por_que')}")
        md.append("")
        md.append("**Cómo arreglarlo:**")
        md.append("")
        md.append(_texto(h, "como"))
        if h.get("arreglo"):
            md.append("")
            md.append(f"En tu caso: {h['arreglo']}")
        if h.get("enlaces"):
            md.append("")
            md.append("Más información: " + ", ".join(h["enlaces"]))
        md.append("")

    if pendientes:
        md.append("## Sin confirmar")
        md.append("")
        md.append("Patrones sospechosos que nadie confirmó todavía leyendo el código. No restan puntos.")
        md.append("")
        for h in pendientes:
            md.append(f"- [{SEVERIDADES[h['severidad']]}] {_texto(h, 'titulo')}: {_ubicacion(h)}. {h.get('detalle', '')}")
        md.append("")

    md.append("## Qué se revisó")
    md.append("")
    md.append("| Revisión | Resultado | Hallazgos |")
    md.append("| --- | --- | --- |")
    verificaciones = datos.get("verificaciones", {})
    for clave, nombre in REVISIONES:
        v = verificaciones.get(clave, {"estado": "no_verificado", "detalle": ""})
        n = sum(CATEGORIA.get(h["tipo"]) == clave for h in confirmados)
        detalle = v.get("detalle", "")
        md.append(f"| {nombre} | {ESTADOS.get(v['estado'], v['estado'])}{': ' + detalle if v['estado'] != 'revisado' and detalle else ''} | {n} |")
    otros = sum(h["tipo"] not in CATEGORIA for h in confirmados)
    if otros:
        md.append(f"| Otros (revisión de Claude) | Revisado | {otros} |")
    md.append("")

    if descartados:
        md.append("## Descartados")
        md.append("")
        md.append("Patrones que parecían un problema pero no lo son, con el motivo:")
        md.append("")
        for h in descartados:
            md.append(f"- {_texto(h, 'titulo')} en {_ubicacion(h)}: {h['motivo']}")
        md.append("")

    if datos.get("notas"):
        md.append("## Notas")
        md.append("")
        md += [f"- {n}" for n in datos["notas"]]
        md.append("")

    md.append("## Qué NO revisa esta herramienta")
    md.append("")
    md += [f"- {x}" for x in LIMITES]
    md.append("")
    md.append("## Cómo se calcula la nota")
    md.append("")
    md.append(f"Empieza en 100. Cada hallazgo confirmado resta: crítico {PESOS['critica']}, alto {PESOS['alta']}, "
              f"medio {PESOS['media']}, bajo {PESOS['baja']}. Las dependencias restan como máximo "
              f"{TOPE_DEPENDENCIAS} en total. Con al menos un hallazgo crítico la nota no pasa de "
              f"{TOPE_CON_CRITICOS}. Niveles: 90-100 Bien, 70-89 Mejorable, 41-69 Riesgoso, 0-40 Crítico.")
    md.append("")
    return "\n".join(md), nota


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Genera el reporte de revisor-seguridad")
    p.add_argument("hallazgos")
    p.add_argument("--salida", help="Archivo .md (por defecto, reporte.md junto al JSON)")
    args = p.parse_args(argv)
    with open(args.hallazgos, encoding="utf-8") as f:
        datos = json.load(f)
    try:
        texto, nota = generar(datos)
    except ErrorDeDatos as e:
        print(f"El JSON tiene un error: {e}", file=sys.stderr)
        return 2
    salida = args.salida or os.path.join(os.path.dirname(os.path.abspath(args.hallazgos)), "reporte.md")
    with open(salida, "w", encoding="utf-8") as f:
        f.write(texto)
    pendientes = [h["id"] for h in datos.get("hallazgos", []) if h["estado"] == "revisar"]
    print(f"Reporte guardado en: {salida}")
    print(f"Nota: {nota}/100 ({nivel(nota)})")
    if pendientes:
        print(f"Atención: quedan sin confirmar {', '.join(pendientes)}; revísalos antes de entregar el reporte.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
