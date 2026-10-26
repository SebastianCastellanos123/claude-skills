"""Pruebas de la nota, del reporte y de decidir.py."""

import json
import os
import tempfile
import unittest

import ayuda
from decidir import main as _decidir
from reporte import ErrorDeDatos, calcular_nota, generar, nivel


def decidir(argv):
    with ayuda.silencio():
        return _decidir(argv)


def h(severidad, tipo="secreto", estado="confirmado", **extra):
    base = {"id": "H01", "tipo": tipo, "severidad": severidad, "estado": estado,
            "archivo": "a.js", "linea": 1, "evidencia": "x", "detalle": "detalle"}
    base.update(extra)
    return base


class Nota(unittest.TestCase):
    def test_sin_hallazgos_es_100(self):
        self.assertEqual(calcular_nota([]), 100)
        self.assertEqual(nivel(100), "Bien")

    def test_pesos(self):
        self.assertEqual(calcular_nota([h("alta"), h("media"), h("baja")]), 100 - 15 - 8 - 3)

    def test_un_critico_limita_a_40(self):
        self.assertEqual(calcular_nota([h("critica")]), 40)
        self.assertEqual(nivel(40), "Crítico")

    def test_nunca_baja_de_cero(self):
        self.assertEqual(calcular_nota([h("critica")] * 10), 0)

    def test_dependencias_restan_maximo_30(self):
        deps = [h("alta", tipo="dependencia_vulnerable")] * 5
        self.assertEqual(calcular_nota(deps), 70)

    def test_revisar_y_descartados_no_restan(self):
        self.assertEqual(calcular_nota([h("critica", estado="revisar"), h("alta", estado="descartado", motivo="m")]), 100)

    def test_niveles(self):
        self.assertEqual([nivel(n) for n in (95, 75, 55, 41)], ["Bien", "Mejorable", "Riesgoso", "Riesgoso"])


class Reporte(unittest.TestCase):
    def datos(self, hallazgos):
        return {"proyecto": "demo", "fecha": "2026-01-01", "version": "0.1.0", "hallazgos": hallazgos,
                "verificaciones": {"secretos": {"estado": "revisado", "detalle": ""}}, "notas": []}

    def test_secciones_y_explicaciones(self):
        texto, nota = generar(self.datos([h("alta", tipo="sql_concatenado", arreglo="usa parámetros")]))
        self.assertEqual(nota, 85)
        for parte in ("## Nota: 85/100", "**Qué está mal:**", "**Por qué es peligroso:**",
                      "**Cómo arreglarlo:**", "**En tu caso:** usa parámetros", "## Qué se revisó",
                      "## Qué NO revisa", "### Para compartir"):
            self.assertIn(parte, texto)

    def test_el_resumen_para_compartir_no_tiene_detalles(self):
        texto, _ = generar(self.datos([h("critica", archivo="src/secreto-especial.js")]))
        compartir = texto.split("### Para compartir")[1].split("## Hallazgos")[0]
        self.assertNotIn("secreto-especial", compartir)
        self.assertIn("1 crítico", compartir)

    def test_descartado_exige_motivo_y_se_muestra(self):
        with self.assertRaises(ErrorDeDatos):
            generar(self.datos([h("alta", estado="descartado")]))
        texto, _ = generar(self.datos([h("alta", estado="descartado", motivo="es de mentira")]))
        self.assertIn("es de mentira", texto)

    def test_tipo_manual_necesita_textos(self):
        with self.assertRaises(ErrorDeDatos):
            generar(self.datos([h("alta", tipo="manual")]))
        texto, _ = generar(self.datos([h("alta", tipo="manual", titulo="Precio del cliente", por_que="p", como="c")]))
        self.assertIn("Precio del cliente", texto)

    def test_ordena_por_severidad(self):
        texto, _ = generar(self.datos([h("baja", id="H01"), h("critica", id="H02", tipo="tabla_sin_rls")]))
        self.assertLess(texto.index("[CRÍTICO]"), texto.index("[BAJO]"))


class Decidir(unittest.TestCase):
    def setUp(self):
        fd, self.json = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        datos = {"hallazgos": [h("alta", tipo="sql_concatenado", estado="revisar", id="H01"),
                               h("media", tipo="politica_abierta", estado="revisar", id="H02")],
                 "verificaciones": {"rutas": {"estado": "pendiente_claude", "detalle": ""}}}
        with open(self.json, "w", encoding="utf-8") as f:
            json.dump(datos, f)

    def tearDown(self):
        os.remove(self.json)

    def leer(self):
        with open(self.json, encoding="utf-8") as f:
            return json.load(f)

    def test_flujo_completo(self):
        decidir([self.json, "confirmar", "H01", "--arreglo", "usa $1"])
        decidir([self.json, "descartar", "H02", "--motivo", "catálogo público"])
        decidir([self.json, "agregar", "--tipo", "ruta_sin_auth", "--severidad", "critica",
                 "--archivo", "s.js", "--linea", "3", "--detalle", "GET /admin sin login"])
        decidir([self.json, "rutas-revisadas", "--detalle", "1 ruta"])
        datos = self.leer()
        self.assertEqual([x["estado"] for x in datos["hallazgos"]], ["confirmado", "descartado", "confirmado"])
        self.assertEqual(datos["hallazgos"][2]["id"], "H03")
        self.assertEqual(datos["verificaciones"]["rutas"]["estado"], "revisado")
        texto, nota = generar(datos)
        self.assertEqual(nota, 40)
        self.assertIn("catálogo público", texto)

    def test_cambiar_severidad_exige_motivo(self):
        with self.assertRaises(SystemExit):
            decidir([self.json, "confirmar", "H01", "--severidad", "baja"])
        decidir([self.json, "confirmar", "H01", "--severidad", "baja", "--motivo", "solo en pruebas"])
        self.assertEqual(self.leer()["hallazgos"][0]["severidad"], "baja")

    def test_descartar_sin_motivo_falla(self):
        with self.assertRaises(SystemExit):
            decidir([self.json, "descartar", "H02"])


if __name__ == "__main__":
    unittest.main()
