"""Pruebas de punta a punta sobre los proyectos de ejemplo.

- vulnerable: cada categoría plantada se detecta.
- limpio: cero hallazgos (ni confirmados ni por revisar).

La consulta real a npm audit solo corre con REVISOR_PRUEBAS_RED=1, porque
depende de internet y del registro de npm.
"""

import json
import os
import shutil
import tempfile
import unittest

import ayuda
from construir import claves_falsas, construir
from escanear import escanear, main as escanear_main


class _ConEjemplo(unittest.TestCase):
    ejemplo = None

    @classmethod
    def setUpClass(cls):
        cls.carpeta = tempfile.mkdtemp(prefix="revisor-prueba-")
        cls.proyecto = construir(cls.ejemplo, os.path.join(cls.carpeta, cls.ejemplo))
        cls.resultado = escanear(cls.proyecto, sin_red=True)
        cls.hallazgos = cls.resultado["hallazgos"]

    @classmethod
    def tearDownClass(cls):
        # git deja archivos de solo lectura en .git/objects (Windows no los borra sin esto).
        def forzar(funcion, ruta, _):
            os.chmod(ruta, 0o700)
            funcion(ruta)
        shutil.rmtree(cls.carpeta, onerror=forzar)

    def buscar(self, tipo, archivo=None):
        return [h for h in self.hallazgos if h["tipo"] == tipo and (archivo is None or h["archivo"] == archivo)]


class Vulnerable(_ConEjemplo):
    ejemplo = "vulnerable"

    def test_secretos_en_el_codigo(self):
        archivos = {h["archivo"] for h in self.buscar("secreto") if h["estado"] == "confirmado"}
        self.assertEqual(archivos, {"src/pagos.js", "src/supabaseCliente.js", "api/app.py"})

    def test_secreto_en_historial(self):
        h = self.buscar("secreto_en_historial")
        self.assertEqual([x["archivo"] for x in h], ["config/claves.js"])
        self.assertTrue(h[0]["commit"])

    def test_env_versionado_sin_repetir_sus_secretos(self):
        h = self.buscar("env_versionado")
        self.assertEqual([(x["archivo"], x["severidad"]) for x in h], [(".env", "critica")])
        self.assertIn("STRIPE_SECRET_KEY", h[0]["detalle"])
        # Los secretos del .env no se reportan otra vez (ni del código ni del historial).
        self.assertFalse([x for x in self.hallazgos if x["archivo"] == ".env" and x["tipo"].startswith("secreto")
                          and x["tipo"] != "secreto_en_frontend"])

    def test_secreto_con_prefijo_publico(self):
        self.assertEqual(len(self.buscar("secreto_en_frontend")), 1)

    def test_supabase(self):
        self.assertEqual([h["detalle"] for h in self.buscar("tabla_sin_rls")],
                         ["La tabla `pedidos` no tiene `enable row level security`"])
        self.assertEqual(len(self.buscar("politica_abierta")), 1)

    def test_firebase(self):
        self.assertEqual([h["severidad"] for h in self.buscar("firebase_abierto")], ["critica"])

    def test_cors(self):
        self.assertEqual(sorted(h["archivo"] for h in self.buscar("cors_abierto")), ["api/app.py", "src/servidor.js"])

    def test_sql(self):
        self.assertEqual(sorted(h["archivo"] for h in self.buscar("sql_concatenado")),
                         ["api/app.py", "app/api/reportes/route.ts", "src/servidor.js"])

    def test_cookies(self):
        self.assertEqual(sorted(h["archivo"] for h in self.buscar("cookie_insegura")), ["api/app.py", "src/servidor.js"])

    def test_rutas_sin_senales_de_login(self):
        sin_auth = {r["ruta"] for r in self.resultado["rutas"] if not r["senales_auth"] and not r["publica_probable"]}
        self.assertTrue({"/api/admin/usuarios", "/api/pedidos/:id", "/api/reportes"} <= sin_auth)

    def test_nada_del_json_tiene_un_secreto_completo(self):
        texto = json.dumps(self.resultado)
        for valor in claves_falsas().values():
            self.assertNotIn(valor, texto)

    def test_cli_escribe_el_json(self):
        salida = os.path.join(self.carpeta, "salida.json")
        with ayuda.silencio():
            self.assertEqual(escanear_main([self.proyecto, "--sin-red", "--salida", salida]), 0)
        with open(salida, encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)["hallazgos"]), len(self.hallazgos))

    @unittest.skipUnless(os.environ.get("REVISOR_PRUEBAS_RED") == "1" and shutil.which("npm"),
                         "Necesita internet y npm (REVISOR_PRUEBAS_RED=1)")
    def test_npm_audit_real(self):
        resultado = escanear(self.proyecto, sin_red=False, sin_historial=True)
        paquetes = [h["paquete"] for h in resultado["hallazgos"] if h["tipo"] == "dependencia_vulnerable"]
        self.assertIn("lodash", paquetes)
        self.assertEqual(resultado["verificaciones"]["dependencias"]["estado"], "revisado")


class Limpio(_ConEjemplo):
    ejemplo = "limpio"

    def test_sin_hallazgos(self):
        self.assertEqual(self.hallazgos, [], json.dumps(self.hallazgos, ensure_ascii=False, indent=1))

    def test_el_env_ignorado_no_se_toca_pero_existe(self):
        self.assertTrue(os.path.exists(os.path.join(self.proyecto, ".env")))

    def test_rutas_sin_senales_son_solo_las_publicas(self):
        for r in self.resultado["rutas"]:
            if not r["senales_auth"]:
                self.assertTrue(r["publica_probable"] or r["ruta"] == "/productos/buscar", r)

    def test_todo_revisado(self):
        v = self.resultado["verificaciones"]
        for clave in ("secretos", "historial", "env", "supabase", "firebase", "cors", "sql", "cookies"):
            self.assertEqual(v[clave]["estado"], "revisado", clave)

    def test_firebase_apikey_queda_como_nota(self):
        self.assertTrue(any("apiKey de Firebase" in n for n in self.resultado["notas"]))


class SinGit(unittest.TestCase):
    def test_carpeta_sin_git(self):
        carpeta = tempfile.mkdtemp(prefix="revisor-singit-")
        try:
            with open(os.path.join(carpeta, ".env"), "w") as f:
                f.write("API_KEY=algo\n")
            with open(os.path.join(carpeta, "a.js"), "w") as f:
                f.write("const s = 1;\n")
            r = escanear(carpeta, sin_red=True)
            self.assertEqual(r["verificaciones"]["historial"]["estado"], "no_aplica")
            self.assertEqual([h["tipo"] for h in r["hallazgos"]], ["env_sin_ignorar"])
        finally:
            shutil.rmtree(carpeta, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
