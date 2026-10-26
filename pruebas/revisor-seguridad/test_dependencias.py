"""Pruebas de la lectura de npm audit / pnpm audit / pip-audit con salidas
grabadas, para no depender de internet."""

import json
import os
import tempfile
import unittest

import ayuda  # noqa: F401
from dependencias import auditar, parsear_npm_audit, parsear_pip_audit

NPM_V2 = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash", "severity": "high", "isDirect": True, "range": "<=4.17.23",
            "via": [{"title": "Command Injection in lodash", "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                     "severity": "high"}],
            "fixAvailable": {"name": "lodash", "version": "4.18.1", "isSemVerMajor": False},
        },
        "express": {"name": "express", "severity": "moderate", "isDirect": False, "range": "<4.20.0",
                    "via": ["body-parser"], "fixAvailable": True},
        "algo": {"name": "algo", "severity": "info", "via": [], "fixAvailable": False},
    },
}
NPM_ANTIGUO = {
    "advisories": {
        "1": {"module_name": "minimist", "severity": "critical", "title": "Prototype Pollution",
              "patched_versions": ">=1.2.6", "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h"},
        "2": {"module_name": "minimist", "severity": "moderate", "title": "Otra", "patched_versions": ">=1.2.6"},
    }
}
PIP_AUDIT = {
    "dependencies": [
        {"name": "django", "version": "3.2.0", "vulns": [{"id": "PYSEC-2021-98", "fix_versions": ["3.2.4"]}]},
        {"name": "requests", "version": "2.32.3", "vulns": []},
    ]
}


class Lectura(unittest.TestCase):
    def test_npm_v2(self):
        h = parsear_npm_audit(json.dumps(NPM_V2), "package-lock.json")
        self.assertEqual([(x["paquete"], x["severidad"]) for x in h], [("express", "media"), ("lodash", "alta")])
        lodash = h[1]
        self.assertEqual(lodash["arreglo"], "actualizar lodash a 4.18.1")
        self.assertIn("Command Injection", lodash["detalle"])
        self.assertIn("otra dependencia", h[0]["detalle"])

    def test_formato_antiguo_toma_la_peor_severidad(self):
        h = parsear_npm_audit(json.dumps(NPM_ANTIGUO), "pnpm-lock.yaml")
        self.assertEqual([(x["paquete"], x["severidad"]) for x in h], [("minimist", "critica")])

    def test_pip_audit(self):
        h = parsear_pip_audit(json.dumps(PIP_AUDIT), "requirements.txt")
        self.assertEqual([(x["paquete"], x["arreglo"]) for x in h], [("django", "actualizar a 3.2.4")])

    def test_salida_rota_devuelve_none(self):
        self.assertIsNone(parsear_npm_audit("npm ERR! network", "package-lock.json"))
        self.assertIsNone(parsear_pip_audit("", "requirements.txt"))


class SinRed(unittest.TestCase):
    def test_sin_red_no_consulta_y_lo_dice(self):
        carpeta = tempfile.mkdtemp()
        with open(os.path.join(carpeta, "package.json"), "w") as f:
            f.write("{}")
        hallazgos, verificacion, _ = auditar(carpeta, sin_red=True)
        self.assertEqual(hallazgos, [])
        self.assertEqual(verificacion["estado"], "no_verificado")

    def test_sin_proyecto_no_aplica(self):
        self.assertEqual(auditar(tempfile.mkdtemp())[1]["estado"], "no_aplica")


if __name__ == "__main__":
    unittest.main()
