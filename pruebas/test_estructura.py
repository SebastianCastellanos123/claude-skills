"""Comprueba que el marketplace, los plugins y las skills sean coherentes.

Cubre lo que `claude plugin validate` revisa en lo básico (que se puede correr
a mano) y agrega reglas propias del repositorio, sin necesitar Claude Code.
"""

import json
import os
import re
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOMBRE_VALIDO = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


def leer_json(*partes):
    with open(os.path.join(RAIZ, *partes), encoding="utf-8") as f:
        return json.load(f)


def frontmatter(ruta):
    with open(ruta, encoding="utf-8") as f:
        texto = f.read()
    m = re.match(r"^---\n(.*?)\n---\n", texto, re.S)
    if not m:
        return None, texto
    campos = {}
    for linea in m.group(1).splitlines():
        if ":" in linea and not linea.startswith(" "):
            clave, valor = linea.split(":", 1)
            campos[clave.strip()] = valor.strip().strip('"')
    return campos, texto[m.end():]


class Marketplace(unittest.TestCase):
    def setUp(self):
        self.marketplace = leer_json(".claude-plugin", "marketplace.json")

    def test_campos_obligatorios(self):
        for campo in ("name", "owner", "plugins", "description"):
            self.assertIn(campo, self.marketplace)
        self.assertTrue(NOMBRE_VALIDO.match(self.marketplace["name"]))
        self.assertNotIn("claude", self.marketplace["name"])  # nombres que imitan a los oficiales se rechazan

    def test_cada_plugin(self):
        nombres = [p["name"] for p in self.marketplace["plugins"]]
        self.assertEqual(len(nombres), len(set(nombres)))
        for entrada in self.marketplace["plugins"]:
            with self.subTest(plugin=entrada["name"]):
                self.assertTrue(NOMBRE_VALIDO.match(entrada["name"]))
                self.assertTrue(entrada["source"].startswith("./") and ".." not in entrada["source"])
                carpeta = os.path.join(RAIZ, entrada["source"])
                manifiesto = leer_json(entrada["source"], ".claude-plugin", "plugin.json")
                # Si los nombres difieren, la instalación falla con "not found in marketplace".
                self.assertEqual(manifiesto["name"], entrada["name"])
                skills = os.path.join(carpeta, "skills")
                self.assertTrue(os.path.isdir(skills))
                for skill in os.listdir(skills):
                    self._revisar_skill(os.path.join(skills, skill))

    def _revisar_skill(self, carpeta):
        campos, cuerpo = frontmatter(os.path.join(carpeta, "SKILL.md"))
        self.assertIsNotNone(campos, f"{carpeta}: SKILL.md sin frontmatter en la primera línea")
        self.assertEqual(campos.get("name"), os.path.basename(carpeta))
        self.assertGreater(len(campos.get("description", "")), 80)
        self.assertLessEqual(len(campos["description"]), 1536)
        self.assertLess(cuerpo.count("\n"), 500)
        # $1, $2... se sustituyen por argumentos de la skill: no deben aparecer por accidente.
        self.assertIsNone(re.search(r"\$\d", cuerpo), "SKILL.md contiene $N")
        for enlace in re.findall(r"\]\(([^)#]+)\)", cuerpo):
            if not enlace.startswith("http"):
                self.assertTrue(os.path.exists(os.path.join(carpeta, enlace)), enlace)
        for script in re.findall(r"\$\{CLAUDE_SKILL_DIR\}/([\w/.-]+\.py)", cuerpo):
            self.assertTrue(os.path.exists(os.path.join(carpeta, script)), script)


if __name__ == "__main__":
    unittest.main()
