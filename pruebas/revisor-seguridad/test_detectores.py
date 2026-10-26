"""Pruebas de cada detector con fragmentos pequeños: casos que deben saltar y
casos parecidos que NO deben saltar (los falsos positivos importan tanto como
los aciertos)."""

import unittest

import ayuda  # noqa: F401
from comun import enmascarar, es_archivo_env
from construir import claves_falsas
from detectores import (
    analizar_reglas_firebase, analizar_reglas_rtdb, analizar_sql, detectar_cookies,
    detectar_cors, detectar_secretos, detectar_sql, inventariar_rutas,
)

CLAVES = claves_falsas()


def tipos(hallazgos):
    return [h["tipo"] for h in hallazgos]


class Secretos(unittest.TestCase):
    def test_detecta_claves_de_proveedores(self):
        for clave in ("STRIPE_LIVE", "GITHUB_TOKEN", "OPENAI"):
            with self.subTest(clave=clave):
                h = detectar_secretos("a.js", f"const k = '{CLAVES[clave]}';")
                self.assertEqual(len(h), 1)
                self.assertEqual(h[0]["severidad"], "critica")
                self.assertEqual(h[0]["estado"], "confirmado")

    def test_nunca_muestra_el_secreto_completo(self):
        h = detectar_secretos("a.js", f"x = '{CLAVES['STRIPE_LIVE']}'")
        self.assertNotIn(CLAVES["STRIPE_LIVE"], h[0]["evidencia"])
        self.assertNotIn(CLAVES["STRIPE_LIVE"], h[0]["detalle"])

    def test_service_role_es_critica_y_anon_no_es_hallazgo(self):
        self.assertEqual(detectar_secretos("a.js", f"'{CLAVES['SERVICE_ROLE_JWT']}'")[0]["severidad"], "critica")
        self.assertEqual(detectar_secretos("a.js", f"'{CLAVES['ANON_JWT']}'"), [])

    def test_apikey_de_firebase_es_nota_no_hallazgo(self):
        notas = []
        texto = f"const firebaseConfig = {{ apiKey: '{CLAVES['FIREBASE_KEY']}', authDomain: 'x.firebaseapp.com' }};"
        self.assertEqual(detectar_secretos("f.js", texto, notas), [])
        self.assertEqual(len(notas), 1)

    def test_clave_de_google_fuera_de_firebase_queda_por_revisar(self):
        h = detectar_secretos("maps.js", f"const KEY = '{CLAVES['FIREBASE_KEY']}';")
        self.assertEqual([x["estado"] for x in h], ["revisar"])

    def test_ignora_valores_de_ejemplo_y_variables_de_entorno(self):
        texto = (
            "const a = 'AKIAIOSFODNN7EXAMPLE';\n"
            "api_key = os.environ['API_KEY']\n"
            "const token = process.env.TOKEN;\n"
            "password: 'tu_contrasena_aqui1'\n"
            "DATABASE_URL=postgres://usuario:contrasena@localhost/db\n"
        )
        self.assertEqual(detectar_secretos("a.py", texto), [])

    def test_asignacion_generica_queda_por_revisar(self):
        h = detectar_secretos("a.py", "API_SECRET = 'x8Hk2LmQ9vTz4Wp7'")
        self.assertEqual(tipos(h), ["secreto"])
        self.assertEqual(h[0]["estado"], "revisar")

    def test_variable_publica_con_nombre_de_secreto(self):
        h = detectar_secretos("a.js", "process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")
        self.assertEqual(tipos(h), ["secreto_en_frontend"])
        self.assertEqual(detectar_secretos("a.js", "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY"), [])

    def test_url_de_base_de_datos_con_clave(self):
        h = detectar_secretos("a.js", f"postgres://admin:{CLAVES['DB_PASS']}@db.example.com:5432/app")
        self.assertEqual(h[0]["severidad"], "critica")


class Archivos(unittest.TestCase):
    def test_es_archivo_env(self):
        for ruta in (".env", ".env.local", "api/.env.production"):
            self.assertTrue(es_archivo_env(ruta), ruta)
        for ruta in (".env.example", ".env.sample", "config/.env.template", "env.js", "dot.env"):
            self.assertFalse(es_archivo_env(ruta), ruta)

    def test_enmascarar(self):
        self.assertEqual(enmascarar("abcdefghijklmnop"), "abcdef…(16 caracteres)")


class Supabase(unittest.TestCase):
    def test_tabla_sin_rls(self):
        sql = "create table public.pedidos (id int);\ncreate table perfiles (id int);\nalter table perfiles enable row level security;"
        h = analizar_sql([("m.sql", sql)])
        self.assertEqual([x["detalle"] for x in h], ["La tabla `pedidos` no tiene `enable row level security`"])

    def test_rls_en_otra_migracion_cuenta(self):
        h = analizar_sql([("1.sql", "create table if not exists \"pedidos\" (id int);"),
                          ("2.sql", "ALTER TABLE ONLY public.pedidos ENABLE ROW LEVEL SECURITY;")])
        self.assertEqual(h, [])

    def test_comentarios_no_cuentan(self):
        h = analizar_sql([("m.sql", "create table pedidos (id int);\n-- alter table pedidos enable row level security;")])
        self.assertEqual(tipos(h), ["tabla_sin_rls"])

    def test_otros_esquemas_no_se_exponen(self):
        self.assertEqual(analizar_sql([("m.sql", "create table privado.registros (id int);")]), [])

    def test_politicas_abiertas_y_rls_desactivado(self):
        sql = ("create table t (id int); alter table t enable row level security;\n"
               "create policy \"leer\" on t for select using (true);\n"
               "create policy escribir on t for insert with check (true);\n"
               "create policy propia on t for select using (auth.uid() = id);\n"
               "alter table t disable row level security;")
        h = analizar_sql([("m.sql", sql)])
        self.assertEqual(sorted((x["tipo"], x["severidad"]) for x in h),
                         [("politica_abierta", "alta"), ("politica_abierta", "media"), ("rls_desactivado", "critica")])


class Firebase(unittest.TestCase):
    def test_reglas_abiertas_y_modo_prueba(self):
        for regla in ("allow read, write;", "allow read, write: if true;",
                      "allow read, write: if request.time < timestamp.date(2025, 1, 1);"):
            with self.subTest(regla=regla):
                h = analizar_reglas_firebase("firestore.rules", f"match /x/{{d}} {{ {regla} }}")
                self.assertEqual([x["severidad"] for x in h], ["critica"])

    def test_lectura_abierta_es_alta(self):
        h = analizar_reglas_firebase("firestore.rules", "allow read: if true;")
        self.assertEqual(h[0]["severidad"], "alta")

    def test_reglas_con_auth_no_saltan(self):
        texto = ("allow read, write: if request.auth != null && request.auth.uid == uid;\n"
                 "// allow read, write: if true;\n")
        self.assertEqual(analizar_reglas_firebase("firestore.rules", texto), [])

    def test_realtime_database(self):
        h = analizar_reglas_rtdb("database.rules.json", '{"rules": {".read": true, ".write": "auth != null"}}')
        self.assertEqual([x["severidad"] for x in h], ["alta"])


class Cors(unittest.TestCase):
    def test_casos_peligrosos(self):
        casos = [
            "app.use(cors({ origin: true, credentials: true }))",
            "app.use(cors({\n  origin: '*',\n  credentials: true,\n}))",
            "app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }))",
            'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)',
            "CORS(app, supports_credentials=True)",
            "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
        ]
        for texto in casos:
            with self.subTest(texto=texto):
                self.assertEqual(tipos(detectar_cors("a.js", texto)), ["cors_abierto"])

    def test_casos_seguros(self):
        casos = [
            "app.use(cors({ origin: ['https://mi.app'], credentials: true }))",
            "app.use(cors())",  # sin credenciales: válido para APIs públicas
            "app.use(cors({ origin: '*' }))",
            'app.add_middleware(CORSMiddleware, allow_origins=["https://mi.app"], allow_credentials=True)',
            "CORS(app, origins=['https://mi.app'], supports_credentials=True)",
        ]
        for texto in casos:
            with self.subTest(texto=texto):
                self.assertEqual(detectar_cors("a.js", texto), [])


class Sql(unittest.TestCase):
    def test_concatenaciones(self):
        casos = [
            ("a.js", 'db.query("SELECT * FROM t WHERE id = " + req.params.id)'),
            ("a.js", "db.query(`SELECT * FROM t WHERE nombre = '${nombre}'`)"),
            ("a.py", 'cur.execute(f"SELECT * FROM t WHERE id = {id}")'),
            ("a.py", 'cur.execute("SELECT * FROM t WHERE id = %s" % id)'),
            ("a.py", 'cur.execute("DELETE FROM t WHERE id = {}".format(id))'),
            ("a.js", 'const q = "UPDATE usuarios SET rol = \'" + rol + "\'";'),
        ]
        for ruta, texto in casos:
            with self.subTest(texto=texto):
                h = detectar_sql(ruta, texto)
                self.assertEqual(tipos(h), ["sql_concatenado"])
                self.assertEqual(h[0]["estado"], "revisar")

    def test_consultas_parametrizadas_no_saltan(self):
        casos = [
            "db.query('SELECT * FROM t WHERE id = $1', [id])",
            'cur.execute("SELECT * FROM t WHERE nombre LIKE ?", (f"%{q}%",))',
            "await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`",
            "await sql`SELECT * FROM t WHERE id = ${id}`",
            "const mensaje = `Seleccionaste ${n} productos`;",
            'console.log("Error: " + error.message)',
        ]
        for texto in casos:
            with self.subTest(texto=texto):
                self.assertEqual(detectar_sql("a.js", texto), [])


class Cookies(unittest.TestCase):
    def test_cookies_de_sesion_inseguras(self):
        casos = [
            "res.cookie('session', token);",
            "res.cookie('token', t, { secure: true });",
            "cookies().set('auth', t, { secure: true })",
            'response.set_cookie("session_id", valor)',
            "res.cookie('sid', t, { httpOnly: false, secure: true })",
            "document.cookie = 'jwt=' + token;",
            "SESSION_COOKIE_HTTPONLY = False",
        ]
        for texto in casos:
            with self.subTest(texto=texto):
                self.assertEqual(tipos(detectar_cookies("a.js", texto)), ["cookie_insegura"])

    def test_cookies_seguras_o_no_de_sesion(self):
        casos = [
            "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });",
            "res.cookie('tema', 'oscuro');",
            'response.set_cookie("session_id", t, httponly=True, secure=True)',
            "document.cookie = 'idioma=es';",
            "const s = req.cookies.session;",
        ]
        for texto in casos:
            with self.subTest(texto=texto):
                self.assertEqual(detectar_cookies("a.js", texto), [])


class Rutas(unittest.TestCase):
    def test_express(self):
        texto = ("app.get('/api/pedidos', requireAuth, listar);\n"
                 "app.post('/api/admin', async (req, res) => {});\n"
                 "router.delete('/health', ok);\n")
        rutas = inventariar_rutas("server.js", texto)
        self.assertEqual([(r["metodo"], r["ruta"], r["senales_auth"]) for r in rutas],
                         [("GET", "/api/pedidos", True), ("POST", "/api/admin", False), ("DELETE", "/health", False)])
        self.assertTrue(rutas[2]["publica_probable"])

    def test_python_sin_duplicados(self):
        texto = ('@app.get("/a")\ndef a():\n    return 1\n\n'
                 '@app.post("/b")\ndef b(u=Depends(get_current_user)):\n    return 2\n')
        rutas = inventariar_rutas("main.py", texto)
        self.assertEqual([(r["ruta"], r["senales_auth"]) for r in rutas], [("/a", False), ("/b", True)])

    def test_flask_con_metodos(self):
        rutas = inventariar_rutas("app.py", "@app.route('/x', methods=['POST', 'PUT'])\ndef x():\n    pass\n")
        self.assertEqual(rutas[0]["metodo"], "POST,PUT")

    def test_next_app_router(self):
        rutas = inventariar_rutas("src/app/api/(privado)/pedidos/[id]/route.ts",
                                  "export async function GET() {}\nexport const POST = async () => {};")
        self.assertEqual([(r["metodo"], r["ruta"]) for r in rutas],
                         [("GET", "/api/pedidos/[id]"), ("POST", "/api/pedidos/[id]")])

    def test_server_actions(self):
        rutas = inventariar_rutas("app/acciones.ts", "'use server'\nexport async function borrar(id) {}")
        self.assertEqual(rutas[0]["metodo"], "ACCION")


if __name__ == "__main__":
    unittest.main()
