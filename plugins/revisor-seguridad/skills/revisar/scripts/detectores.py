"""Detectores deterministas. Cada función recibe (ruta, texto) y devuelve una
lista de hallazgos (diccionarios). No ejecutan código del proyecto ni usan red.

Cada hallazgo tiene un "estado":
  - "confirmado": el patrón por sí solo ya es un problema.
  - "revisar": el patrón es sospechoso, pero hace falta leer el código para
    decidir (lo decide Claude siguiendo SKILL.md). No cuenta para la nota
    hasta que se confirme.
"""

import base64
import json
import re

from comun import enmascarar, linea_en, numero_de_linea


def hallazgo(tipo, severidad, archivo, linea, evidencia, detalle="", estado="confirmado"):
    return {
        "tipo": tipo,
        "severidad": severidad,
        "estado": estado,
        "archivo": archivo,
        "linea": linea,
        "evidencia": evidencia.strip()[:160],
        "detalle": detalle,
    }


# ---------------------------------------------------------------------------
# Secretos
# ---------------------------------------------------------------------------

# (nombre legible, expresión, severidad). El orden importa: lo más específico primero.
PATRONES_SECRETOS = [
    ("Clave privada (PEM)", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critica"),
    ("Clave de Anthropic", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"), "critica"),
    ("Clave de OpenAI (u otro proveedor con prefijo sk-)", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"), "critica"),
    ("Clave secreta de Stripe (modo real)", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}"), "critica"),
    ("Clave secreta de Stripe (modo prueba)", re.compile(r"\b[sr]k_test_[A-Za-z0-9]{20,}"), "baja"),
    ("ID de clave de acceso de AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critica"),
    ("Token de GitHub", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"), "critica"),
    ("Token de Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "alta"),
    ("Clave de SendGrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "alta"),
    ("Clave secreta de Supabase", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}"), "critica"),
    ("Clave de Google (AIza…)", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "media"),
]

_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
_RE_URL_BD = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp)://([^:@/\s'\"]+):([^@\s'\"]+)@"
)
_RE_ASIGNACION = re.compile(
    r"""(?ix)
    \b([A-Za-z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*)
    ["']?\s*[:=]\s*["']([^"'\s]{12,})["']
    """
)
# Variables que el framework mete en el código del navegador: lo que se nombre
# así es público, aunque se llame SECRET.
_RE_ENV_PUBLICA = re.compile(
    r"\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*"
    r"(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|STRIPE_SK|SK_LIVE)[A-Z0-9_]*)\b"
)

_PALABRAS_DE_RELLENO = (
    "xxx", "your", "tu_", "tu-", "tus_", "example", "ejemplo", "changeme", "cambiar",
    "cambia", "placeholder", "dummy", "replace", "reemplaza", "<", ">", "${", "{{",
    "process.env", "os.environ", "getenv", "import.meta.env", "env(", "redacted",
    "1234567890", "abcdef", "*****", "....",
)


def es_relleno(valor):
    v = valor.lower()
    if any(p in v for p in _PALABRAS_DE_RELLENO):
        return True
    return len(set(v)) <= 3  # "aaaaaaaaaaaa", "000000000000"


def _rol_jwt(token_payload):
    relleno = "=" * (-len(token_payload) % 4)
    try:
        datos = json.loads(base64.urlsafe_b64decode(token_payload + relleno))
    except (ValueError, json.JSONDecodeError):
        return None
    return datos.get("role") if isinstance(datos, dict) else None


def _es_config_firebase(texto):
    return bool(re.search(r"authDomain|firebaseConfig|initializeApp\s*\(|firebaseapp\.com", texto))


def detectar_secretos(ruta, texto, notas=None):
    """Credenciales escritas en el código. `notas` recibe observaciones que no son
    hallazgos (por ejemplo, claves públicas por diseño)."""
    resultados = []
    vistos = set()

    def agregar(nombre, severidad, pos, valor, detalle="", estado="confirmado"):
        if valor in vistos:
            return
        vistos.add(valor)
        linea = numero_de_linea(texto, pos)
        resultados.append(hallazgo(
            "secreto", severidad, ruta, linea,
            f"{nombre}: {enmascarar(valor)}", detalle or nombre, estado,
        ))

    for nombre, patron, severidad in PATRONES_SECRETOS:
        for m in patron.finditer(texto):
            valor = m.group(0)
            if es_relleno(valor):
                continue
            if nombre.startswith("Clave de Google"):
                if _es_config_firebase(texto):
                    if notas is not None:
                        notas.append(
                            f"{ruta}:{numero_de_linea(texto, m.start())}: apiKey de Firebase. Es pública por "
                            "diseño (va en el navegador); la seguridad depende de las reglas de Firebase. "
                            "Aun así, restríngela en Google Cloud > Credenciales a tu dominio y a las APIs que usas."
                        )
                    vistos.add(valor)
                    continue
                agregar(nombre, severidad, m.start(), valor,
                        "Clave de Google fuera de una configuración de Firebase (puede ser de Maps, Gemini u otra API de pago)",
                        estado="revisar")
                continue
            agregar(nombre, severidad, m.start(), valor)

    for m in _RE_JWT.finditer(texto):
        rol = _rol_jwt(m.group(1))
        if rol == "service_role":
            agregar("Clave service_role de Supabase", "critica", m.start(), m.group(0),
                    "Clave service_role de Supabase: se salta todas las políticas RLS")
        elif rol == "anon":
            vistos.add(m.group(0))  # pública por diseño
        else:
            agregar("JWT", "media", m.start(), m.group(0),
                    "Token JWT escrito en el código (puede ser una sesión o una credencial)", estado="revisar")

    for m in _RE_URL_BD.finditer(texto):
        clave = m.group(2)
        if es_relleno(clave) or clave.lower() in {"password", "postgres", "root", "pass", "contrasena"}:
            continue
        agregar("URL de base de datos con contraseña", "critica", m.start(), m.group(0))

    for m in _RE_ASIGNACION.finditer(texto):
        variable, valor = m.group(1), m.group(2)
        if valor in vistos or es_relleno(valor):
            continue
        # Exigimos letras y números para no confundir textos normales con claves.
        if not (re.search(r"[A-Za-z]", valor) and re.search(r"\d", valor)):
            continue
        agregar(f"Valor secreto asignado a {variable}", "alta", m.start(2), valor,
                f"Parece una credencial escrita directamente en `{variable}`", estado="revisar")

    for m in _RE_ENV_PUBLICA.finditer(texto):
        nombre = m.group(1)
        clave_visto = "env-publica:" + nombre
        if clave_visto in vistos:
            continue
        vistos.add(clave_visto)
        resultados.append(hallazgo(
            "secreto_en_frontend", "critica", ruta, numero_de_linea(texto, m.start()),
            nombre,
            f"`{nombre}`: el prefijo hace que el framework la meta en el JavaScript que descarga cualquier visitante",
        ))
    return resultados


# ---------------------------------------------------------------------------
# Supabase: tablas sin Row Level Security
# ---------------------------------------------------------------------------

def _sin_comentarios_sql(texto):
    texto = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), texto, flags=re.S)
    return re.sub(r"--[^\n]*", "", texto)


_NOMBRE = r'(?:"?(\w+)"?\.)?"?(\w+)"?'
_RE_CREAR_TABLA = re.compile(r"(?i)\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?" + _NOMBRE)
_RE_ACTIVAR_RLS = re.compile(
    r"(?i)\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?" + _NOMBRE + r"\s+enable\s+row\s+level\s+security"
)
_RE_DESACTIVAR_RLS = re.compile(
    r"(?i)\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?" + _NOMBRE + r"\s+disable\s+row\s+level\s+security"
)
_RE_POLITICA_ABIERTA = re.compile(
    r"(?is)\bcreate\s+policy\s+(\"[^\"]+\"|\w+)\s+on\s+" + _NOMBRE + r"(.*?)(?:;|$)"
)


def analizar_sql(archivos_sql):
    """Recibe [(ruta, texto)] de todas las migraciones juntas, porque el RLS de
    una tabla se puede activar en otro archivo distinto al que la crea."""
    creadas = {}      # tabla -> (ruta, línea)
    con_rls = set()
    resultados = []
    for ruta, texto in archivos_sql:
        limpio = _sin_comentarios_sql(texto)
        for m in _RE_CREAR_TABLA.finditer(limpio):
            esquema, tabla = (m.group(1) or "public").lower(), m.group(2).lower()
            if esquema == "public":
                creadas.setdefault(tabla, (ruta, numero_de_linea(limpio, m.start())))
        for m in _RE_ACTIVAR_RLS.finditer(limpio):
            if (m.group(1) or "public").lower() == "public":
                con_rls.add(m.group(2).lower())
        for m in _RE_DESACTIVAR_RLS.finditer(limpio):
            resultados.append(hallazgo(
                "rls_desactivado", "critica", ruta, numero_de_linea(limpio, m.start()),
                linea_en(texto, numero_de_linea(limpio, m.start())),
                f"Se desactiva RLS en la tabla `{m.group(2)}`",
            ))
        for m in _RE_POLITICA_ABIERTA.finditer(limpio):
            cuerpo = m.group(4)
            if re.search(r"(?i)\b(using|with\s+check)\s*\(\s*true\s*\)", cuerpo):
                linea = numero_de_linea(limpio, m.start())
                es_lectura = re.search(r"(?i)\bfor\s+select\b", cuerpo) is not None
                resultados.append(hallazgo(
                    "politica_abierta", "media" if es_lectura else "alta", ruta, linea,
                    linea_en(texto, linea),
                    f"La política {m.group(1)} de `{m.group(3)}` deja pasar a cualquiera (`true`)",
                    estado="revisar",
                ))
    for tabla, (ruta, linea) in sorted(creadas.items()):
        if tabla not in con_rls:
            resultados.append(hallazgo(
                "tabla_sin_rls", "critica", ruta, linea, f"create table {tabla}",
                f"La tabla `{tabla}` no tiene `enable row level security`",
            ))
    return resultados


# ---------------------------------------------------------------------------
# Firebase: reglas abiertas
# ---------------------------------------------------------------------------

_RE_ALLOW = re.compile(r"\ballow\s+([a-z ,]+?)\s*(?::\s*if\s+([^;]+))?;")


def analizar_reglas_firebase(ruta, texto):
    """firestore.rules / storage.rules."""
    resultados = []
    limpio = re.sub(r"//[^\n]*", "", texto)
    for m in _RE_ALLOW.finditer(limpio):
        operaciones = m.group(1)
        condicion = (m.group(2) or "").strip()
        linea = numero_de_linea(limpio, m.start())
        escribe = re.search(r"write|create|update|delete", operaciones) is not None
        if condicion in ("", "true"):
            detalle = f"`allow {operaciones.strip()}` sin condición: cualquier persona en internet puede hacerlo"
        elif re.fullmatch(r"request\.time\s*<\s*timestamp\.date\([^)]*\)", condicion):
            detalle = ("Reglas de 'modo de prueba': abiertas a todo el mundo hasta una fecha "
                       "(y después la app deja de funcionar)")
        else:
            continue
        resultados.append(hallazgo(
            "firebase_abierto", "critica" if escribe else "alta", ruta, linea,
            linea_en(texto, linea), detalle,
        ))
    return resultados


_RE_RTDB = re.compile(r'"\.(read|write)"\s*:\s*(true|"true")')


def analizar_reglas_rtdb(ruta, texto):
    """database.rules.json (Realtime Database)."""
    resultados = []
    for m in _RE_RTDB.finditer(texto):
        linea = numero_de_linea(texto, m.start())
        resultados.append(hallazgo(
            "firebase_abierto", "critica" if m.group(1) == "write" else "alta", ruta, linea,
            linea_en(texto, linea), f'`".{m.group(1)}": true` deja esa parte de la base abierta a cualquiera',
        ))
    return resultados


# ---------------------------------------------------------------------------
# CORS con origen abierto y credenciales
# ---------------------------------------------------------------------------

def _ventana(texto, inicio, largo=600):
    """Texto desde `inicio` hasta cerrar el primer paréntesis/llave (o `largo`)."""
    nivel = 0
    for i in range(inicio, min(len(texto), inicio + largo)):
        c = texto[i]
        if c in "({[":
            nivel += 1
        elif c in ")}]":
            nivel -= 1
            if nivel <= 0:
                return texto[inicio:i + 1]
    return texto[inicio:inicio + largo]


_RE_CORS_JS = re.compile(r"\bcors\s*\(")
_RE_ORIGEN_ABIERTO_JS = re.compile(
    r"""origin\s*:\s*(?:['"`]\*['"`]|true\b|\(\s*\w*\s*,\s*(\w+)\s*\)\s*=>\s*\1\s*\(\s*null\s*,\s*true\s*\))"""
)
_RE_CREDENCIALES_JS = re.compile(r"credentials\s*:\s*true\b")
_RE_FASTAPI_CORS = re.compile(r"\bCORSMiddleware\b")
_RE_FLASK_CORS = re.compile(r"\bCORS\s*\(")
_RE_HEADER_ORIGEN = re.compile(
    r"""Access-Control-Allow-Origin['"]?\s*(?:,|:|=>)\s*(?:['"]\*['"]|req(?:uest)?\.headers?(?:\.origin|\[['"]origin['"]\]|\.get\(\s*['"]origin['"]\s*\)))""",
    re.I,
)
_RE_HEADER_ORIGEN_JSON = re.compile(
    r"""["']?key["']?\s*:\s*["']Access-Control-Allow-Origin["']\s*,\s*["']?value["']?\s*:\s*["']\*["']""", re.I
)
_RE_HEADER_CRED = re.compile(r"""Access-Control-Allow-Credentials['"]?\s*(?:,|:|=>|["']?value["']?\s*:)?\s*['"]?true""", re.I)


def detectar_cors(ruta, texto):
    resultados = []

    def agregar(pos, detalle):
        linea = numero_de_linea(texto, pos)
        resultados.append(hallazgo("cors_abierto", "alta", ruta, linea, linea_en(texto, linea), detalle))

    for m in _RE_CORS_JS.finditer(texto):
        llamada = _ventana(texto, m.end() - 1)
        if _RE_ORIGEN_ABIERTO_JS.search(llamada) and _RE_CREDENCIALES_JS.search(llamada):
            agregar(m.start(), "CORS acepta cualquier origen y además permite enviar cookies/credenciales")
    for m in _RE_FASTAPI_CORS.finditer(texto):
        llamada = _ventana(texto, texto.find("(", m.end()) if "(" in texto[m.end():m.end() + 40] else m.end())
        if re.search(r"""allow_origins\s*=\s*\[\s*["']\*["']\s*\]""", llamada) and re.search(r"allow_credentials\s*=\s*True", llamada):
            agregar(m.start(), "CORSMiddleware con allow_origins=['*'] y allow_credentials=True")
    for m in _RE_FLASK_CORS.finditer(texto):
        llamada = _ventana(texto, m.end() - 1)
        if re.search(r"supports_credentials\s*=\s*True", llamada):
            origenes = re.search(r"""origins\s*=\s*(["'][^"']*["']|\[[^\]]*\])""", llamada)
            if origenes is None or "*" in origenes.group(1):
                agregar(m.start(), "Flask-CORS con supports_credentials=True y sin lista de orígenes (refleja cualquiera)")
    origen = _RE_HEADER_ORIGEN.search(texto) or _RE_HEADER_ORIGEN_JSON.search(texto)
    if origen and _RE_HEADER_CRED.search(texto):
        agregar(origen.start(), "Cabecera Access-Control-Allow-Origin abierta (o copiada del Origin) junto con Allow-Credentials: true")
    return resultados


# ---------------------------------------------------------------------------
# SQL armado concatenando texto
# ---------------------------------------------------------------------------

_SQL = r"(?:\bselect\b[^;]*?\bfrom\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b)"
_RE_SQL = re.compile(_SQL, re.I | re.S)
# Plantilla `...` de JS con ${} que NO es una plantilla etiquetada (sql`...`, Prisma.sql`...`),
# porque las etiquetadas sí parametrizan.
_RE_PLANTILLA_JS = re.compile(r"(?<![\w$.)\]])`([^`]*)`")
_RE_CONCAT = re.compile(
    r"""(["'])(?P<cadena>(?:(?!\1).)*)\1\s*\+\s*[\w$.\[\]()'"]+"""
)
_RE_FSTRING = re.compile(r"""\bf(["'])(?P<cadena>(?:(?!\1).)*\{[^}]+\}(?:(?!\1).)*)\1""")
_RE_FORMATO_PY = re.compile(r"""(["'])(?P<cadena>(?:(?!\1).)*)\1\s*(?:%\s*[\w(]|\.format\s*\()""")
_RE_PHP = re.compile(r'''"(?P<cadena>[^"\n]*\$\w+[^"\n]*)"''')


def detectar_sql(ruta, texto):
    resultados = []
    lineas_vistas = set()

    def agregar(pos, como):
        linea = numero_de_linea(texto, pos)
        if linea in lineas_vistas:
            return
        lineas_vistas.add(linea)
        resultados.append(hallazgo(
            "sql_concatenado", "alta", ruta, linea, linea_en(texto, linea),
            f"Consulta SQL armada con {como}", estado="revisar",
        ))

    for m in _RE_PLANTILLA_JS.finditer(texto):
        if "${" in m.group(1) and _RE_SQL.search(m.group(1)):
            agregar(m.start(), "una plantilla `${}`")
    for patron, como in ((_RE_CONCAT, "concatenación (+)"), (_RE_FSTRING, "un f-string"),
                         (_RE_FORMATO_PY, "% o .format()")):
        for m in patron.finditer(texto):
            cadena = m.group("cadena")
            if "\n" in cadena:
                continue
            # Basta con la parte del WHERE: "... WHERE id = " + id también es inyectable.
            if _RE_SQL.search(cadena) or re.search(r"(?i)\bwhere\s+\w+\s*(=|<|>|\blike\b|\bin\b)", cadena):
                agregar(m.start(), como)
    if ruta.endswith(".php"):
        for m in _RE_PHP.finditer(texto):
            if _RE_SQL.search(m.group("cadena")):
                agregar(m.start(), "variables dentro de la cadena")
    return resultados


# ---------------------------------------------------------------------------
# Cookies de sesión sin HttpOnly / Secure
# ---------------------------------------------------------------------------

_RE_NOMBRE_SESION = re.compile(r"(?i)(sess|sid|token|jwt|auth|access|refresh|login|user|remember)")
_RE_COOKIE_JS = re.compile(r"""\b(?:res|response|reply|ctx|c)?\.?cookies?(?:\(\))?\s*(?:\.set)?\s*\(\s*(['"`])([^'"`]+)\1""")
_RE_SET_COOKIE_PY = re.compile(r"""\.set_cookie\s*\(\s*(?:key\s*=\s*)?(['"])([^'"]+)\1""")
_RE_CONFIG_INSEGURA = re.compile(
    r"""(?x)
    (?P<httponly>\bhttpOnly\s*:\s*false\b|\bhttponly\s*=\s*False\b|SESSION_COOKIE_HTTPONLY\s*[=:]\s*False\b)
    |(?P<secure>\bsecure\s*:\s*false\b|\bsecure\s*=\s*False\b|(?:SESSION|CSRF)_COOKIE_SECURE\s*[=:]\s*False\b)
    """
)
_RE_DOCUMENT_COOKIE = re.compile(r"document\.cookie\s*=\s*([^;\n]+)")
_RE_SET_COOKIE_HEADER = re.compile(r"""Set-Cookie['"]?\s*[,:]\s*[`'"]([^`'"]+)""", re.I)


def detectar_cookies(ruta, texto):
    resultados = []
    lineas_vistas = set()

    def agregar(pos, severidad, detalle, estado="confirmado"):
        linea = numero_de_linea(texto, pos)
        if linea in lineas_vistas:
            return
        lineas_vistas.add(linea)
        resultados.append(hallazgo("cookie_insegura", severidad, ruta, linea, linea_en(texto, linea), detalle, estado))

    def revisar_opciones(pos, nombre, llamada, httponly, secure):
        if not _RE_NOMBRE_SESION.search(nombre):
            return
        faltan = []
        if not re.search(httponly, llamada):
            faltan.append("HttpOnly")
        if not re.search(secure, llamada):
            faltan.append("Secure")
        if faltan:
            agregar(pos, "alta" if "HttpOnly" in faltan else "media",
                    f"La cookie `{nombre}` se crea sin {' ni '.join(faltan)}")

    for m in _RE_COOKIE_JS.finditer(texto):
        if "cookie" not in m.group(0).lower():
            continue
        llamada = _ventana(texto, m.start() + m.group(0).rindex("("))
        revisar_opciones(m.start(), m.group(2), llamada, r"httpOnly\s*:\s*true", r"secure\s*:\s*(?:true|process\.env|[\w.]+\s*===)")
    for m in _RE_SET_COOKIE_PY.finditer(texto):
        llamada = _ventana(texto, m.start() + m.group(0).rindex("("))
        revisar_opciones(m.start(), m.group(2), llamada, r"httponly\s*=\s*True", r"secure\s*=\s*(?:True|not\s|\w+)")
    for m in _RE_CONFIG_INSEGURA.finditer(texto):
        if m.group("httponly"):
            agregar(m.start(), "alta", "HttpOnly desactivado explícitamente: el JavaScript de la página puede leer la cookie")
        else:
            agregar(m.start(), "media", "Secure desactivado: la cookie viaja también por HTTP sin cifrar", estado="revisar")
    for m in _RE_DOCUMENT_COOKIE.finditer(texto):
        if _RE_NOMBRE_SESION.search(m.group(1)):
            agregar(m.start(), "alta", "La sesión se guarda con document.cookie, que nunca puede ser HttpOnly")
    for m in _RE_SET_COOKIE_HEADER.finditer(texto):
        valor = m.group(1)
        nombre = valor.split("=", 1)[0]
        if _RE_NOMBRE_SESION.search(nombre) and "httponly" not in valor.lower():
            agregar(m.start(), "alta", f"Cabecera Set-Cookie de `{nombre}` sin HttpOnly")
    return resultados


# ---------------------------------------------------------------------------
# Inventario de rutas (no son hallazgos: Claude decide cuáles necesitan login)
# ---------------------------------------------------------------------------

_RE_SENAL_AUTH = re.compile(
    r"(?i)(auth|session|getuser|currentuser|current_user|usuario_actual|requireuser|require_user|verify_?token|verificar_?token|"
    r"jwt\.verify|getserversession|clerk|login_required|isauthenticated|is_authenticated|"
    r"passport\.authenticate|req\.user|request\.user|permission_classes|protect|ensure\w*logged|guard)"
)
_RE_RUTA_JS = re.compile(
    r"""\b(app|router|server|api|fastify|hono|route[rs]?)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]+)\3([^\n]*)"""
)
_RE_USO_GLOBAL_AUTH = re.compile(r"""\b(?:app|router)\.use\s*\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?[^)]*?(auth|protect|session|jwt|guard|require)""", re.I)
_RE_RUTA_PY = re.compile(
    r"""@(\w+)\.(route|get|post|put|patch|delete|api_route)\s*\(\s*['"]([^'"]+)['"]([^\n]*)"""
)
_RE_HANDLER_NEXT = re.compile(r"\bexport\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE)\b")
_PUBLICAS_PROBABLES = re.compile(r"(?i)(health|status|ping|login|signin|signup|register|registro|webhook|callback|public|publico|^/$)")


def _ruta_next(ruta):
    partes = ruta.split("/")
    if "api" in partes:
        partes = partes[partes.index("api"):]
    elif "app" in partes:
        partes = partes[partes.index("app") + 1:]
    return "/" + "/".join(p for p in partes[:-1] if not p.startswith("("))


def inventariar_rutas(ruta, texto):
    rutas = []
    auth_global = _RE_USO_GLOBAL_AUTH.search(texto) is not None

    def agregar(metodo, camino, pos, senal):
        rutas.append({
            "metodo": metodo.upper(), "ruta": camino, "archivo": ruta,
            "linea": numero_de_linea(texto, pos), "senales_auth": bool(senal),
            "publica_probable": bool(_PUBLICAS_PROBABLES.search(camino)),
        })

    es_python = ruta.endswith(".py")
    for m in ([] if es_python else _RE_RUTA_JS.finditer(texto)):
        resto = m.group(5)
        agregar(m.group(2), m.group(4), m.start(), auth_global or _RE_SENAL_AUTH.search(resto))
    for m in (_RE_RUTA_PY.finditer(texto) if es_python else []):
        metodo = m.group(2)
        if metodo in ("route", "api_route"):
            metodos = re.search(r"methods\s*=\s*\[([^\]]+)\]", m.group(4))
            metodo = ",".join(re.findall(r"\w+", metodos.group(1))) if metodos else "GET"
        siguiente = texto[m.start():m.end() + 900]
        # El cuerpo llega hasta el próximo decorador de ruta.
        corte = _RE_RUTA_PY.search(siguiente, len(m.group(0)))
        cuerpo = siguiente[:corte.start()] if corte else siguiente
        antes = texto[max(0, m.start() - 200):m.start()]
        agregar(metodo, m.group(3), m.start(), _RE_SENAL_AUTH.search(cuerpo) or "login_required" in antes)
    if re.search(r"(^|/)route\.(js|ts|mjs)$", ruta) or re.search(r"(^|/)pages/api/", ruta):
        senal = _RE_SENAL_AUTH.search(texto)
        handlers = _RE_HANDLER_NEXT.findall(texto) or (["*"] if "export default" in texto else [])
        for h in handlers:
            pos = texto.find(h) if h != "*" else 0
            agregar(h if h != "*" else "ALL", _ruta_next(ruta) if "pages/api/" not in ruta
                    else "/" + ruta.split("pages/", 1)[1].rsplit(".", 1)[0], pos, senal)
    if re.match(r"['\"]use server['\"]", texto.lstrip()):
        senal = _RE_SENAL_AUTH.search(texto)
        for m in re.finditer(r"\bexport\s+async\s+function\s+(\w+)", texto):
            agregar("ACCION", f"acción de servidor {m.group(1)}()", m.start(), senal)
    if re.search(r"(^|/)supabase/functions/[^/]+/index\.(ts|js)$", ruta):
        nombre_funcion = ruta.split("/")[-2]
        agregar("ALL", f"/functions/v1/{nombre_funcion}", 0, _RE_SENAL_AUTH.search(texto))
    return rutas
