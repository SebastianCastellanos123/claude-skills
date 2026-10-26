"""Explicaciones de cada tipo de hallazgo: qué es, por qué es peligroso y cómo
arreglarlo. Están en un solo lugar para que el reporte sea consistente; Claude
agrega el detalle concreto de cada caso (archivo, línea, código de ejemplo)."""

CATALOGO = {
    "secreto": {
        "titulo": "Credencial escrita en el código",
        "por_que": "Cualquiera con acceso al repositorio puede copiarla y usarla a tu nombre: gastar tu saldo "
                   "de API, cobrar con tu cuenta de pagos o leer tu base de datos. Si el archivo llega al "
                   "navegador, la ve cualquier visitante. Hay bots que buscan claves en GitHub todo el día y "
                   "las usan en minutos.",
        "como": "1. Revoca o rota la clave YA en el panel del proveedor: borrarla del código no basta, sigue "
                "en el historial de git.\n2. Ponla en una variable de entorno (`.env` incluido en "
                "`.gitignore`, o los secretos de tu hosting) y léela con `process.env.NOMBRE` / "
                "`os.environ[\"NOMBRE\"]`.\n3. Si el repositorio es o fue público, asume que ya la vieron.",
    },
    "secreto_en_historial": {
        "titulo": "Credencial que sigue en el historial de git",
        "por_que": "La borraste del código, pero cualquiera que clone el repositorio la ve con `git log -p`. "
                   "Para un atacante es igual de útil que si siguiera en el archivo.",
        "como": "1. Rota la clave en el panel del proveedor: es lo único que la invalida de verdad.\n"
                "2. Opcional, después de rotarla: limpia el historial con `git filter-repo` o BFG y haz "
                "force push. Si el repo es público, las copias que ya existan no se pueden borrar; por eso "
                "el paso 1 es obligatorio.",
    },
    "secreto_en_frontend": {
        "titulo": "Secreto con prefijo público (llega al navegador)",
        "por_que": "Las variables con prefijo `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` o `EXPO_PUBLIC_` se "
                   "copian dentro del JavaScript que descarga cada visitante. Cualquiera puede abrir las "
                   "herramientas del navegador y leerla, aunque esté en un `.env` que no subiste a git.",
        "como": "1. Rota la clave.\n2. Quítale el prefijo público y úsala solo en código de servidor (API "
                "routes, server actions, edge functions).\n3. En el navegador usa solo claves hechas para "
                "ser públicas (por ejemplo, la `anon key` de Supabase con RLS bien configurado).",
    },
    "env_versionado": {
        "titulo": "Archivo .env subido a git",
        "por_que": "El `.env` suele tener todas las claves del proyecto juntas. Estando en git, las tiene "
                   "cualquiera con acceso al repositorio, y quedan en el historial para siempre.",
        "como": "1. Rota todas las claves que contiene.\n2. Sácalo de git sin borrarlo de tu disco: "
                "`git rm --cached .env`.\n3. Agrega `.env*` y `!.env.example` a `.gitignore`.\n4. Deja un "
                "`.env.example` con los nombres de las variables y valores de mentira.",
    },
    "env_sin_ignorar": {
        "titulo": "Archivo .env que no está en .gitignore",
        "por_que": "Todavía no está en git, pero el próximo `git add .` (o el botón de commit del editor) lo "
                   "sube con todas tus claves.",
        "como": "Agrega `.env*` y `!.env.example` a `.gitignore` y confirma con `git status` que ya no "
                "aparece.",
    },
    "env_en_historial": {
        "titulo": "Archivo .env que estuvo en git",
        "por_que": "Lo sacaste del repositorio, pero sigue en commits viejos con los valores que tenía ese día.",
        "como": "Rota las claves que tenía en ese momento (`git show COMMIT:ruta/.env` te muestra cuáles "
                "eran, sin compartir la salida). Opcional: limpiar el historial con `git filter-repo`.",
    },
    "tabla_sin_rls": {
        "titulo": "Tabla de Supabase sin Row Level Security",
        "por_que": "Supabase publica las tablas de `public` en una API que se usa con la `anon key`, y esa "
                   "clave está en tu frontend. Sin RLS, cualquiera que la copie puede leer, modificar o borrar "
                   "TODAS las filas de esa tabla con una sola petición.",
        "como": "Activa RLS y crea políticas que limiten cada fila a su dueño:\n```sql\n"
                "alter table public.TABLA enable row level security;\n"
                "create policy \"cada quien ve lo suyo\" on public.TABLA\n"
                "  for select using (auth.uid() = usuario_id);\n```\n"
                "Con RLS activo y sin políticas, nadie puede acceder (eso es seguro: después agregas lo que "
                "sí se permite).",
    },
    "rls_desactivado": {
        "titulo": "Row Level Security desactivado a propósito",
        "por_que": "Igual que una tabla sin RLS: la `anon key` del frontend da acceso total a esa tabla.",
        "como": "Quita el `disable row level security`, activa RLS y escribe políticas. Si un proceso de "
                "servidor necesita saltarse RLS, que use la `service_role key` solo en el servidor.",
    },
    "politica_abierta": {
        "titulo": "Política de Supabase que deja pasar a todos",
        "por_que": "`using (true)` o `with check (true)` equivale a no tener RLS para esa operación. Puede "
                   "ser intencional para datos públicos de solo lectura (un catálogo), pero en escrituras o "
                   "datos personales es una fuga.",
        "como": "Cambia la condición por una que compare con el usuario: `using (auth.uid() = usuario_id)`. "
                "Para escrituras usa también `with check (auth.uid() = usuario_id)`.",
    },
    "firebase_abierto": {
        "titulo": "Reglas de Firebase abiertas",
        "por_que": "Las reglas son lo único que protege tu base de Firebase: el SDK y la configuración están "
                   "en el navegador. Con reglas abiertas cualquiera puede leer, cambiar o borrar todo usando "
                   "tu propia configuración pública. Las reglas de 'modo de prueba' además dejan de funcionar "
                   "en la fecha que tienen.",
        "como": "Exige usuario autenticado y que el documento sea suyo:\n```\n"
                "match /usuarios/{uid}/{doc=**} {\n"
                "  allow read, write: if request.auth != null && request.auth.uid == uid;\n}\n```\n"
                "Prueba los cambios con el simulador de reglas de la consola antes de publicarlos.",
    },
    "cors_abierto": {
        "titulo": "CORS abierto a cualquier origen con credenciales",
        "por_que": "Permite que cualquier página web, incluida una del atacante, haga peticiones a tu API con "
                   "las cookies de sesión de quien la visite y lea las respuestas. El navegador rechaza `*` "
                   "junto con credenciales, por eso la 'solución' típica es reflejar el origen (`origin: true`), "
                   "que abre la puerta del todo.",
        "como": "Lista los orígenes permitidos explícitamente:\n```js\n"
                "app.use(cors({ origin: ['https://tu-dominio.com'], credentials: true }));\n```\n"
                "En FastAPI: `allow_origins=[\"https://tu-dominio.com\"]`.",
    },
    "sql_concatenado": {
        "titulo": "Consulta SQL armada pegando texto (inyección SQL)",
        "por_que": "Si alguna parte del texto viene del usuario (URL, formulario, JSON), puede escribir SQL "
                   "propio: `1 OR 1=1` para ver todos los registros, o peor. Es una de las vulnerabilidades "
                   "más explotadas que existen.",
        "como": "Usa parámetros; la base de datos los trata como datos, nunca como código:\n```js\n"
                "pool.query('SELECT * FROM pedidos WHERE id = $1', [id]);\n```\n```python\n"
                "cursor.execute(\"SELECT * FROM pedidos WHERE id = %s\", (id,))\n```\n"
                "Con Prisma, `$queryRaw` con plantilla etiquetada es seguro; `$queryRawUnsafe` no.",
    },
    "cookie_insegura": {
        "titulo": "Cookie de sesión sin HttpOnly o Secure",
        "por_que": "Sin `HttpOnly`, cualquier script que logre correr en tu página (un XSS, una librería "
                   "comprometida) puede leer la cookie y robar la sesión. Sin `Secure`, la cookie viaja también "
                   "por HTTP sin cifrar, por ejemplo en un wifi público.",
        "como": "```js\nres.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });\n```\n"
                "```python\nresponse.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')\n```",
    },
    "dependencia_vulnerable": {
        "titulo": "Dependencia con vulnerabilidad conocida",
        "por_que": "La vulnerabilidad es pública, así que hay instrucciones (y a veces código) para explotarla. "
                   "No todas aplican a tu uso del paquete, pero actualizar suele ser barato.",
        "como": "Actualiza el paquete a una versión corregida (`npm audit fix`, o cambia la versión en "
                "`package.json` / `requirements.txt`) y vuelve a correr las pruebas de tu app.",
    },
    "ruta_sin_auth": {
        "titulo": "Ruta de servidor sin verificación de usuario",
        "por_que": "Cualquiera puede llamar a esa URL directamente (con curl, sin pasar por tu interfaz). Si "
                   "la ruta lee o cambia datos privados, no verificar quién llama es dejarlos abiertos.",
        "como": "Verifica la sesión al inicio de la ruta y responde 401 si no hay usuario. Si la ruta usa un "
                "ID (`/pedidos/:id`), comprueba además que el recurso sea de ese usuario.",
    },
    "acceso_sin_dueno": {
        "titulo": "Acceso a datos de otros usuarios cambiando un ID (IDOR)",
        "por_que": "La ruta pide login, pero no comprueba que el recurso sea del usuario: cambiando el número "
                   "en la URL se ven los datos de otra persona.",
        "como": "Filtra siempre por el dueño: `WHERE id = $1 AND usuario_id = $2` con el ID del usuario de la "
                "sesión, nunca con uno que venga en la petición.",
    },
}

SEVERIDADES = {
    "critica": "CRÍTICO",
    "alta": "ALTO",
    "media": "MEDIO",
    "baja": "BAJO",
}

# Nombres legibles de cada revisión, en el orden en que aparecen en el reporte.
REVISIONES = [
    ("secretos", "Secretos y claves de API en el código"),
    ("historial", "Secretos en el historial de git"),
    ("env", "Archivos .env versionados"),
    ("supabase", "Supabase: tablas sin RLS y políticas abiertas"),
    ("firebase", "Firebase: reglas abiertas"),
    ("rutas", "Rutas y endpoints sin verificación de usuario"),
    ("cors", "CORS abierto con credenciales"),
    ("sql", "SQL armado concatenando texto"),
    ("dependencias", "Dependencias con vulnerabilidades conocidas"),
    ("cookies", "Cookies de sesión sin HttpOnly/Secure"),
]

LIMITES = [
    "No ejecuta tu aplicación ni hace pruebas de penetración: revisa el código y la configuración que están en el repositorio.",
    "No ve lo que configuraste solo en paneles web (Supabase, Firebase, Vercel, AWS) si no está en el repositorio.",
    "Detecta secretos con patrones de proveedores conocidos y asignaciones obvias; una clave con formato raro puede pasar.",
    "No cubre toda la lógica de negocio (precios que manda el cliente, flujos de pago, límites de uso, XSS, SSRF, subida de archivos). Claude señala lo que vea, pero no hay garantía de encontrarlo todo.",
    "Una nota alta no significa que el proyecto sea seguro: significa que no se encontraron estos errores comunes.",
]
