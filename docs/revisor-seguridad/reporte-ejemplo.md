<!-- Reporte generado con la skill sobre pruebas/revisor-seguridad/ejemplos/vulnerable: escanear.py, decisiones de Claude con decidir.py (3 SQL confirmados, 1 política descartada, 3 rutas sin login y 1 hallazgo manual) y reporte.py. Las claves son falsas. -->

# Reporte de seguridad: tienda-vibe

## Nota: 0/100 · Crítico

Críticos: 9 · Altos: 10 · Medios: 0 · Bajos: 0

Revisado el 2026-10-25 con revisor-seguridad 0.1.0.

### Para compartir

Este resumen no revela detalles de los problemas; el resto del reporte sí, así que no lo publiques hasta arreglarlos.

> Mi proyecto sacó **0/100** en la revisión de seguridad de revisor-seguridad (9 críticos, 10 altos).

## Hallazgos

### 1. [CRÍTICO] Archivo .env subido a git

**Dónde:** `.env`

**Qué está mal:** `.env` está versionado en git. Contiene valores para: SUPABASE_SERVICE_ROLE_KEY, NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY, STRIPE_SECRET_KEY.

**Por qué es peligroso:** El `.env` suele tener todas las claves del proyecto juntas. Estando en git, las tiene cualquiera con acceso al repositorio, y quedan en el historial para siempre.

**Cómo arreglarlo:**

1. Rota todas las claves que contiene.
2. Sácalo de git sin borrarlo de tu disco: `git rm --cached .env`.
3. Agrega `.env*` y `!.env.example` a `.gitignore`.
4. Deja un `.env.example` con los nombres de las variables y valores de mentira.

### 2. [CRÍTICO] Secreto con prefijo público (llega al navegador)

**Dónde:** `.env:3`

**Qué está mal:** `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`: el prefijo hace que el framework la meta en el JavaScript que descarga cualquier visitante

**Por qué es peligroso:** Las variables con prefijo `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` o `EXPO_PUBLIC_` se copian dentro del JavaScript que descarga cada visitante. Cualquiera puede abrir las herramientas del navegador y leerla, aunque esté en un `.env` que no subiste a git.

**Cómo arreglarlo:**

1. Rota la clave.
2. Quítale el prefijo público y úsala solo en código de servidor (API routes, server actions, edge functions).
3. En el navegador usa solo claves hechas para ser públicas (por ejemplo, la `anon key` de Supabase con RLS bien configurado).

### 3. [CRÍTICO] Credencial escrita en el código

**Dónde:** `api/app.py:15`

**Qué está mal:** Clave de OpenAI (u otro proveedor con prefijo sk-)

**Por qué es peligroso:** Cualquiera con acceso al repositorio puede copiarla y usarla a tu nombre: gastar tu saldo de API, cobrar con tu cuenta de pagos o leer tu base de datos. Si el archivo llega al navegador, la ve cualquier visitante. Hay bots que buscan claves en GitHub todo el día y las usan en minutos.

**Cómo arreglarlo:**

1. Revoca o rota la clave YA en el panel del proveedor: borrarla del código no basta, sigue en el historial de git.
2. Ponla en una variable de entorno (`.env` incluido en `.gitignore`, o los secretos de tu hosting) y léela con `process.env.NOMBRE` / `os.environ["NOMBRE"]`.
3. Si el repositorio es o fue público, asume que ya la vieron.

### 4. [CRÍTICO] Credencial que sigue en el historial de git

**Dónde:** `config/claves.js` (commit d62910f)

**Qué está mal:** Token de GitHub (agregado en el commit d62910f; ya no está en el código actual, pero sigue en el historial)

**Por qué es peligroso:** La borraste del código, pero cualquiera que clone el repositorio la ve con `git log -p`. Para un atacante es igual de útil que si siguiera en el archivo.

**Cómo arreglarlo:**

1. Rota la clave en el panel del proveedor: es lo único que la invalida de verdad.
2. Opcional, después de rotarla: limpia el historial con `git filter-repo` o BFG y haz force push. Si el repo es público, las copias que ya existan no se pueden borrar; por eso el paso 1 es obligatorio.

### 5. [CRÍTICO] Reglas de Firebase abiertas

**Dónde:** `firestore.rules:5`

**Qué está mal:** Reglas de 'modo de prueba': abiertas a todo el mundo hasta una fecha (y después la app deja de funcionar)

**Por qué es peligroso:** Las reglas son lo único que protege tu base de Firebase: el SDK y la configuración están en el navegador. Con reglas abiertas cualquiera puede leer, cambiar o borrar todo usando tu propia configuración pública. Las reglas de 'modo de prueba' además dejan de funcionar en la fecha que tienen.

**Cómo arreglarlo:**

Exige usuario autenticado y que el documento sea suyo:
```
match /usuarios/{uid}/{doc=**} {
  allow read, write: if request.auth != null && request.auth.uid == uid;
}
```
Prueba los cambios con el simulador de reglas de la consola antes de publicarlos.

### 6. [CRÍTICO] Credencial escrita en el código

**Dónde:** `src/pagos.js:3`

**Qué está mal:** Clave secreta de Stripe (modo real)

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 3.

### 7. [CRÍTICO] Credencial escrita en el código

**Dónde:** `src/supabaseCliente.js:6`

**Qué está mal:** Clave service_role de Supabase: se salta todas las políticas RLS

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 3.

### 8. [CRÍTICO] Tabla de Supabase sin Row Level Security

**Dónde:** `supabase/migrations/20250101000000_inicial.sql:10`

**Qué está mal:** La tabla `pedidos` no tiene `enable row level security`

**Por qué es peligroso:** Supabase publica las tablas de `public` en una API que se usa con la `anon key`, y esa clave está en tu frontend. Sin RLS, cualquiera que la copie puede leer, modificar o borrar TODAS las filas de esa tabla con una sola petición.

**Cómo arreglarlo:**

Activa RLS y crea políticas que limiten cada fila a su dueño:
```sql
alter table public.TABLA enable row level security;
create policy "cada quien ve lo suyo" on public.TABLA
  for select using (auth.uid() = usuario_id);
```
Con RLS activo y sin políticas, nadie puede acceder (eso es seguro: después agregas lo que sí se permite).

### 9. [CRÍTICO] Ruta de servidor sin verificación de usuario

**Dónde:** `src/servidor.js:28`

**Qué está mal:** GET /api/admin/usuarios devuelve el email y el teléfono de todos los usuarios sin pedir sesión

**Por qué es peligroso:** Cualquiera puede llamar a esa URL directamente (con curl, sin pasar por tu interfaz). Si la ruta lee o cambia datos privados, no verificar quién llama es dejarlos abiertos.

**Cómo arreglarlo:**

Verifica la sesión al inicio de la ruta y responde 401 si no hay usuario. Si la ruta usa un ID (`/pedidos/:id`), comprueba además que el recurso sea de ese usuario.

**En tu caso:** agrega un middleware que verifique la sesión y que req.user.rol === 'admin' antes del handler

### 10. [ALTO] Cookie de sesión sin HttpOnly o Secure

**Dónde:** `api/app.py:27`

**Qué está mal:** La cookie `session_id` se crea sin HttpOnly ni Secure

**Por qué es peligroso:** Sin `HttpOnly`, cualquier script que logre correr en tu página (un XSS, una librería comprometida) puede leer la cookie y robar la sesión. Sin `Secure`, la cookie viaja también por HTTP sin cifrar, por ejemplo en un wifi público.

**Cómo arreglarlo:**

```js
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
```
```python
response.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')
```

### 11. [ALTO] Dependencia con vulnerabilidad conocida

**Dónde:** `package-lock.json`

**Qué está mal:** lodash <=4.17.23: Command Injection in lodash; Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions; Prototype Pollution in lodash; Regular Expression Denial of Service (ReDoS) in lodash; lodash vulnerable to Code Injection via `_.template` imports key names; lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`

**Por qué es peligroso:** La vulnerabilidad es pública, así que hay instrucciones (y a veces código) para explotarla. No todas aplican a tu uso del paquete, pero actualizar suele ser barato.

**Cómo arreglarlo:**

Actualiza el paquete a una versión corregida (`npm audit fix`, o cambia la versión en `package.json` / `requirements.txt`) y vuelve a correr las pruebas de tu app.

**En tu caso:** actualizar lodash a 4.18.1

Más información: https://github.com/advisories/GHSA-29mw-wpgm-hmr9, https://github.com/advisories/GHSA-35jh-r3h4-6jhm, https://github.com/advisories/GHSA-f23m-r3pf-42rh

### 12. [ALTO] CORS abierto a cualquier origen con credenciales

**Dónde:** `src/servidor.js:14`

**Qué está mal:** CORS acepta cualquier origen y además permite enviar cookies/credenciales

**Por qué es peligroso:** Permite que cualquier página web, incluida una del atacante, haga peticiones a tu API con las cookies de sesión de quien la visite y lea las respuestas. El navegador rechaza `*` junto con credenciales, por eso la 'solución' típica es reflejar el origen (`origin: true`), que abre la puerta del todo.

**Cómo arreglarlo:**

Lista los orígenes permitidos explícitamente:
```js
app.use(cors({ origin: ['https://tu-dominio.com'], credentials: true }));
```
En FastAPI: `allow_origins=["https://tu-dominio.com"]`.

### 13. [ALTO] Cookie de sesión sin HttpOnly o Secure

**Dónde:** `src/servidor.js:19`

**Qué está mal:** La cookie `session` se crea sin HttpOnly ni Secure

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 10.

### 14. [ALTO] Consulta SQL armada pegando texto (inyección SQL)

**Dónde:** `api/app.py:21`

**Qué está mal:** Consulta SQL armada con un f-string

**Por qué es peligroso:** Si alguna parte del texto viene del usuario (URL, formulario, JSON), puede escribir SQL propio: `1 OR 1=1` para ver todos los registros, o peor. Es una de las vulnerabilidades más explotadas que existen.

**Cómo arreglarlo:**

Usa parámetros; la base de datos los trata como datos, nunca como código:
```js
pool.query('SELECT * FROM pedidos WHERE id = $1', [id]);
```
```python
cursor.execute("SELECT * FROM pedidos WHERE id = %s", (id,))
```
Con Prisma, `$queryRaw` con plantilla etiquetada es seguro; `$queryRawUnsafe` no.

**En tu caso:** q llega de la URL. Usa: con.execute("SELECT nombre, precio FROM productos WHERE nombre LIKE ?", (f"%{q}%",))

### 15. [ALTO] Consulta SQL armada pegando texto (inyección SQL)

**Dónde:** `app/api/reportes/route.ts:6`

**Qué está mal:** Consulta SQL armada con una plantilla `${}`

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 14.

**En tu caso:** mes llega de la URL. Usa: db.query('SELECT * FROM ventas WHERE mes = $1', [mes])

### 16. [ALTO] Consulta SQL armada pegando texto (inyección SQL)

**Dónde:** `src/servidor.js:24`

**Qué está mal:** Consulta SQL armada con concatenación (+)

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 14.

**En tu caso:** req.params.id llega de la URL. Usa: pool.query('SELECT * FROM pedidos WHERE id = $1', [req.params.id])

### 17. [ALTO] Ruta de servidor sin verificación de usuario

**Dónde:** `src/servidor.js:23`

**Qué está mal:** GET /api/pedidos/:id devuelve cualquier pedido (con dirección) sin pedir sesión ni comprobar que sea del usuario

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 9.

**En tu caso:** exige sesión y filtra por dueño: WHERE id = $1 AND usuario_id = $2 con req.user.id

### 18. [ALTO] Ruta de servidor sin verificación de usuario

**Dónde:** `app/api/reportes/route.ts:3`

**Qué está mal:** GET /api/reportes devuelve las ventas del mes sin verificar quién llama

**Por qué es peligroso y cómo arreglarlo:** igual que en el hallazgo 9.

**En tu caso:** al inicio: const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response('No autorizado', { status: 401 });

### 19. [ALTO] El monto del cobro lo decide el navegador

**Dónde:** `src/pagos.js:6`

**Qué está mal:** stripe.paymentIntents.create usa req.body.monto tal cual llega

**Por qué es peligroso:** Cualquiera puede llamar a /api/pagos con monto: 100 y pagar 1 peso por un pedido de 100.000. El servidor nunca debe confiar en precios que mande el cliente.

**Cómo arreglarlo:**

Recibe solo el ID del pedido y calcula el monto en el servidor a partir de lo guardado en la base de datos.

## Qué se revisó

| Revisión | Resultado | Hallazgos |
| --- | --- | --- |
| Secretos y claves de API en el código | Revisado | 4 |
| Secretos en el historial de git | Revisado | 1 |
| Archivos .env versionados | Revisado | 1 |
| Supabase: tablas sin RLS y políticas abiertas | Revisado | 1 |
| Firebase: reglas abiertas | Revisado | 1 |
| Rutas y endpoints sin verificación de usuario | Revisado | 3 |
| CORS abierto con credenciales | Revisado | 1 |
| SQL armado concatenando texto | Revisado | 3 |
| Dependencias con vulnerabilidades conocidas | Revisado | 1 |
| Cookies de sesión sin HttpOnly/Secure | Revisado | 2 |
| Otros (revisión de Claude) | Revisado | 1 |

## Descartados

Patrones que parecían un problema pero no lo son, con el motivo:

- Política de Supabase que deja pasar a todos en `supabase/migrations/20250101000000_inicial.sql:7`: perfiles solo tiene id y nombre, que la tienda muestra públicamente, y la política es solo de lectura

## Notas

- Para revisar dependencias se consultó la base de vulnerabilidades del ecosistema con los nombres y versiones de tus paquetes (no con tu código).

## Qué NO revisa esta herramienta

- No ejecuta tu aplicación ni hace pruebas de penetración: revisa el código y la configuración que están en el repositorio.
- No ve lo que configuraste solo en paneles web (Supabase, Firebase, Vercel, AWS) si no está en el repositorio.
- Detecta secretos con patrones de proveedores conocidos y asignaciones obvias; una clave con formato raro puede pasar.
- No cubre toda la lógica de negocio (precios que manda el cliente, flujos de pago, límites de uso, XSS, SSRF, subida de archivos). Claude señala lo que vea, pero no hay garantía de encontrarlo todo.
- Una nota alta no significa que el proyecto sea seguro: significa que no se encontraron estos errores comunes.

## Cómo se calcula la nota

Empieza en 100. Cada hallazgo confirmado resta: crítico 25, alto 15, medio 8, bajo 3. Las dependencias restan como máximo 30 en total. Con al menos un hallazgo crítico la nota no pasa de 40. Niveles: 90-100 Bien, 70-89 Mejorable, 41-69 Riesgoso, 0-40 Crítico.
