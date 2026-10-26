# Criterio para decidir cada tipo de sospecha

Cómo confirmar o descartar los hallazgos con `estado: "revisar"`. Ante la duda
real, confirma y explica la duda en `--nota`: es mejor que el usuario revise un
caso de más que dejar abierta una vulnerabilidad.

## `sql_concatenado`

Sigue el valor que se pega al SQL hasta su origen.

- **Confirmar** si viene, aunque sea indirectamente, de la petición (`req.params`,
  `req.query`, `req.body`, `searchParams`, argumentos de un endpoint de FastAPI o
  Flask, un formulario, un mensaje de un bot) o de la base de datos con datos
  que escribieron usuarios.
- **Descartar** solo si es una constante del código o un valor de una lista
  cerrada validada justo antes (por ejemplo, el nombre de columna para ordenar
  se elige de `['fecha', 'precio']`). Pon esa razón en `--motivo`.
- Un ORM no salva si se usa la vía "raw" con texto armado: `$queryRawUnsafe`,
  `sequelize.query` con plantilla, `knex.raw` con `${}`, `.extra()`/`.raw()` de
  Django con f-string.
- `--arreglo`: muestra la misma consulta con parámetros en el estilo de la
  librería que usa el proyecto (`$1` en pg, `?` en mysql2/sqlite, `%s` en
  psycopg, `:nombre` en SQLAlchemy).

## `politica_abierta` (Supabase)

- **Descartar** si la tabla es realmente pública y la política es solo de
  lectura (`for select`): catálogo de productos, publicaciones públicas. Revisa
  las columnas: si la tabla pública tiene emails, teléfonos o direcciones,
  confirma (se pueden leer todos con la anon key).
- **Confirmar** siempre que `true` esté en `insert`, `update`, `delete` o `all`.

## `secreto` con estado "revisar" (asignaciones genéricas, JWT, claves de Google)

- **Descartar** si el valor es claramente de mentira (pruebas, documentación,
  fixtures con nombres como `test`, `ejemplo`), si es un identificador público
  (ID de cliente OAuth, ID de proyecto) o si es la `anon key`/clave publicable.
- **Confirmar** si parece una credencial real, aunque esté en un archivo de
  pruebas: los repositorios se publican completos.
- Clave de Google `AIza...` fuera de una configuración de Firebase: confirma
  como `media` y aconseja restringirla en Google Cloud (por dominio y por API);
  si se usa desde el servidor para Gemini, Maps u otra API de pago, sube a `alta`.

## `cookie_insegura` con estado "revisar" (`secure: false`)

- **Descartar** si solo aplica en desarrollo (`secure: process.env.NODE_ENV ===
  'production'` o un archivo de configuración solo de desarrollo).
- **Confirmar** si esa configuración es la que se usa en producción.
- Si ves que el token de sesión se guarda en `localStorage`, agrégalo como
  `manual` (`media`): cualquier XSS lo puede leer, igual que una cookie sin HttpOnly.

## `env_sin_ignorar` en proyectos sin git

Confirma si no hay `.gitignore` que excluya `.env`; descártalo si el usuario no
usa git ni piensa subir el proyecto (pregúntale si no está claro).

## Hallazgos confirmados que podrían ser falsos positivos

Los patrones confirmados casi siempre son reales. Excepciones típicas:

- La clave está en un archivo de pruebas o documentación y es de mentira.
- El `.env` versionado solo tiene valores de ejemplo (aun así recomienda
  renombrarlo a `.env.example`; baja la severidad a `baja` con motivo).
- El "CORS abierto" está en un ejemplo o en código que no se despliega.

## Rutas: señales de que una ruta sí está protegida

- Express/Fastify: un middleware en la ruta o en `app.use` antes de ella que
  responde 401/403 si no hay usuario (no basta con que lo lea: debe cortar).
- Next.js: `middleware.ts` con `matcher` que cubre la ruta, o
  `getServerSession`/`auth()`/`supabase.auth.getUser()` al inicio del handler
  con un `return` si no hay usuario. Las server actions (`'use server'`) son
  endpoints públicos: también necesitan esa verificación.
- FastAPI: `Depends(...)` que lanza `HTTPException(401)`. Flask:
  `@login_required` o una verificación explícita.
- Supabase Edge Functions: verificación del JWT del encabezado
  `Authorization` (`supabase.auth.getUser(token)`), salvo que se desplieguen con
  verificación de JWT activada (`verify_jwt`, por defecto true; revisa
  `supabase/config.toml`).

Una ruta que usa el cliente de Supabase con la anon key y el token del usuario
queda protegida por RLS; una que usa la service key no, y entonces debe
verificar al usuario ella misma.
