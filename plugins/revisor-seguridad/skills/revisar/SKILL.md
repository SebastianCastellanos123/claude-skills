---
name: revisar
description: Revisa la seguridad de un proyecto hecho con IA (vibe coding) y entrega un reporte en español con cada problema (qué está mal, por qué es peligroso, cómo arreglarlo) y una nota de 0 a 100 para compartir. Detecta claves de API en el código o en el historial de git, archivos .env subidos, tablas de Supabase sin RLS, reglas de Firebase abiertas, rutas sin verificación de usuario, CORS abierto con credenciales, SQL concatenado, dependencias vulnerables y cookies de sesión sin HttpOnly/Secure. Úsala cuando el usuario pida revisar la seguridad de su app, proyecto o repositorio, pregunte si su código es seguro, vaya a publicar o hacer deploy, o mencione claves filtradas, RLS de Supabase o reglas de Firebase. También para "security review", "audit my app", "is my vibe-coded app safe".
argument-hint: "[ruta-del-proyecto]"
allowed-tools: Read Grep Glob Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/*) Bash(python ${CLAUDE_SKILL_DIR}/scripts/*)
---

# Revisor de seguridad para proyectos hechos con IA

Revisas el proyecto del usuario y le entregas un reporte en español, claro para
alguien que quizá no es experto en seguridad. Lo mecánico lo hacen scripts
deterministas; tú pones el criterio: confirmar o descartar sospechas leyendo el
código y revisar lo que un patrón no puede decidir (sobre todo las rutas).

## Reglas que no se rompen

- **No envíes el código del usuario a ningún servicio externo.** Nada de
  WebFetch, WebSearch ni pegar código en URLs. La única consulta a internet es la
  de dependencias que hace `escanear.py` (manda nombres y versiones de paquetes a
  npm/PyPI, no código); si el usuario pide no usar internet, agrega `--sin-red`.
- **No ejecutes el proyecto** ni instales sus dependencias (`npm install`,
  `pip install`, scripts de `package.json`): pueden correr código arbitrario.
- **Nunca muestres un secreto completo.** Los scripts ya los enmascaran; si lees
  el archivo, cita solo el nombre de la variable o los primeros caracteres.
- **No modifiques el proyecto durante la revisión.** Al final ofrece arreglar lo
  que encontraste; hazlo solo si el usuario dice que sí.
- **Sé honesto con el alcance.** No digas que el proyecto "es seguro". Di qué se
  revisó y qué no (el reporte ya incluye la sección "Qué NO revisa").
- No descartes una sospecha sin haber leído el código que la rodea.

## Paso 1: escanear

Usa `python3`; si no existe (o en Windows abre la Microsoft Store), usa `python`.
La ruta del proyecto es `$ARGUMENTS` o, si viene vacío, el directorio actual.

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/escanear.py RUTA_DEL_PROYECTO
```

El script imprime dónde guardó el JSON (una carpeta temporal fuera del proyecto,
para no dejar archivos con hallazgos en el repositorio). Lee ese JSON. Tiene:

- `hallazgos`: cada uno con `id`, `tipo`, `severidad`, `estado`, `archivo`,
  `linea`, `evidencia` (enmascarada) y `detalle`.
  - `estado: "confirmado"`: el patrón ya es un problema por sí solo.
  - `estado: "revisar"`: sospecha; tú decides (paso 2).
- `rutas`: inventario de endpoints con `senales_auth` (si se ve algo de
  autenticación cerca) y `publica_probable` (login, health, webhook...).
- `verificaciones`: qué se revisó, qué no aplica y qué no se pudo verificar.
- `notas`: observaciones que no son hallazgos.

## Paso 2: decidir las sospechas

Para cada hallazgo con `estado: "revisar"`, abre el archivo en esa línea, lee lo
necesario (la función completa, de dónde vienen las variables) y decide con
`decidir.py`. Criterio por tipo en [referencias/criterio.md](referencias/criterio.md).

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/decidir.py RUTA_JSON confirmar H14 --arreglo "pasa req.params.id como parámetro de pool.query en vez de concatenarlo"
python3 ${CLAUDE_SKILL_DIR}/scripts/decidir.py RUTA_JSON descartar H17 --motivo "es el catálogo público de productos; solo lectura"
```

Puedes ajustar la severidad al confirmar (`--severidad media --motivo "..."`)
cuando el contexto lo justifique, explicando por qué. Revisa también por encima
los confirmados: si uno es claramente un falso positivo (por ejemplo, una clave
de un archivo de pruebas que es de mentira), descártalo con su motivo.

En `--arreglo` pon el cambio concreto para ESE código (no repitas la
explicación general, que el reporte ya trae).

## Paso 3: revisar las rutas

Esto no lo puede decidir un patrón. Para cada ruta del inventario:

1. Lee el handler completo y los middlewares que se le aplican (también los
   globales, como `app.use(...)` o un `middleware.ts` de Next.js).
2. Pregúntate: ¿lee o cambia datos que no son públicos? Si sí, ¿verifica quién
   llama antes de hacerlo?
3. Si recibe un ID (`/pedidos/:id`), ¿comprueba que el recurso sea del usuario
   de la sesión? Si no, es un IDOR (`acceso_sin_dueno`).
4. `senales_auth: true` solo significa que apareció una palabra como `auth` o
   `session`; confirma que de verdad bloquea a quien no tiene sesión.
5. Los webhooks son públicos, pero deben verificar la firma del proveedor
   (Stripe, GitHub...). Si no lo hacen, repórtalo como `manual`.

Registra cada problema:

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/decidir.py RUTA_JSON agregar --tipo ruta_sin_auth --severidad alta \
  --archivo src/servidor.js --linea 28 --detalle "GET /api/admin/usuarios devuelve emails y teléfonos sin verificar sesión" \
  --arreglo "agrega el middleware requireAuth y comprueba req.user.rol === 'admin'"
python3 ${CLAUDE_SKILL_DIR}/scripts/decidir.py RUTA_JSON rutas-revisadas --detalle "9 rutas revisadas; 3 sin verificación"
```

Severidad orientativa: datos personales o acciones de administración sin login
→ `critica`; datos privados de un usuario o escrituras → `alta`; información
poco sensible → `media`.

## Paso 4: lo que veas de paso

Mientras lees el código, si ves algo grave fuera de las categorías (el precio lo
manda el navegador, se sube cualquier archivo sin validar, `dangerouslySetInnerHTML`
con datos del usuario, la service key usada en un componente de cliente,
contraseñas guardadas sin hash...), agrégalo con `--tipo manual --titulo ...
--por-que ... --como ...`. No busques exhaustivamente fuera del alcance: es un
extra, y el reporte deja claro que no hay garantía de encontrarlo todo.

Para lo que salga como `no_verificado` (por ejemplo, Supabase sin migraciones en
el repositorio), no inventes resultados: el reporte ya le dice al usuario cómo
revisarlo él mismo en el panel.

## Paso 5: generar y entregar el reporte

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/reporte.py RUTA_JSON
```

La nota la calcula el script con reglas fijas; no la cambies a mano ni la
redondees. Si el script avisa que quedan hallazgos sin confirmar o rutas sin
revisar, vuelve al paso 2 o 3.

Entrega al usuario, en este orden:

1. La nota y el nivel, en una línea.
2. Los 3 problemas más urgentes, en una frase cada uno, empezando por lo que
   debe hacer YA (normalmente: rotar claves expuestas).
3. El reporte completo (lee el `.md` generado y muéstralo) y la ruta del archivo.
4. Ofrece guardar una copia en el proyecto y avisa que no la suba a un
   repositorio público hasta arreglar los problemas, porque describe cómo
   atacarlo. La sección "Para compartir" sí se puede publicar.
5. Ofrece arreglar los problemas, empezando por los críticos.
