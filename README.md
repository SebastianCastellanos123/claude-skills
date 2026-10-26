# castellanos-skills

**Español** · [English](README.en.md)

Skills de Claude Code en español, publicadas como un marketplace de plugins:
se instalan con una línea y se actualizan solas.

| Plugin | Qué hace | Estado |
| --- | --- | --- |
| [revisor-seguridad](#revisor-seguridad) | Revisa la seguridad de un proyecto hecho con IA y entrega un reporte con nota de 0 a 100 | v0.1.0 |

[![CI](https://github.com/SebastianCastellanos123/claude-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/SebastianCastellanos123/claude-skills/actions/workflows/ci.yml)

## Instalación

Necesitas [Claude Code](https://code.claude.com), Python 3.10 o superior y git.
En una terminal:

```bash
claude plugin marketplace add SebastianCastellanos123/claude-skills && claude plugin install revisor-seguridad@castellanos-skills
```

O dentro de Claude Code:

```text
/plugin marketplace add SebastianCastellanos123/claude-skills
/plugin install revisor-seguridad@castellanos-skills
```

---

## revisor-seguridad

Pensado para proyectos hechos con *vibe coding* (Cursor, Lovable, Bolt, v0,
Claude...): la IA escribe código que funciona, pero suele dejar las mismas
puertas abiertas. Esta skill las busca y te explica cada una en español: **qué
está mal, por qué es peligroso y cómo arreglarlo**, con una nota de 0 a 100 que
puedes compartir.

### Uso

Abre Claude Code en la carpeta de tu proyecto y escribe:

```text
/revisor-seguridad:revisar
```

o simplemente *"revisa la seguridad de mi proyecto"*. También acepta una ruta:
`/revisor-seguridad:revisar ../mi-app`.

### Demo

Resultado sobre el [proyecto de ejemplo vulnerable](pruebas/revisor-seguridad/ejemplos/vulnerable)
(una tienda con errores plantados a propósito). Reporte completo:
[docs/revisor-seguridad/reporte-ejemplo.md](docs/revisor-seguridad/reporte-ejemplo.md).

> ## Nota: 0/100 · Crítico
>
> Críticos: 9 · Altos: 10 · Medios: 0 · Bajos: 0
>
> ### 8. [CRÍTICO] Tabla de Supabase sin Row Level Security
>
> **Dónde:** `supabase/migrations/20250101000000_inicial.sql:10`
>
> **Qué está mal:** La tabla `pedidos` no tiene `enable row level security`
>
> **Por qué es peligroso:** Supabase publica las tablas de `public` en una API
> que se usa con la `anon key`, y esa clave está en tu frontend. Sin RLS,
> cualquiera que la copie puede leer, modificar o borrar TODAS las filas de esa
> tabla con una sola petición.
>
> **Cómo arreglarlo:** Activa RLS y crea políticas que limiten cada fila a su
> dueño: `alter table public.pedidos enable row level security;` …

El mismo proyecto hecho bien ([ejemplo limpio](pruebas/revisor-seguridad/ejemplos/limpio))
saca 100/100 sin falsos positivos, aunque tiene a propósito cosas que *parecen*
peligrosas y no lo son: un `.env` con claves que sí está en `.gitignore`, la
`anon key` de Supabase y la `apiKey` de Firebase (ambas públicas por diseño).

### Qué revisa

| Revisión | Cómo |
| --- | --- |
| Claves de API y credenciales en el código (Stripe, OpenAI, Anthropic, AWS, GitHub, Supabase `service_role`, URLs de base de datos con contraseña…) | Script |
| Las mismas claves en el **historial de git** (borradas del código pero no del repositorio) | Script |
| Archivos `.env` subidos a git, a punto de subirse o que estuvieron en el historial | Script |
| Secretos con prefijo público (`NEXT_PUBLIC_`, `VITE_`…) que terminan en el navegador | Script |
| Tablas de Supabase sin RLS y políticas `using (true)` | Script + criterio |
| Reglas de Firebase abiertas, incluidas las de "modo de prueba" | Script |
| Rutas y endpoints sin verificación de usuario, y acceso a datos de otros cambiando un ID (IDOR) | Inventario por script, decisión de Claude |
| CORS abierto (`*` u origen reflejado) con credenciales | Script |
| SQL armado concatenando texto | Script + criterio |
| Dependencias con vulnerabilidades conocidas (`npm audit`, `pnpm audit`, `pip-audit`) | Herramienta del ecosistema |
| Cookies de sesión sin `HttpOnly` / `Secure` | Script + criterio |

**Por qué esta división.** Lo que se puede decidir con un patrón (una clave
con formato de Stripe, un `.env` versionado, una tabla sin `enable row level
security`) lo hacen scripts en Python incluidos en la skill: dan siempre el
mismo resultado y se pueden probar. Lo que necesita entender el código (¿este
valor que se pega al SQL viene del usuario?, ¿esta ruta debería pedir login?)
lo decide Claude leyendo el código, y cada descarte queda en el reporte con su
motivo. La nota también la calcula un script, para que no dependa del día.

### Qué NO revisa

- No ejecuta tu aplicación ni hace pruebas de penetración: lee el código y la
  configuración del repositorio.
- No ve lo que configuraste solo en paneles web. Si usas Supabase o Firebase
  y las tablas o reglas no están en el repositorio, el reporte lo marca como
  **no verificado** y te dice cómo revisarlo en el panel.
- Los secretos se detectan por patrones de proveedores conocidos y
  asignaciones obvias; una clave con formato raro puede pasar.
- No cubre toda la lógica de negocio (precios que manda el cliente, XSS, SSRF,
  subida de archivos…). Claude señala lo que vea al leer, sin garantía de
  encontrarlo todo.
- **Una nota alta no significa que el proyecto sea seguro**, sino que no tiene
  estos errores comunes.

### Privacidad

- **Tu código no sale de tu computador.** Los scripts no usan internet y la
  skill le prohíbe a Claude mandar código a servicios externos.
- La única consulta a internet es la de dependencias: `npm audit` y
  `pip-audit` envían a su registro **los nombres y versiones de tus paquetes**
  (no tu código). Si no quieres ni eso, pide la revisión "sin red".
- Los secretos nunca se muestran completos (solo los primeros caracteres y el
  largo), y los resultados se guardan en una carpeta temporal fuera de tu
  proyecto.
- No instala dependencias ni ejecuta scripts de tu proyecto.

### Cómo se calcula la nota

Empieza en 100 y cada hallazgo confirmado resta: crítico 25, alto 15, medio 8,
bajo 3. Las dependencias restan como máximo 30 en total (suelen venir en grupo
y se arreglan con una actualización). Con al menos un crítico, la nota no pasa
de 40. Niveles: 90-100 Bien, 70-89 Mejorable, 41-69 Riesgoso, 0-40 Crítico.
Las sospechas que nadie confirmó y los descartes no restan.

---

## Estructura del repositorio

```text
.claude-plugin/marketplace.json    lista de plugins del marketplace
plugins/<plugin>/
  .claude-plugin/plugin.json       nombre, versión, autor
  skills/<skill>/SKILL.md          instrucciones para Claude (frontmatter name + description)
  skills/<skill>/scripts/          scripts deterministas (solo librería estándar)
pruebas/                           pruebas automáticas y proyectos de ejemplo
docs/                              reportes de ejemplo
```

Para agregar una skill nueva: crea `plugins/<nombre>/` con su `plugin.json` y
su `skills/<skill>/SKILL.md`, y agrégala a `marketplace.json`. La prueba
`pruebas/test_estructura.py` verifica que todo coincida.

## Desarrollo

```bash
python -m unittest discover -s pruebas
python -m unittest discover -s pruebas/revisor-seguridad
```

Para probar a mano sobre un ejemplo:

```bash
python pruebas/revisor-seguridad/construir.py vulnerable
```

Ese comando arma el proyecto en una carpeta temporal (con claves falsas
generadas en el momento, para no guardar nada con formato de clave real en el
repositorio) e imprime dónde quedó. Luego, desde la raíz de este repositorio:

```bash
python plugins/revisor-seguridad/skills/revisar/scripts/escanear.py RUTA_IMPRESA
```

La CI corre las pruebas en Linux y Windows, con permisos de solo lectura.

## Licencia

[MIT](LICENSE) · Hecho por [José Sebastián Castellanos](https://github.com/SebastianCastellanos123).
