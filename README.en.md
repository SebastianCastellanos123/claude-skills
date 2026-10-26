# castellanos-skills

[Español](README.md) · **English**

Claude Code skills written in Spanish, published as a plugin marketplace: one
line to install, updates arrive on their own.

| Plugin | What it does | Status |
| --- | --- | --- |
| [revisor-seguridad](#revisor-seguridad-security-reviewer) | Reviews the security of an AI-built project and produces a report with a 0–100 score | v0.1.0 |

[![CI](https://github.com/SebastianCastellanos123/claude-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/SebastianCastellanos123/claude-skills/actions/workflows/ci.yml)

## Install

You need [Claude Code](https://code.claude.com), Python 3.10+ and git. In a
terminal:

```bash
claude plugin marketplace add SebastianCastellanos123/claude-skills && claude plugin install revisor-seguridad@castellanos-skills
```

Or inside Claude Code:

```text
/plugin marketplace add SebastianCastellanos123/claude-skills
/plugin install revisor-seguridad@castellanos-skills
```

---

## revisor-seguridad (security reviewer)

Built for *vibe-coded* projects (Cursor, Lovable, Bolt, v0, Claude...): the AI
writes code that works, but tends to leave the same doors open. This skill
looks for them and explains each one: **what is wrong, why it is dangerous and
how to fix it**, plus a shareable 0–100 score. **The report is written in
Spanish** (the audience is Latin American developers); Claude can translate it
if you ask.

### Usage

Open Claude Code in your project folder and run:

```text
/revisor-seguridad:revisar
```

or just ask *"review the security of my project"*. A path also works:
`/revisor-seguridad:revisar ../my-app`.

### Demo

Output on the [vulnerable example project](pruebas/revisor-seguridad/ejemplos/vulnerable)
(a fake store with bugs planted on purpose). Full report (Spanish):
[docs/revisor-seguridad/reporte-ejemplo.md](docs/revisor-seguridad/reporte-ejemplo.md).

> **Score: 0/100 · Critical** — 9 critical, 10 high.
>
> **8. [CRITICAL] Supabase table without Row Level Security** —
> `supabase/migrations/20250101000000_inicial.sql:10`
>
> *What's wrong:* table `pedidos` has no `enable row level security`.
> *Why it's dangerous:* Supabase exposes `public` tables through an API used
> with the `anon key`, which ships in your frontend. Without RLS anyone who
> copies it can read, change or delete every row with a single request.
> *How to fix it:* enable RLS and add policies that restrict each row to its
> owner: `alter table public.pedidos enable row level security;` …

The same project done right ([clean example](pruebas/revisor-seguridad/ejemplos/limpio))
scores 100/100 with no false positives, even though it deliberately contains
things that *look* dangerous and are not: a `.env` with real-looking keys that
is in `.gitignore`, the Supabase `anon key` and the Firebase web `apiKey`
(both public by design).

### What it checks

| Check | How |
| --- | --- |
| API keys and credentials in code (Stripe, OpenAI, Anthropic, AWS, GitHub, Supabase `service_role`, database URLs with passwords…) | Script |
| The same keys in **git history** (deleted from the code, not from the repo) | Script |
| `.env` files committed, about to be committed, or present in history | Script |
| Secrets with public prefixes (`NEXT_PUBLIC_`, `VITE_`…) that end up in the browser | Script |
| Supabase tables without RLS and `using (true)` policies | Script + judgment |
| Open Firebase rules, including "test mode" rules | Script |
| Routes/endpoints without user verification, and IDOR | Inventory by script, decision by Claude |
| Open CORS (`*` or reflected origin) with credentials | Script |
| SQL built by string concatenation | Script + judgment |
| Dependencies with known vulnerabilities (`npm audit`, `pnpm audit`, `pip-audit`) | Ecosystem tool |
| Session cookies without `HttpOnly` / `Secure` | Script + judgment |

**Why the split.** Anything a pattern can decide (a Stripe-shaped key, a
committed `.env`, a table without RLS) is done by Python scripts bundled with
the skill: same input, same output, and tested. Anything that needs to
understand the code (does this value glued into SQL come from the user? should
this route require login?) is decided by Claude reading the code, and every
dismissal is recorded in the report with its reason. The score is computed by
a script too, so it doesn't change from run to run.

### What it does NOT check

- It doesn't run your app or do penetration testing: it reads the code and
  configuration in the repository.
- It can't see settings that only live in web dashboards. If you use Supabase
  or Firebase and the tables/rules aren't in the repo, the report marks it
  **not verified** and tells you how to check it in the dashboard.
- Secrets are detected by known provider formats and obvious assignments; an
  unusually formatted key can slip through.
- It doesn't cover all business logic (client-side prices, XSS, SSRF, file
  uploads…). Claude flags what it sees while reading, with no guarantee.
- **A high score doesn't mean the project is secure**, only that it doesn't
  have these common mistakes.

### Privacy

- **Your code never leaves your machine.** The scripts don't use the network
  and the skill forbids Claude from sending code to external services.
- The only network call is the dependency check: `npm audit` and `pip-audit`
  send **package names and versions** (not code) to their registry. Ask for an
  offline review if you don't want even that.
- Secrets are never shown in full (only the first characters and the length),
  and results are written to a temp folder outside your project.
- It doesn't install dependencies or run your project's scripts.

### Scoring

Starts at 100; each confirmed finding subtracts: critical 25, high 15, medium
8, low 3. Dependencies subtract at most 30 in total. With at least one critical
finding the score is capped at 40. Levels: 90–100 Good, 70–89 Needs work,
41–69 Risky, 0–40 Critical. Unconfirmed suspicions and dismissals don't count.

## Development

```bash
python -m unittest discover -s pruebas
python -m unittest discover -s pruebas/revisor-seguridad
```

`python pruebas/revisor-seguridad/construir.py vulnerable` builds an example
project in a temp folder, with fake keys generated on the fly so nothing
key-shaped is stored in this repo. CI runs the tests on Linux and Windows with
read-only permissions. The repository layout is described in the
[Spanish README](README.md#estructura-del-repositorio).

## License

[MIT](LICENSE) · Made by [José Sebastián Castellanos](https://github.com/SebastianCastellanos123).
