# routeproof

Nginx `location` precedence and Next.js `middleware.ts` negative lookahead matchers are a common source of accidental auth bypasses. Instead of fuzzing or guessing paths, `routeproof` compiles route and matcher rules into deterministic finite automata (DFA) and uses set intersection/difference with BFS to synthesize the shortest concrete URL that triggers a bypass.

Written in pure Go with zero external dependencies.

## How It Works

### Nginx (`routeproof nginx`)

For each `server` block, `routeproof` compiles every `location` rule (`=`, `^~`, prefix, `~`, `~*`) into a minimal DFA and computes each block's exact effective URL domain:

1. Exact matches (`=`) take highest priority.
2. Longest prefix match across `^~` and plain prefix locations (excluding exact matches).
3. If the winning longest prefix uses `^~`, regex evaluation is skipped.
4. Regex locations (`~` and `~*`) are evaluated in declaration order.
5. Plain prefix locations win only when no regex matches.

For each protected rule `P` and each unprotected, externally reachable, non-blocking location `U`, `routeproof` computes `Intended(P) ∩ Effective(U)` and uses BFS to find the shortest readable witness URL (for example `/admin/a.json`). It also checks prefix `location` blocks where `alias` ends with `/` while the `location` prefix does not (off-by-slash traversal such as `/static../`), verified against the location's effective DFA.

### Next.js (`routeproof nextjs`)

For a Next.js project directory, `routeproof` discovers App Router (`app/`, `src/app/`) and Pages Router (`pages/`, `src/pages/`) routes, parses `config.matcher` from `middleware.{ts,js}` (or `src/middleware.{ts,js}`), and computes `RouteDFA \ MiddlewareCoverageDFA` for every route. When a gap exists, BFS synthesizes the shortest concrete URL that reaches the route without triggering the middleware.

## Installation

Requires Go 1.22+ (stdlib only):

```bash
go build ./cmd/routeproof
```

## Quick Start (Examples)

The repository includes two minimal vulnerable fixtures under `examples/`:

```bash
# Nginx: regex overrides auth_basic prefix + alias off-by-slash traversal
go run ./cmd/routeproof nginx examples/nginx-vuln.conf

# Next.js: negative lookahead matcher leaves /api/internal and dotted /api/admin/[file] paths uncovered
go run ./cmd/routeproof nextjs examples/nextjs-demo
```

## Usage

```bash
# Scan an nginx.conf file
routeproof nginx /etc/nginx/nginx.conf

# Treat extra URL prefixes as protected (repeatable)
routeproof nginx --protected /admin --protected /internal nginx.conf

# Scan a Next.js project directory
routeproof nextjs ./my-nextjs-app

# Scan Next.js with explicit protected prefixes and JSON output
routeproof nextjs --protected /admin --protected /api/internal --json ./my-nextjs-app

# Fail CI when findings are present (exit 1 on findings, 2 on usage/parse/IO errors)
routeproof nginx --fail-on-finding nginx.conf
routeproof nextjs --fail-on-finding ./my-nextjs-app

# Override DFA state limit (default: 50000)
routeproof nginx --max-states 25000 nginx.conf

# Print version
routeproof --version
```

### Example Output (Nginx)

```text
Target: examples/nginx-vuln.conf
[HIGH] AUTH_BYPASS (server app.example.com, line 1)
  Witness:   /admin/a.json
  Protected: location /admin/ (line 5, auth_basic)
  Winning:   location ~* /[^/]+\.json$ (line 11)
  Reason:    regex overrides prefix (missing ^~ modifier)

[HIGH] ALIAS_TRAVERSAL (server app.example.com, line 1)
  Witness:   /static../
  Protected: location /static (line 16, alias /var/www/static/)
  Winning:   location /static (line 15)
  Reason:    alias ends with '/' while location prefix lacks trailing '/'

Summary: 2 finding(s) (2 high, 0 medium), 0 warning(s)
```

### Example Output (Next.js)

```text
Target: examples/nextjs-demo
Middleware: middleware.ts (auth signals: NextResponse.redirect, cookies, redirect)
[HIGH] MIDDLEWARE_COVERAGE_GAP
  Witness: /api/admin/a.
  Route:   /api/admin/[file] (app-route, app/api/admin/[file]/route.ts)
  Reason:  route partially escapes middleware matcher coverage

[HIGH] MIDDLEWARE_COVERAGE_GAP
  Witness: /api/internal
  Route:   /api/internal (app-route, app/api/internal/route.ts)
  Reason:  route is not covered by middleware matcher

Summary: 2 finding(s) (2 high, 0 medium, 0 low), 0 warning(s) across 3 route(s)
```

## Exit Codes

- `0`: Analysis completed (no findings, or `--fail-on-finding` was not set). Warnings alone (`UNSUPPORTED` / `STATE_LIMIT` / `INVALID`) exit `0` even when `--fail-on-finding` is enabled.
- `1`: One or more findings (`findings > 0`) were detected with `--fail-on-finding`.
- `2`: Invalid CLI usage, file I/O error, missing Next.js middleware file, or configuration parse error.

## Limitations

- **Nginx auth scope:** Only locations with explicit Nginx access control (`auth_request`, `auth_basic`, or `deny all`) or matching `--protected` are treated as protected. Configs that delegate auth to upstream backends report zero findings unless `--protected` is passed. Explicit `auth_request off;` or `auth_basic off;` overrides are reported as `MEDIUM`.
- **Nginx dynamic directives:** `if`, `rewrite`, `map`, `include`, `limit_except`, and nested `location` blocks are not modeled and emit `UNSUPPORTED` warnings with line numbers.
- **Next.js dynamic and conditional matchers:** Dynamic `config.matcher` expressions (variables, function calls, spreads, template interpolations) and conditional `has`/`missing` matchers emit `UNSUPPORTED` warnings. When `config.matcher` contains dynamic or unmodeled entries, coverage-gap findings are suppressed to avoid false positives.
- **Next.js severity:** `MIDDLEWARE_COVERAGE_GAP` severity is based on detected middleware auth signals (`cookies`, `session`, `authorization`, `getToken`, `401`/`403`, `NextResponse.redirect`), route kind/path, and `--protected`. Middleware without auth signals or `--protected` matches is reported as `LOW`.
- **Regex subset:** Supports Go `regexp/syntax` (`Perl`) plus single-level negative lookahead `(?!R)S`. Backreferences, lookbehind, positive lookahead, `\b`, and nested/quantified lookaheads emit `UNSUPPORTED` warnings.
- **Alphabet:** URL paths are modeled over printable non-whitespace ASCII (`0x21..0x7E`). Patterns or route segments outside this range emit `UNSUPPORTED` warnings.

## License

MIT - see [LICENSE](LICENSE).
