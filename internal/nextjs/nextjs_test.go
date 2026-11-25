package nextjs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"routeproof/internal/automata"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

func TestDiscoverAppRouterRoutes(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"app/page.tsx":                             "export default function Home() {}",
		"app/layout.tsx":                           "export default function Layout() {}",
		"app/(auth)/login/page.tsx":                "export default function Login() {}",
		"app/(dashboard)/(admin)/settings/page.js": "export default function Settings() {}",
		"app/users/[id]/page.tsx":                  "export default function User() {}",
		"app/docs/[...slug]/page.mdx":              "# Docs",
		"app/shop/[[...slug]]/page.tsx":            "export default function Shop() {}",
		"app/api/admin/route.ts":                   "export async function GET() {}",
		"app/admin/@analytics/visitors/page.tsx":   "export default function Visitors() {}",
		"app/components/Page.tsx":                  "export function Page() {}",
		"app/components/Route.ts":                  "export const Route = 1;",
		"app/_private/secret/page.tsx":             "export default function Private() {}",
		"app/_components/button.tsx":               "export function Button() {}",
		"app/types.d.ts":                           "export type X = string;",
	})

	routes, warnings, err := DiscoverRoutes(dir, automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("DiscoverRoutes error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	byPattern := make(map[string]Route, len(routes))
	for _, r := range routes {
		byPattern[r.Pattern] = r
	}

	wantRoutes := []struct {
		pattern string
		kind    RouteKind
		accept  []string
		reject  []string
	}{
		{"/", RouteAppPage, []string{"/"}, []string{"/a"}},
		{"/login", RouteAppPage, []string{"/login"}, []string{"/(auth)/login", "/login/"}},
		{"/settings", RouteAppPage, []string{"/settings"}, []string{"/(admin)/settings"}},
		{"/users/[id]", RouteAppPage, []string{"/users/alice", "/users/42", "/users/.env", "/users/a."}, []string{"/users", "/users/alice/edit", "/users/.", "/users/..", "/users//a", "/users/?", "/users/#", "/users/a?b", "/users/a#b"}},
		{"/docs/[...slug]", RouteAppPage, []string{"/docs/a", "/docs/a/b/c", "/docs/.env/a"}, []string{"/docs", "/docs/.", "/docs/..", "/docs/a//b", "/docs/a/..", "/docs/?q=1", "/docs/#top"}},
		{"/shop/[[...slug]]", RouteAppPage, []string{"/shop", "/shop/a", "/shop/a/b", "/shop/a."}, []string{"/shopping", "/shop/.", "/shop/..", "/shop//a", "/shop/?a=1", "/shop/#x"}},
		{"/api/admin", RouteAppRoute, []string{"/api/admin"}, []string{"/api/admin/"}},
		{"/admin/visitors", RouteAppPage, []string{"/admin/visitors"}, []string{"/admin/@analytics/visitors"}},
	}

	if len(routes) != len(wantRoutes) {
		t.Fatalf("got %d routes, want %d: %+v", len(routes), len(wantRoutes), routes)
	}

	for _, tc := range wantRoutes {
		r, ok := byPattern[tc.pattern]
		if !ok {
			t.Errorf("missing route %q", tc.pattern)
			continue
		}
		if r.Kind != tc.kind {
			t.Errorf("route %q kind = %q, want %q", tc.pattern, r.Kind, tc.kind)
		}
		for _, s := range tc.accept {
			if !r.DFA.Accepts(s) {
				t.Errorf("route %q (%s) rejected %q", tc.pattern, r.Regex, s)
			}
		}
		for _, s := range tc.reject {
			if r.DFA.Accepts(s) {
				t.Errorf("route %q (%s) accepted %q", tc.pattern, r.Regex, s)
			}
		}
	}
}

func TestDiscoverRootOptionalCatchAll(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"src/app/[[...slug]]/page.tsx": "export default function CatchAll() {}",
	})
	routes, _, err := DiscoverRoutes(dir, automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("DiscoverRoutes error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	for _, s := range []string{"/", "/a", "/a/b/c", "/.env"} {
		if !routes[0].DFA.Accepts(s) {
			t.Errorf("root [[...slug]] rejected %q", s)
		}
	}
	for _, s := range []string{"/.", "/..", "//", "/a//b", "/a/.."} {
		if routes[0].DFA.Accepts(s) {
			t.Errorf("root [[...slug]] accepted invalid normalized path %q", s)
		}
	}
}

func TestDiscoverPagesRouterAndHybrid(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"src/app/dashboard/page.tsx":         "export default function Dash() {}",
		"src/pages/index.tsx":                "export default function Index() {}",
		"src/pages/_app.tsx":                 "export default function App() {}",
		"src/pages/_document.tsx":            "export default function Doc() {}",
		"src/pages/_error.tsx":               "export default function Err() {}",
		"src/pages/404.tsx":                  "export default function NotFound() {}",
		"src/pages/500.tsx":                  "export default function ServerErr() {}",
		"src/pages/admin/index.tsx":          "export default function Admin() {}",
		"src/pages/users/[id].tsx":          "export default function User() {}",
		"src/pages/api.tsx":                 "export default function ApiDocsPage() {}",
		"src/pages/api/secret/[...path].ts": "export default function handler() {}",
		"src/pages/api/health.ts":           "export default function health() {}",
	})

	routes, warnings, err := DiscoverRoutes(dir, automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("DiscoverRoutes error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", warnings)
	}

	wantKinds := map[string]RouteKind{
		"/":                     RoutePagesPage,
		"/admin":                RoutePagesPage,
		"/api":                  RoutePagesPage,
		"/dashboard":            RouteAppPage,
		"/users/[id]":           RoutePagesPage,
		"/api/health":           RoutePagesAPI,
		"/api/secret/[...path]": RoutePagesAPI,
	}

	if len(routes) != len(wantKinds) {
		t.Fatalf("got %d routes, want %d: %+v", len(routes), len(wantKinds), routes)
	}
	for _, r := range routes {
		want, ok := wantKinds[r.Pattern]
		if !ok {
			t.Errorf("unexpected route %q (%s)", r.Pattern, r.File)
			continue
		}
		if r.Kind != want {
			t.Errorf("route %q kind = %q, want %q", r.Pattern, r.Kind, want)
		}
	}
}

func TestMatcherToRegexAndDFA(t *testing.T) {
	tests := []struct {
		name    string
		matcher string
		accept  []string
		reject  []string
	}{
		{
			name:    "official nextjs negative lookahead matcher",
			matcher: `/((?!_next/static|_next/image|favicon.ico|.*\..*).*)`,
			accept:  []string{"/", "/users/alice", "/admin", "/admin/settings"},
			reject:  []string{"/_next/static/chunk.js", "/_next/image/logo.png", "/favicon.ico", "/admin/secret.json", "/users/a.b/settings"},
		},
		{
			name:    "zero-or-more catch-all :path*",
			matcher: `/admin/:path*`,
			accept:  []string{"/admin", "/admin/", "/admin/users", "/admin/a/b/c"},
			reject:  []string{"/administrator", "/admin2", "/public"},
		},
		{
			name:    "root :path*",
			matcher: `/:path*`,
			accept:  []string{"/", "/admin", "/a/b"},
			reject:  []string{""},
		},
		{
			name:    "one-or-more catch-all :path+",
			matcher: `/admin/:path+`,
			accept:  []string{"/admin/a", "/admin/a/b"},
			reject:  []string{"/admin", "/admin/", "/administrator"},
		},
		{
			name:    "single segment :id",
			matcher: `/admin/:id`,
			accept:  []string{"/admin/42", "/admin/alice"},
			reject:  []string{"/admin", "/admin/", "/admin/42/edit"},
		},
		{
			name:    "optional single segment :id?",
			matcher: `/admin/:id?`,
			accept:  []string{"/admin", "/admin/42"},
			reject:  []string{"/admin/42/edit", "/administrator"},
		},
		{
			name:    "custom regex segment :id(\\d+)",
			matcher: `/users/:id(\d+)`,
			accept:  []string{"/users/123", "/users/0"},
			reject:  []string{"/users/abc", "/users/", "/users/123/456"},
		},
		{
			name:    "literal dot escaped outside group",
			matcher: `/api/v1.0/:path*`,
			accept:  []string{"/api/v1.0", "/api/v1.0/users"},
			reject:  []string{"/api/v1X0/users"},
		},
		{
			name:    "root optional locale param followed by prefix",
			matcher: `/:locale(en|fr)?/admin/:path*`,
			accept:  []string{"/admin", "/admin/users", "/en/admin", "/fr/admin/settings"},
			reject:  []string{"/de/admin", "/en", "//admin", "/administrator"},
		},
		{
			name:    "slash-prefixed optional anonymous group at end",
			matcher: `/admin/(settings)?`,
			accept:  []string{"/admin", "/admin/settings"},
			reject:  []string{"/admin/", "/adminsettings", "/admin/other"},
		},
		{
			name:    "slash-prefixed optional anonymous group at start",
			matcher: `/(en|fr)?/admin`,
			accept:  []string{"/admin", "/en/admin", "/fr/admin"},
			reject:  []string{"/de/admin", "//admin", "/en"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reStr, err := MatcherToRegex(tc.matcher)
			if err != nil {
				t.Fatalf("MatcherToRegex(%q) error: %v", tc.matcher, err)
			}
			d, err := automata.Compile(reStr, automata.CompileOptions{Anchored: true})
			if err != nil {
				t.Fatalf("Compile(%q) error: %v", reStr, err)
			}
			for _, s := range tc.accept {
				if !d.Accepts(s) {
					t.Errorf("matcher %q (regex %q) rejected %q", tc.matcher, reStr, s)
				}
			}
			for _, s := range tc.reject {
				if d.Accepts(s) {
					t.Errorf("matcher %q (regex %q) accepted %q", tc.matcher, reStr, s)
				}
			}
		})
	}
}

func TestParseMiddlewareConfigForms(t *testing.T) {
	t.Run("official negative lookahead string in TS source", func(t *testing.T) {
		src := `
import { NextResponse } from 'next/server';
import type { NextRequest, MiddlewareConfig } from 'next/server';

// export const config = { matcher: '/ignored-comment' }
/* export const config = { matcher: '/ignored-block' } */

export function middleware(req: NextRequest) {
  const token = req.cookies.get('session');
  if (!token) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

export const config: MiddlewareConfig = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\..*).*)'],
};
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if !mw.HasExplicitMatcher {
			t.Fatalf("HasExplicitMatcher = false, want true")
		}
		if len(mw.Matchers) != 1 || mw.Matchers[0].Unmodeled {
			t.Fatalf("unexpected matchers: %+v (warnings: %+v)", mw.Matchers, mw.Warnings)
		}
		if !mw.Coverage.Accepts("/users/alice") || mw.Coverage.Accepts("/_next/static/chunk.js") || mw.Coverage.Accepts("/admin/a.json") {
			t.Errorf("unexpected Coverage membership for official Next.js lookahead matcher")
		}
		if !mw.HasAuthSignal {
			t.Errorf("expected HasAuthSignal = true")
		}
	})

	t.Run("single string matcher with as const", func(t *testing.T) {
		src := `
export function middleware() {}
export const config = {
  matcher: '/admin/:path*' as const,
};
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if len(mw.Matchers) != 1 || len(mw.Warnings) != 0 {
			t.Fatalf("got %d matchers, %d warnings; want 1, 0", len(mw.Matchers), len(mw.Warnings))
		}
		if !mw.Coverage.Accepts("/admin") || !mw.Coverage.Accepts("/admin/users") || mw.Coverage.Accepts("/public") {
			t.Errorf("unexpected Coverage for /admin/:path*")
		}
	})

	t.Run("object matcher with has and missing emits UNSUPPORTED warning", func(t *testing.T) {
		src := `
export function middleware() {}
export const config = {
  matcher: [
    {
      source: '/admin/:path*',
      has: [{ type: 'header', key: 'x-internal' }],
      missing: [{ type: 'header', key: 'next-router-prefetch' }],
    },
  ],
};
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if len(mw.Matchers) != 1 {
			t.Fatalf("got %d matchers, want 1", len(mw.Matchers))
		}
		if !mw.Matchers[0].Conditional || mw.Matchers[0].Raw != "/admin/:path*" {
			t.Errorf("unexpected matcher entry: %+v", mw.Matchers[0])
		}
		foundCondWarn := false
		for _, w := range mw.Warnings {
			if w.Kind == WarnUnsupported && strings.Contains(w.Message, "has/missing") && w.Line == 7 {
				foundCondWarn = true
			}
		}
		if !foundCondWarn {
			t.Errorf("expected UNSUPPORTED warning at line 7 for has/missing, got: %+v", mw.Warnings)
		}
	})

	t.Run("missing config.matcher applies to all routes", func(t *testing.T) {
		src := `
export function middleware(req) {
  if (!req.headers.get('authorization')) {
    return new Response('Unauthorized', { status: 401 });
  }
}
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if mw.HasExplicitMatcher {
			t.Errorf("HasExplicitMatcher = true, want false")
		}
		for _, s := range []string{"/", "/admin", "/api/users"} {
			if !mw.Coverage.Accepts(s) {
				t.Errorf("default middleware coverage rejected %q", s)
			}
		}
		if !mw.HasAuthSignal {
			t.Errorf("expected HasAuthSignal = true for authorization + 401")
		}
	})

	t.Run("dynamic matcher spread and variable emit UNSUPPORTED warnings", func(t *testing.T) {
		src := `
const extra = ['/api/:path*'];
export function middleware() {}
export const config = {
  matcher: ['/admin/:path*', ...extra, dynVar],
};
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if !mw.HasDynamicMatcher {
			t.Errorf("HasDynamicMatcher = false, want true")
		}
		if len(mw.Matchers) != 1 || mw.Matchers[0].Raw != "/admin/:path*" {
			t.Errorf("expected static element preserved, got: %+v", mw.Matchers)
		}
		unsupportedCount := 0
		for _, w := range mw.Warnings {
			if w.Kind == WarnUnsupported && w.Line == 5 {
				unsupportedCount++
			}
		}
		if unsupportedCount != 2 {
			t.Errorf("got %d UNSUPPORTED warnings at line 5, want 2: %+v", unsupportedCount, mw.Warnings)
		}
	})
}

func TestMiddlewareAuthSignalDetection(t *testing.T) {
	t.Run("detects concrete auth signals", func(t *testing.T) {
		src := `
import { getToken } from 'next-auth/jwt';
import { NextResponse } from 'next/server';

export async function middleware(req) {
  const token = await getToken({ req });
  const hdr = req.headers.get('authorization');
  if (!token && !hdr) {
    if (req.nextUrl.pathname.startsWith('/api')) {
      return new Response('Forbidden', { status: 403 });
    }
    return NextResponse.redirect(new URL('/login', req.url));
  }
}

export const config = { matcher: ['/admin/:path*'] };
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if !mw.HasAuthSignal {
			t.Fatalf("HasAuthSignal = false, want true")
		}
		got := map[string]bool{}
		for _, s := range mw.AuthSignals {
			got[s] = true
		}
		for _, want := range []string{"NextResponse.redirect", "redirect", "403", "authorization", "getToken", "token"} {
			if !got[want] {
				t.Errorf("missing expected auth signal %q in %v", want, mw.AuthSignals)
			}
		}
	})

	t.Run("ignores comments and config block for auth signals", func(t *testing.T) {
		src := `
import { NextResponse } from 'next/server';

// TODO: check auth cookie, session, jwt token, or return 401/403 redirect later
/* NextResponse.redirect getToken authorization */
export function middleware(req) {
  const res = NextResponse.next();
  res.headers.set('x-author', 'team');
  return res;
}

export const config = {
  matcher: ['/auth/:path*', '/session/:path*'],
};
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if mw.HasAuthSignal || len(mw.AuthSignals) != 0 {
			t.Errorf("expected no auth signals, got %v", mw.AuthSignals)
		}
	})
}

func TestLoadMiddlewareDiscoveryAndMissing(t *testing.T) {
	emptyDir := t.TempDir()
	if _, err := LoadMiddleware(emptyDir, automata.DefaultMaxStates); !errors.Is(err, ErrNoMiddleware) {
		t.Fatalf("expected ErrNoMiddleware, got %v", err)
	}

	projDir := t.TempDir()
	writeFiles(t, projDir, map[string]string{
		"src/middleware.ts": `
export function middleware(req) {
  return new Response('Denied', { status: 401 });
}
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\..*).*)'],
};
`,
		"src/app/admin/[...slug]/page.tsx": "export default function Admin() {}",
	})

	mw, err := LoadMiddleware(projDir, automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("LoadMiddleware error: %v", err)
	}
	if mw.File != "src/middleware.ts" {
		t.Errorf("File = %q, want src/middleware.ts", mw.File)
	}

	routes, _, err := DiscoverRoutes(projDir, automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("DiscoverRoutes error: %v", err)
	}
	uncovered, err := routes[0].DFA.Difference(mw.Coverage, automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("Difference error: %v", err)
	}
	witness, ok := uncovered.ShortestWitness()
	if !ok || witness != "/admin/a." {
		t.Fatalf("ShortestWitness() = (%q, %v), want (\"/admin/a.\", true)", witness, ok)
	}
}

func TestAnalyzeDirScenarios(t *testing.T) {
	t.Run("official negative lookahead dot-exclusion bypasses admin API route as HIGH", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
import { NextResponse } from 'next/server';

export function middleware(req) {
  if (!req.cookies.get('session')) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\..*).*)'],
};
`,
			"app/api/admin/[file]/route.ts": "export async function GET() {}",
			"app/blog/[slug]/page.tsx":      "export default function Blog() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if res.RoutesCount != 2 {
			t.Fatalf("RoutesCount = %d, want 2", res.RoutesCount)
		}
		if !res.HasAuthSignal {
			t.Fatalf("HasAuthSignal = false, want true")
		}
		if len(res.Findings) != 2 {
			t.Fatalf("got %d findings, want 2: %+v", len(res.Findings), res.Findings)
		}

		// HIGH (API/admin) must sort before MEDIUM (general blog page).
		high := res.Findings[0]
		if high.Kind != FindingMiddlewareGap || high.Severity != SeverityHigh {
			t.Errorf("first finding = (%q, %q), want (MIDDLEWARE_COVERAGE_GAP, HIGH)", high.Kind, high.Severity)
		}
		if high.RoutePattern != "/api/admin/[file]" || high.RouteKind != RouteAppRoute {
			t.Errorf("unexpected high route: %+v", high)
		}
		if high.Witness != "/api/admin/a." {
			t.Errorf("Witness = %q, want /api/admin/a.", high.Witness)
		}

		med := res.Findings[1]
		if med.Severity != SeverityMedium || med.RoutePattern != "/blog/[slug]" {
			t.Errorf("second finding = (%q, %q), want (MEDIUM, /blog/[slug])", med.Severity, med.RoutePattern)
		}
	})

	t.Run("fully covered static route produces 0 findings", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware(req) {
  return new Response('Denied', { status: 401 });
}
export const config = {
  matcher: ['/admin/:path*'],
};
`,
			"app/admin/page.tsx": "export default function Admin() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings, want 0: %+v", len(res.Findings), res.Findings)
		}
	})

	t.Run("uncovered general route without auth signal reports LOW", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
import { NextResponse } from 'next/server';

export function middleware() {
  const res = NextResponse.next();
  res.headers.set('x-locale', 'en');
  return res;
}

export const config = {
  matcher: ['/en/:path*'],
};
`,
			"app/about/page.tsx": "export default function About() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if res.HasAuthSignal {
			t.Fatalf("HasAuthSignal = true, want false")
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		f := res.Findings[0]
		if f.Severity != SeverityLow || f.Witness != "/about" {
			t.Errorf("got (%q, %q), want (LOW, /about)", f.Severity, f.Witness)
		}
	})

	t.Run("protected flag upgrades uncovered route to HIGH even without auth signal", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
import { NextResponse } from 'next/server';

export function middleware() {
  return NextResponse.next();
}

export const config = {
  matcher: ['/public/:path*'],
};
`,
			"app/[[...slug]]/page.tsx": "export default function CatchAll() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{ProtectedPrefixes: []string{"/secret"}})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		f := res.Findings[0]
		if f.Severity != SeverityHigh {
			t.Errorf("Severity = %q, want HIGH", f.Severity)
		}
		if f.ProtectedMatch != "/secret" {
			t.Errorf("ProtectedMatch = %q, want /secret", f.ProtectedMatch)
		}
		if !strings.HasPrefix(f.Witness, "/secret") {
			t.Errorf("Witness = %q, want prefix /secret", f.Witness)
		}
	})

	t.Run("fully dynamic matcher emits UNSUPPORTED warning and 0 false-positive findings", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware() {
  return new Response('Denied', { status: 401 });
}
export const config = {
  matcher: getMatchers(),
};
`,
			"app/admin/page.tsx":     "export default function Admin() {}",
			"app/api/users/route.ts": "export async function GET() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{ProtectedPrefixes: []string{"/admin"}})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings, want 0 false positives for dynamic matcher: %+v", len(res.Findings), res.Findings)
		}
		hasUnsupported := false
		for _, w := range res.Warnings {
			if w.Kind == WarnUnsupported {
				hasUnsupported = true
				break
			}
		}
		if !hasUnsupported {
			t.Errorf("expected UNSUPPORTED warning for dynamic matcher, got %+v", res.Warnings)
		}
	})

	t.Run("missing middleware file returns ErrNoMiddleware", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"app/page.tsx": "export default function Home() {}",
		})

		_, err := AnalyzeDir(dir, AnalyzeOptions{})
		if !errors.Is(err, ErrNoMiddleware) {
			t.Fatalf("got err = %v, want ErrNoMiddleware", err)
		}
	})

	t.Run("shorthand matcher and dynamic config exports are flagged as dynamic with 0 false positives", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
		}{
			{
				name: "ES6 shorthand { matcher }",
				src: `
const matcher = ['/admin/:path*'];
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = { matcher };
`,
			},
			{
				name: "dynamic config call export const config = defineConfig(...)",
				src: `
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = defineConfig({ matcher: ['/admin/:path*'] });
`,
			},
			{
				name: "re-exported config export { config } from './cfg'",
				src: `
export function middleware() { return new Response('Denied', { status: 401 }); }
export { config } from './cfg';
`,
			},
			{
				name: "chained array expression matcher.concat(...)",
				src: `
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = { matcher: ['/admin/:path*'].concat(extra) };
`,
			},
			{
				name: "chained object expression in array",
				src: `
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = { matcher: [{ source: '/admin/:path*' }.toString()] };
`,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				writeFiles(t, dir, map[string]string{
					"middleware.ts":      tc.src,
					"app/admin/page.tsx": "export default function Admin() {}",
				})
				mw, err := LoadMiddleware(dir, automata.DefaultMaxStates)
				if err != nil {
					t.Fatalf("LoadMiddleware error: %v", err)
				}
				if !mw.HasExplicitMatcher || !mw.HasDynamicMatcher {
					t.Fatalf("got (explicit=%v, dynamic=%v), want (true, true)", mw.HasExplicitMatcher, mw.HasDynamicMatcher)
				}
				res, err := AnalyzeDir(dir, AnalyzeOptions{})
				if err != nil {
					t.Fatalf("AnalyzeDir error: %v", err)
				}
				if len(res.Findings) != 0 {
					t.Fatalf("got %d findings, want 0 false positives: %+v", len(res.Findings), res.Findings)
				}
				hasWarn := false
				for _, w := range res.Warnings {
					if w.Kind == WarnUnsupported {
						hasWarn = true
						break
					}
				}
				if !hasWarn {
					t.Errorf("expected UNSUPPORTED warning, got %+v", res.Warnings)
				}
			})
		}
	})

	t.Run("conditional has/missing matcher does not count as unconditional coverage", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware(req) {
  if (!req.cookies.get('session')) {
    return new Response('Unauthorized', { status: 401 });
  }
}
export const config = {
  matcher: [
    {
      source: '/admin/:path*',
      missing: [{ type: 'header', key: 'purpose', value: 'prefetch' }],
    },
  ],
};
`,
			"app/admin/page.tsx": "export default function Admin() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 1 || res.Findings[0].Severity != SeverityHigh || res.Findings[0].Witness != "/admin" {
			t.Fatalf("expected 1 HIGH finding for conditional matcher gap on /admin, got: %+v", res.Findings)
		}
		hasWarn := false
		for _, w := range res.Warnings {
			if w.Kind == WarnUnsupported && strings.Contains(w.Message, "missing") {
				hasWarn = true
				break
			}
		}
		if !hasWarn {
			t.Errorf("expected UNSUPPORTED warning for conditional matcher, got: %+v", res.Warnings)
		}
	})

	t.Run("unmodeled static matcher suppresses false-positive flood", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = {
  matcher: ['/((?=admin).*)'],
};
`,
			"app/admin/page.tsx": "export default function Admin() {}",
			"app/users/page.tsx": "export default function Users() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings, want 0 false positives for unmodeled static matcher: %+v", len(res.Findings), res.Findings)
		}
		hasWarn := false
		for _, w := range res.Warnings {
			if w.Kind == WarnUnsupported {
				hasWarn = true
				break
			}
		}
		if !hasWarn {
			t.Errorf("expected UNSUPPORTED warning for positive lookahead matcher, got %+v", res.Warnings)
		}
	})

	t.Run("protected prefix enforces path segment boundary", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware() {}
export const config = { matcher: ['/public/:path*'] };
`,
			"app/admin/page.tsx":  "export default function Admin() {}",
			"app/admina/page.tsx": "export default function Admina() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{ProtectedPrefixes: []string{"/admin"}})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 2 {
			t.Fatalf("got %d findings, want 2: %+v", len(res.Findings), res.Findings)
		}
		byRoute := map[string]Finding{}
		for _, f := range res.Findings {
			byRoute[f.RoutePattern] = f
		}
		if byRoute["/admin"].Severity != SeverityHigh || byRoute["/admin"].ProtectedMatch != "/admin" {
			t.Errorf("/admin finding = %+v, want HIGH with ProtectedMatch=/admin", byRoute["/admin"])
		}
		if byRoute["/admina"].Severity != SeverityLow || byRoute["/admina"].ProtectedMatch != "" {
			t.Errorf("/admina finding = %+v, want LOW with empty ProtectedMatch", byRoute["/admina"])
		}
	})

	t.Run("src directory layout ignores stale root middleware", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware() { return new Response('Root', { status: 401 }); }
export const config = { matcher: ['/root-only'] };
`,
			"src/middleware.ts": `
export function middleware() { return new Response('Src', { status: 401 }); }
export const config = { matcher: ['/admin/:path*'] };
`,
			"src/app/admin/page.tsx": "export default function Admin() {}",
		})

		mw, err := LoadMiddleware(dir, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("LoadMiddleware error: %v", err)
		}
		if mw.File != "src/middleware.ts" {
			t.Errorf("File = %q, want src/middleware.ts", mw.File)
		}

		// When only src/app exists and only root middleware.ts exists, Next.js ignores root middleware.ts.
		dirOnlyRootMW := t.TempDir()
		writeFiles(t, dirOnlyRootMW, map[string]string{
			"middleware.ts":          "export function middleware() {}",
			"src/app/admin/page.tsx": "export default function Admin() {}",
		})
		if _, err := LoadMiddleware(dirOnlyRootMW, automata.DefaultMaxStates); !errors.Is(err, ErrNoMiddleware) {
			t.Errorf("expected ErrNoMiddleware when only root middleware exists for src/app, got %v", err)
		}
	})

	t.Run("partially unmodeled or partially dynamic matcher suppresses false positives", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
		}{
			{
				name: "valid matcher plus unmodeled Clerk nested lookahead",
				src: `
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = {
  matcher: ['/admin/:path*', '/((?!_next|[^?]*\\.(?:html?|css|js(?!on))).*)'],
};
`,
			},
			{
				name: "valid matcher plus spread dynamic routes",
				src: `
export function middleware() { return new Response('Denied', { status: 401 }); }
export const config = {
  matcher: ['/admin/:path*', ...dynamicRoutes],
};
`,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				writeFiles(t, dir, map[string]string{
					"middleware.ts":       tc.src,
					"app/secret/page.tsx": "export default function Secret() {}",
				})
				res, err := AnalyzeDir(dir, AnalyzeOptions{})
				if err != nil {
					t.Fatalf("AnalyzeDir error: %v", err)
				}
				if len(res.Findings) != 0 {
					t.Fatalf("got %d findings, want 0 false positives: %+v", len(res.Findings), res.Findings)
				}
				if len(res.Warnings) == 0 {
					t.Errorf("expected warning for unmodeled/dynamic matcher entry")
				}
			})
		}
	})

	t.Run("TS arrow type annotation, local const config, satisfies, and lexJS regex/template edge cases", func(t *testing.T) {
		src := `
import { NextResponse } from 'next/server';

export function middleware(req) {
  const config = { timeout: 5000 };
  const msg = ` + "`hello ${/* } */ `inner ${1}` // }\n}`" + `;
  if (req) {
    console.log(config, msg);
  } /['"]/.test('x');
  if (false) return NextResponse.next(); else /'/.test('y');
  return NextResponse.next();
}

const config: { check?: () => void; matcher: readonly unknown[] } = {
  matcher: [
    { source: '/admin/:path*' satisfies string } satisfies MatcherConfig,
  ] satisfies ReadonlyArray<unknown>,
};

export { config };
`
		mw, err := ParseMiddleware("middleware.ts", src, automata.DefaultMaxStates)
		if err != nil {
			t.Fatalf("ParseMiddleware error: %v", err)
		}
		if !mw.HasExplicitMatcher || mw.HasDynamicMatcher {
			t.Fatalf("got (explicit=%v, dynamic=%v), want (true, false); warnings=%+v", mw.HasExplicitMatcher, mw.HasDynamicMatcher, mw.Warnings)
		}
		if len(mw.Matchers) != 1 || mw.Matchers[0].Raw != "/admin/:path*" {
			t.Fatalf("unexpected matchers: %+v", mw.Matchers)
		}
		if !mw.Coverage.Accepts("/admin/users") || mw.Coverage.Accepts("/public") {
			t.Errorf("unexpected Coverage membership")
		}
	})

	t.Run("protected picks shortest witness and scopes partial check to protected prefix", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"middleware.ts": `
export function middleware() {}
export const config = { matcher: ['/public/:path*'] };
`,
			"app/[[...slug]]/page.tsx": "export default function CatchAll() {}",
		})

		res, err := AnalyzeDir(dir, AnalyzeOptions{
			ProtectedPrefixes: []string{"/admin/super/deep", "/z"},
		})
		if err != nil {
			t.Fatalf("AnalyzeDir error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(res.Findings))
		}
		f := res.Findings[0]
		if f.ProtectedMatch != "/z" || f.Witness != "/z" {
			t.Errorf("got (ProtectedMatch=%q, Witness=%q), want (\"/z\", \"/z\")", f.ProtectedMatch, f.Witness)
		}
		if f.Reason != "protected prefix /z is not covered by middleware matcher" {
			t.Errorf("Reason = %q, want non-partial protected reason", f.Reason)
		}
	})
}
