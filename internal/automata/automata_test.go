package automata

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestEmptyAndUniversal(t *testing.T) {
	empty := Empty()
	if !empty.IsEmpty() {
		t.Fatalf("Empty().IsEmpty() = false, want true")
	}
	for _, s := range []string{"", "/", "/admin", "a"} {
		if empty.Accepts(s) {
			t.Errorf("Empty().Accepts(%q) = true, want false", s)
		}
	}

	univ := Universal()
	if univ.IsEmpty() {
		t.Fatalf("Universal().IsEmpty() = true, want false")
	}
	for _, s := range []string{"", "/", "/admin/test.json", "!~"} {
		if !univ.Accepts(s) {
			t.Errorf("Universal().Accepts(%q) = false, want true", s)
		}
	}
	// Bytes outside [0x21..0x7E] must be rejected even by Universal.
	for _, s := range []string{" ", "/a b", "/a\nb", "/a\tb", "\x7f", "/café"} {
		if univ.Accepts(s) {
			t.Errorf("Universal().Accepts(%q) = true, want false for out-of-alphabet byte", s)
		}
	}
}

func TestCompileExactAndPrefix(t *testing.T) {
	exactTests := []struct {
		literal string
		accept  []string
		reject  []string
	}{
		{
			literal: "",
			accept:  []string{""},
			reject:  []string{"/", "a"},
		},
		{
			literal: "/admin",
			accept:  []string{"/admin"},
			reject:  []string{"", "/admi", "/admin/", "/admin/x", "x/admin", "/ADMIN"},
		},
		{
			literal: "/has space",
			accept:  nil,
			reject:  []string{"/has space", "/has", ""},
		},
	}

	for _, tc := range exactTests {
		d := CompileExact(tc.literal)
		for _, s := range tc.accept {
			if !d.Accepts(s) {
				t.Errorf("CompileExact(%q).Accepts(%q) = false, want true", tc.literal, s)
			}
		}
		for _, s := range tc.reject {
			if d.Accepts(s) {
				t.Errorf("CompileExact(%q).Accepts(%q) = true, want false", tc.literal, s)
			}
		}
	}

	prefixTests := []struct {
		prefix string
		accept []string
		reject []string
	}{
		{
			prefix: "",
			accept: []string{"", "/", "/anything"},
			reject: []string{"/has space"},
		},
		{
			prefix: "/admin/",
			accept: []string{"/admin/", "/admin/a", "/admin/a/b.json"},
			reject: []string{"", "/admin", "/admi/", "x/admin/", "/ADMIN/"},
		},
		{
			prefix: "/bad\npath",
			accept: nil,
			reject: []string{"/bad\npath", "/bad"},
		},
	}

	for _, tc := range prefixTests {
		d := CompilePrefix(tc.prefix)
		for _, s := range tc.accept {
			if !d.Accepts(s) {
				t.Errorf("CompilePrefix(%q).Accepts(%q) = false, want true", tc.prefix, s)
			}
		}
		for _, s := range tc.reject {
			if d.Accepts(s) {
				t.Errorf("CompilePrefix(%q).Accepts(%q) = true, want false", tc.prefix, s)
			}
		}
	}
}

func TestCompileAnchoredVsUnanchored(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		opts    CompileOptions
		accept  []string
		reject  []string
	}{
		{
			name:    "unanchored substring",
			pattern: `/admin`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/admin", "/admin/", "/v1/admin/panel", "foo/adminbar"},
			reject:  []string{"", "/admi", "/ADMIN", "admin"},
		},
		{
			name:    "anchored full string",
			pattern: `/admin`,
			opts:    CompileOptions{Anchored: true},
			accept:  []string{"/admin"},
			reject:  []string{"/admin/", "/v1/admin", "/admi"},
		},
		{
			name:    "unanchored with start anchor",
			pattern: `^/admin`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/admin", "/admin/", "/admin/users"},
			reject:  []string{"/v1/admin", "x/admin", "/admi"},
		},
		{
			name:    "unanchored with end anchor",
			pattern: `\.json$`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{".json", "/admin/data.json", "/a.json"},
			reject:  []string{"/admin/data.json/", "/admin/data.json.bak", "/admin/data_json"},
		},
		{
			name:    "alternation with per-branch anchors",
			pattern: `^/exact$|/suffix$|^/prefix/`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/exact", "/a/suffix", "/suffix", "/prefix/anything"},
			reject:  []string{"/exact/", "/x/exact", "/suffix/more", "/x/prefix/a"},
		},
		{
			name:    "empty string anchor pair",
			pattern: `^$`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{""},
			reject:  []string{"/", "a"},
		},
		{
			name:    "reversed empty anchors",
			pattern: `$^`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{""},
			reject:  []string{"/", "a"},
		},
		{
			name:    "impossible mid-string start anchor",
			pattern: `a^b`,
			opts:    CompileOptions{Anchored: false},
			accept:  nil,
			reject:  []string{"", "ab", "a", "b"},
		},
		{
			name:    "impossible mid-string end anchor",
			pattern: `a$b`,
			opts:    CompileOptions{Anchored: false},
			accept:  nil,
			reject:  []string{"", "ab", "a", "b"},
		},
		{
			name:    "bounded repetition and negated class",
			pattern: `^/v[0-9]{1,2}/[^/]+$`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/v1/users", "/v12/item.json"},
			reject:  []string{"/v/users", "/v123/users", "/v1/a/b", "/v1/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Compile(tc.pattern, tc.opts)
			if err != nil {
				t.Fatalf("Compile(%q) error = %v", tc.pattern, err)
			}
			for _, s := range tc.accept {
				if !d.Accepts(s) {
					t.Errorf("Accepts(%q) = false, want true", s)
				}
			}
			for _, s := range tc.reject {
				if d.Accepts(s) {
					t.Errorf("Accepts(%q) = true, want false", s)
				}
			}
		})
	}
}

func TestCompileCaseInsensitive(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		opts    CompileOptions
		accept  []string
		reject  []string
	}{
		{
			name:    "nginx tilde-star option",
			pattern: `\.(json|bak)$`,
			opts:    CompileOptions{Anchored: false, CaseInsensitive: true},
			accept:  []string{"/a.json", "/a.JSON", "/a.Json", "/a.BAK", "/a.BaK"},
			reject:  []string{"/a.json/", "/a.txt", "/ajson"},
		},
		{
			name:    "inline (?i) flag",
			pattern: `(?i)^/admin/`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/admin/x", "/ADMIN/x", "/AdMiN/"},
			reject:  []string{"/admin", "/x/admin/"},
		},
		{
			name:    "scoped (?i:...) and (?-i:...)",
			pattern: `^/(?i:admin)/(?-i:Secret)$`,
			opts:    CompileOptions{Anchored: false, CaseInsensitive: true},
			accept:  []string{"/admin/Secret", "/ADMIN/Secret"},
			reject:  []string{"/admin/secret", "/ADMIN/SECRET"},
		},
		{
			name:    "char class case folding",
			pattern: `^/[a-c]+$`,
			opts:    CompileOptions{Anchored: false, CaseInsensitive: true},
			accept:  []string{"/abc", "/ABC", "/aBc"},
			reject:  []string{"/d", "/D", "/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Compile(tc.pattern, tc.opts)
			if err != nil {
				t.Fatalf("Compile(%q) error = %v", tc.pattern, err)
			}
			for _, s := range tc.accept {
				if !d.Accepts(s) {
					t.Errorf("Accepts(%q) = false, want true", s)
				}
			}
			for _, s := range tc.reject {
				if d.Accepts(s) {
					t.Errorf("Accepts(%q) = true, want false", s)
				}
			}
		})
	}
}

func TestBooleanOperations(t *testing.T) {
	a, err := Compile(`^/admin(/.*)?$`, CompileOptions{Anchored: false})
	if err != nil {
		t.Fatalf("compile a: %v", err)
	}
	b, err := Compile(`\.(json|bak)$`, CompileOptions{Anchored: false, CaseInsensitive: true})
	if err != nil {
		t.Fatalf("compile b: %v", err)
	}

	inter, err := a.Intersect(b, DefaultMaxStates)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	union, err := a.Union(b, DefaultMaxStates)
	if err != nil {
		t.Fatalf("Union: %v", err)
	}
	diff, err := a.Difference(b, DefaultMaxStates)
	if err != nil {
		t.Fatalf("Difference: %v", err)
	}
	compA := a.Complement()
	doubleCompA := compA.Complement()

	// Verify De Morgan: ~(A ∪ B) == (~A) ∩ (~B).
	deMorganLHS := union.Complement()
	deMorganRHS, err := compA.Intersect(b.Complement(), DefaultMaxStates)
	if err != nil {
		t.Fatalf("De Morgan RHS: %v", err)
	}
	symDiff, err := deMorganLHS.Difference(deMorganRHS, DefaultMaxStates)
	if err != nil {
		t.Fatalf("symDiff 1: %v", err)
	}
	symDiff2, err := deMorganRHS.Difference(deMorganLHS, DefaultMaxStates)
	if err != nil {
		t.Fatalf("symDiff 2: %v", err)
	}
	if !symDiff.IsEmpty() || !symDiff2.IsEmpty() {
		t.Fatalf("De Morgan law failed: ~(A ∪ B) != ~A ∩ ~B")
	}

	// Self difference must be empty.
	selfDiff, err := a.Difference(a, DefaultMaxStates)
	if err != nil {
		t.Fatalf("self Difference: %v", err)
	}
	if !selfDiff.IsEmpty() {
		t.Fatalf("A \\ A is not empty")
	}

	// Verify membership across representative paths against stdlib regexp.
	reA := regexp.MustCompile(`^/admin(/.*)?$`)
	reB := regexp.MustCompile(`(?i)\.(json|bak)$`)
	samples := []string{
		"", "/", "/admin", "/admin/", "/admin/users", "/admin/data.json",
		"/admin/data.BAK", "/admin.json", "/public/data.json", "/public/page",
	}
	for _, s := range samples {
		inA := reA.MatchString(s)
		inB := reB.MatchString(s)
		if a.Accepts(s) != inA {
			t.Errorf("a.Accepts(%q) = %v, want %v", s, a.Accepts(s), inA)
		}
		if b.Accepts(s) != inB {
			t.Errorf("b.Accepts(%q) = %v, want %v", s, b.Accepts(s), inB)
		}
		if compA.Accepts(s) != !inA {
			t.Errorf("compA.Accepts(%q) = %v, want %v", s, compA.Accepts(s), !inA)
		}
		if doubleCompA.Accepts(s) != inA {
			t.Errorf("doubleCompA.Accepts(%q) = %v, want %v", s, doubleCompA.Accepts(s), inA)
		}
		if inter.Accepts(s) != (inA && inB) {
			t.Errorf("inter.Accepts(%q) = %v, want %v", s, inter.Accepts(s), inA && inB)
		}
		if union.Accepts(s) != (inA || inB) {
			t.Errorf("union.Accepts(%q) = %v, want %v", s, union.Accepts(s), inA || inB)
		}
		if diff.Accepts(s) != (inA && !inB) {
			t.Errorf("diff.Accepts(%q) = %v, want %v", s, diff.Accepts(s), inA && !inB)
		}
	}

	// Verify Concat on exact + suffix.
	cat, err := CompileExact("/api").Concat(CompileExact("/v1"), DefaultMaxStates)
	if err != nil {
		t.Fatalf("Concat: %v", err)
	}
	if !cat.Accepts("/api/v1") || cat.Accepts("/api") || cat.Accepts("/api/v1/x") {
		t.Errorf("Concat(/api, /v1) gave unexpected membership")
	}
}

func TestNegativeLookahead(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		opts    CompileOptions
		accept  []string
		reject  []string
	}{
		{
			name:    "nextjs static and dot exclusion matcher",
			pattern: `/((?!_next/static|.*\..*).*)`,
			opts:    CompileOptions{Anchored: true},
			accept:  []string{"/users/alice", "/", "/admin", "/_next/data", "/_next/stati"},
			reject:  []string{"/_next/static/chunk.js", "/_next/static/foo", "/users/a.b/settings", "/favicon.ico", "users/alice"},
		},
		{
			name:    "nextjs multi-prefix matcher",
			pattern: `^/((?!api|_next/static|_next/image|favicon\.ico).*)$`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/", "/dashboard", "/users/profile", "/ap/test"},
			reject:  []string{"/api", "/api/users", "/_next/static/app.js", "/_next/image/logo.png", "/favicon.ico"},
		},
		{
			name:    "chained negative lookaheads",
			pattern: `^/(?!admin)(?!internal).*`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/users", "/admi", "/intern", "/"},
			reject:  []string{"/admin", "/admin/panel", "/internal", "/internal/metrics"},
		},
		{
			name:    "end-anchored exclusion inside lookahead",
			pattern: `^/api/(?!health$|metrics$).*`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/api/healthcheck", "/api/metrics/v2", "/api/users"},
			reject:  []string{"/api/health", "/api/metrics"},
		},
		{
			name:    "unanchored negative lookahead",
			pattern: `(?!barbaz)bar`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"bar", "foobar", "barbazbar", "barx"},
			reject:  []string{"barbaz", "xbarbaz", "baz"},
		},
		{
			name:    "case-insensitive inline flag before lookahead",
			pattern: `(?i)^/(?!admin).*`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/users", "/USERS"},
			reject:  []string{"/admin", "/ADMIN", "/AdMiN/panel"},
		},
		{
			name:    "group with trailing suffix after lookahead",
			pattern: `^/((?!_next/static).*)/edit$`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/users/edit", "/posts/123/edit"},
			reject:  []string{"/_next/static/edit", "/_next/static/a/edit", "/users/view"},
		},
		{
			name:    "top-level alternation with lookahead",
			pattern: `^/api/(?!health$).*|^/admin/(?!public$).*`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/api/v1", "/admin/secret", "/api/healthcheck"},
			reject:  []string{"/api/health", "/admin/public", "/other"},
		},
		{
			name:    "inline (?i) propagates across top-level alternation with lookahead",
			pattern: `(?i)^/zzz(?!x)|^/priv`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/zzz", "/ZZZ", "/zzzy", "/priv", "/PRIV", "/PrIv/x"},
			reject:  []string{"/zzzx", "/ZZZX", "/other"},
		},
		{
			name:    "inline (?i) propagates across group alternation without leaking outside",
			pattern: `^/(?:(?i)(?!x)a|b)c$`,
			opts:    CompileOptions{Anchored: true},
			accept:  []string{"/ac", "/Ac", "/bc", "/Bc"},
			reject:  []string{"/aC", "/BC", "/xc"},
		},
		{
			name:    "inline (?i) in group alternation matches /B",
			pattern: `^/(?:(?i)(?!x)a|b)`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/a", "/A", "/b", "/B"},
			reject:  []string{"/x", "/c"},
		},
		{
			name:    "pcre named capture group (?<name>...) with lookahead",
			pattern: `^/admin/(?<path>(?!public)secret/.*\.json)$`,
			opts:    CompileOptions{Anchored: false},
			accept:  []string{"/admin/secret/a.json", "/admin/secret/dir/data.json"},
			reject:  []string{"/admin<p>.json", "/admin/public/a.json", "/admin/secret/a.txt"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Compile(tc.pattern, tc.opts)
			if err != nil {
				t.Fatalf("Compile(%q) error = %v", tc.pattern, err)
			}
			for _, s := range tc.accept {
				if !d.Accepts(s) {
					t.Errorf("Accepts(%q) = false, want true", s)
				}
			}
			for _, s := range tc.reject {
				if d.Accepts(s) {
					t.Errorf("Accepts(%q) = true, want false", s)
				}
			}
		})
	}
}

func TestStateLimit(t *testing.T) {
	t.Run("compile exceeds custom cap", func(t *testing.T) {
		// Minimal DFA for .*a.{10} has 2^11 = 2048 states.
		_, err := Compile(`.*a.{10}`, CompileOptions{Anchored: true, MaxStates: 100})
		if !errors.Is(err, ErrStateLimit) {
			t.Fatalf("got err = %v, want ErrStateLimit", err)
		}
	})

	t.Run("compile exceeds default cap", func(t *testing.T) {
		// Minimal DFA for .*a.{16} has 2^17 = 131072 > DefaultMaxStates (50000).
		_, err := Compile(`.*a.{16}`, CompileOptions{Anchored: true})
		if !errors.Is(err, ErrStateLimit) {
			t.Fatalf("got err = %v, want ErrStateLimit", err)
		}
	})

	t.Run("product operations enforce cap", func(t *testing.T) {
		a := CompilePrefix("/alpha/beta/gamma")
		b, err := Compile(`\.json$`, CompileOptions{Anchored: false})
		if err != nil {
			t.Fatalf("compile b: %v", err)
		}

		if _, err := a.Intersect(b, 5); !errors.Is(err, ErrStateLimit) {
			t.Errorf("Intersect err = %v, want ErrStateLimit", err)
		}
		if _, err := a.Union(b, 5); !errors.Is(err, ErrStateLimit) {
			t.Errorf("Union err = %v, want ErrStateLimit", err)
		}
		if _, err := a.Difference(b, 5); !errors.Is(err, ErrStateLimit) {
			t.Errorf("Difference err = %v, want ErrStateLimit", err)
		}
	})

	t.Run("lookahead branch expansion budget prevents exponential blowup", func(t *testing.T) {
		// 5 unquantified 4-branch groups -> 4^5 = 1024 leaves > maxLookaheadExpansions (256).
		pat := "^/" + strings.Repeat("(?:(?!a)x|b|c|d)", 5)
		start := time.Now()
		_, err := Compile(pat, CompileOptions{Anchored: true})
		elapsed := time.Since(start)
		if !errors.Is(err, ErrStateLimit) {
			t.Fatalf("got err = %v, want ErrStateLimit", err)
		}
		if elapsed > time.Second {
			t.Errorf("expansion cap took too long: %v", elapsed)
		}
	})

	t.Run("wide NFA padding alternation hits node cap quickly", func(t *testing.T) {
		parts := make([]string, 60)
		for i := range parts {
			parts[i] = fmt.Sprintf("p%da{1000}", i)
		}
		pat := "^(?:" + strings.Join(parts, "|") + ")$"
		start := time.Now()
		_, err := Compile(pat, CompileOptions{Anchored: true})
		elapsed := time.Since(start)
		if !errors.Is(err, ErrStateLimit) {
			t.Fatalf("got err = %v, want ErrStateLimit", err)
		}
		if elapsed > time.Second {
			t.Errorf("NFA node cap took too long: %v", elapsed)
		}
	})

	t.Run("subset bitset memory budget caps large NFA state explosion", func(t *testing.T) {
		// ~10k NFA nodes (under maxNFANodes) + .*a.{14} (32768 DFA states) -> exceeds maxSubsetWords.
		parts := make([]string, 10)
		for i := range parts {
			parts[i] = fmt.Sprintf("p%da{1000}", i)
		}
		pat := "^(?:" + strings.Join(parts, "|") + "|.*a.{14})$"
		start := time.Now()
		_, err := Compile(pat, CompileOptions{Anchored: true})
		elapsed := time.Since(start)
		if !errors.Is(err, ErrStateLimit) {
			t.Fatalf("got err = %v, want ErrStateLimit", err)
		}
		if elapsed > 2*time.Second {
			t.Errorf("subset memory cap took too long: %v", elapsed)
		}
	})
}

func TestUnsupportedRegex(t *testing.T) {
	patterns := []struct {
		name    string
		pattern string
	}{
		{"numeric backreference \\1", `(admin)/\1`},
		{"numeric backreference \\2", `(a)(b)\2`},
		{"named backreference \\k", `(?P<x>a)\k<x>`},
		{"backreference \\g", `(a)\g{1}`},
		{"named backreference (?P=)", `(?P<x>a)(?P=x)`},
		{"positive lookahead", `(?=admin).*`},
		{"positive lookbehind", `(?<=admin)/panel`},
		{"negative lookbehind", `(?<!admin)/panel`},
		{"nested negative lookahead", `^(?!a(?!b)).*`},
		{"lookahead inside quantified group", `^/((?!admin).)+$`},
		{"quantified negative lookahead", `^(?!admin)*foo$`},
		{"word boundary", `\badmin\b`},
		{"end anchor before lookahead", `^/$(?!a).*`},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.pattern, CompileOptions{Anchored: false})
			if !errors.Is(err, ErrUnsupportedRegex) {
				t.Errorf("Compile(%q) err = %v, want ErrUnsupportedRegex", tc.pattern, err)
			}
		})
	}
}

func TestShortestWitness(t *testing.T) {
	t.Run("admin prefix with case-insensitive json or bak suffix", func(t *testing.T) {
		adminUnanchoredEnd, err := Compile(`^/admin(/.*)?`, CompileOptions{Anchored: false})
		if err != nil {
			t.Fatalf("compile admin: %v", err)
		}
		ext, err := Compile(`\.(json|bak)$`, CompileOptions{Anchored: false, CaseInsensitive: true})
		if err != nil {
			t.Fatalf("compile ext: %v", err)
		}
		inter, err := adminUnanchoredEnd.Intersect(ext, DefaultMaxStates)
		if err != nil {
			t.Fatalf("Intersect: %v", err)
		}
		w, ok := inter.ShortestWitness()
		if !ok {
			t.Fatalf("ShortestWitness returned ok=false")
		}
		if w != "/admin.bak" {
			t.Errorf("ShortestWitness() = %q, want %q", w, "/admin.bak")
		}
		if !adminUnanchoredEnd.Accepts(w) || !ext.Accepts(w) {
			t.Errorf("witness %q not accepted by both DFAs", w)
		}
	})

	t.Run("anchored admin subpath with case-insensitive json or bak suffix", func(t *testing.T) {
		admin, err := Compile(`^/admin(/.*)?$`, CompileOptions{Anchored: false})
		if err != nil {
			t.Fatalf("compile admin: %v", err)
		}
		ext, err := Compile(`\.(json|bak)$`, CompileOptions{Anchored: false, CaseInsensitive: true})
		if err != nil {
			t.Fatalf("compile ext: %v", err)
		}
		inter, err := admin.Intersect(ext, DefaultMaxStates)
		if err != nil {
			t.Fatalf("Intersect: %v", err)
		}
		w, ok := inter.ShortestWitness()
		if !ok {
			t.Fatalf("ShortestWitness returned ok=false")
		}
		if w != "/admin/.bak" {
			t.Errorf("ShortestWitness() = %q, want %q", w, "/admin/.bak")
		}
	})

	t.Run("readable character priority order", func(t *testing.T) {
		tests := []struct {
			pattern string
			want    string
		}{
			{`^/admin/.+\.json$`, "/admin/a.json"},
			{`^/admin/[^a-z]\.json$`, "/admin/0.json"},
			{`^/admin/[^a-z0-9]\.json$`, "/admin//.json"},
			{`^/admin/[^a-z0-9/]\.json$`, "/admin/..json"},
			{`^/admin/[^a-z0-9/.]\.json$`, "/admin/-.json"},
			{`^/admin/[^a-z0-9/.-]\.json$`, "/admin/_.json"},
			{`^/admin/[^a-z0-9/._-]\.json$`, "/admin/A.json"},
		}
		for _, tc := range tests {
			d, err := Compile(tc.pattern, CompileOptions{Anchored: false})
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.pattern, err)
			}
			w, ok := d.ShortestWitness()
			if !ok {
				t.Fatalf("Compile(%q): ShortestWitness returned ok=false", tc.pattern)
			}
			if w != tc.want {
				t.Errorf("Compile(%q): ShortestWitness() = %q, want %q", tc.pattern, w, tc.want)
			}
		}
	})

	t.Run("nextjs lookahead bypass synthesis", func(t *testing.T) {
		protected, err := Compile(`^/admin/.+$`, CompileOptions{Anchored: false})
		if err != nil {
			t.Fatalf("compile protected: %v", err)
		}
		middleware, err := Compile(`/((?!_next/static|.*\..*).*)`, CompileOptions{Anchored: true})
		if err != nil {
			t.Fatalf("compile middleware: %v", err)
		}
		bypass, err := protected.Difference(middleware, DefaultMaxStates)
		if err != nil {
			t.Fatalf("Difference: %v", err)
		}
		w, ok := bypass.ShortestWitness()
		if !ok {
			t.Fatalf("expected non-empty bypass language")
		}
		if w != "/admin/." {
			t.Errorf("ShortestWitness() = %q, want %q", w, "/admin/.")
		}
		if !protected.Accepts(w) || middleware.Accepts(w) {
			t.Errorf("invalid bypass witness %q", w)
		}
	})

	t.Run("empty and universal witnesses", func(t *testing.T) {
		if w, ok := Empty().ShortestWitness(); ok || w != "" {
			t.Errorf("Empty().ShortestWitness() = (%q, %v), want (\"\", false)", w, ok)
		}
		if w, ok := Universal().ShortestWitness(); !ok || w != "" {
			t.Errorf("Universal().ShortestWitness() = (%q, %v), want (\"\", true)", w, ok)
		}
	})

	t.Run("full-alphabet literal complement has valid witness", func(t *testing.T) {
		all := make([]byte, AlphabetSize)
		for i := 0; i < AlphabetSize; i++ {
			all[i] = MinByte + byte(i)
		}
		d := CompileExact(string(all))
		if d.NumClasses() != AlphabetSize {
			t.Fatalf("NumClasses() = %d, want %d", d.NumClasses(), AlphabetSize)
		}
		comp := d.Complement()
		w, ok := comp.ShortestWitness()
		if !ok || !comp.Accepts(w) || d.Accepts(w) {
			t.Fatalf("unexpected complement witness (%q, %v)", w, ok)
		}
	})
}
