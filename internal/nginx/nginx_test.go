package nginx

import (
	"strings"
	"testing"

	"routeproof/internal/automata"
)

func TestRegexOverridesPrefixBypass(t *testing.T) {
	t.Run("plain prefix shadowed by case-insensitive regex", func(t *testing.T) {
		conf := `
server {
    listen 80;
    server_name app.example.com;

    location /admin {
        auth_request /auth;
        proxy_pass http://admin_backend;
    }

    location ~* \.(json|bak)$ {
        proxy_pass http://static_backend;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		f := res.Findings[0]
		if f.Kind != FindingAuthBypass {
			t.Errorf("Kind = %q, want %q", f.Kind, FindingAuthBypass)
		}
		if f.Severity != SeverityHigh {
			t.Errorf("Severity = %q, want %q", f.Severity, SeverityHigh)
		}
		if f.Witness != "/admin.bak" {
			t.Errorf("Witness = %q, want %q", f.Witness, "/admin.bak")
		}
		if !strings.Contains(f.Reason, "regex overrides prefix") {
			t.Errorf("Reason = %q, want regex overrides prefix", f.Reason)
		}
		if f.ProtectedLine != 6 || f.WinningLine != 11 {
			t.Errorf("lines = (%d, %d), want (6, 11)", f.ProtectedLine, f.WinningLine)
		}
	})

	t.Run("trailing slash prefix yields readable /admin/a.json witness", func(t *testing.T) {
		conf := `
server {
    location /admin/ {
        auth_request /auth;
        proxy_pass http://admin_backend;
    }

    location ~* /[^/]+\.json$ {
        proxy_pass http://static_backend;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		if res.Findings[0].Witness != "/admin/a.json" {
			t.Errorf("Witness = %q, want %q", res.Findings[0].Witness, "/admin/a.json")
		}
	})

	t.Run("caret-tilde prefix prevents regex bypass", func(t *testing.T) {
		conf := `
server {
    location ^~ /admin {
        auth_request /auth;
        proxy_pass http://admin_backend;
    }

    location ~* \.(json|bak)$ {
        proxy_pass http://static_backend;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings, want 0: %+v", len(res.Findings), res.Findings)
		}
	})
}

func TestServerLevelAuthInheritanceAndOffOverride(t *testing.T) {
	t.Run("server auth_basic disabled in single location", func(t *testing.T) {
		conf := `
server {
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://app;
    }

    location /public {
        auth_basic off;
        proxy_pass http://app;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		f := res.Findings[0]
		if f.Witness != "/public" {
			t.Errorf("Witness = %q, want %q", f.Witness, "/public")
		}
		if f.Reason != "auth_basic off override" {
			t.Errorf("Reason = %q, want %q", f.Reason, "auth_basic off override")
		}
		if f.Severity != SeverityMedium {
			t.Errorf("Severity = %q, want %q", f.Severity, SeverityMedium)
		}
	})

	t.Run("server auth_request overridden by regex with auth_request off", func(t *testing.T) {
		conf := `
server {
    auth_request /auth;

    location /admin/ {
        proxy_pass http://admin;
    }

    location ~* \.json$ {
        auth_request off;
        proxy_pass http://static;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		f := res.Findings[0]
		if f.Witness != "/admin/.json" {
			t.Errorf("Witness = %q, want %q", f.Witness, "/admin/.json")
		}
		if f.Severity != SeverityHigh {
			t.Errorf("Severity = %q, want %q", f.Severity, SeverityHigh)
		}
		if f.Reason != "regex overrides prefix with auth_request off" {
			t.Errorf("Reason = %q, want %q", f.Reason, "regex overrides prefix with auth_request off")
		}
	})
}

func TestBlockingAndInternalTargetsExcluded(t *testing.T) {
	conf := `
server {
    location /admin {
        auth_request /auth;
        proxy_pass http://admin;
    }

    location ~* \.bak$ {
        return 403;
    }

    location ~* \.old$ {
        return 404 "Not Found";
    }

    location ~* \.key$ {
        return 401;
    }

    location ~* \.secret$ {
        deny all;
    }

    location ~* \.internal$ {
        internal;
        proxy_pass http://internal_app;
    }

    location @fallback {
        proxy_pass http://fallback;
    }
}
`
	res, err := Analyze(conf, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("got %d findings, want 0 for blocking/internal targets: %+v", len(res.Findings), res.Findings)
	}
}

func TestBackendAuthZeroFalsePositivesAndProtectedFlag(t *testing.T) {
	conf := `
server {
    location /admin {
        auth_request /auth;
        proxy_pass http://admin;
    }

    location /admin/public {
        proxy_pass http://public;
    }
}
`
	// Without --protected: explicit auth_request on /admin detects longer unprotected prefix /admin/public.
	res, err := Analyze(conf, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Witness != "/admin/public" {
		t.Errorf("Witness = %q, want %q", res.Findings[0].Witness, "/admin/public")
	}
	if res.Findings[0].Reason != "longer unprotected prefix" {
		t.Errorf("Reason = %q, want %q", res.Findings[0].Reason, "longer unprotected prefix")
	}

	// Config delegating all auth to backend: 0 findings unless --protected is supplied.
	backendOnly := `
server {
    location / {
        proxy_pass http://app;
    }
    location /admin/public {
        proxy_pass http://public;
    }
}
`
	resClean, err := Analyze(backendOnly, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze backendOnly error: %v", err)
	}
	if len(resClean.Findings) != 0 {
		t.Fatalf("expected 0 findings without --protected, got %+v", resClean.Findings)
	}

	resFlag, err := Analyze(backendOnly, AnalyzeOptions{ProtectedPrefixes: []string{"/admin"}})
	if err != nil {
		t.Fatalf("Analyze backendOnly with --protected error: %v", err)
	}
	if len(resFlag.Findings) != 2 {
		t.Fatalf("got %d findings with --protected /admin, want 2: %+v", len(resFlag.Findings), resFlag.Findings)
	}
	witnesses := map[string]bool{}
	for _, f := range resFlag.Findings {
		witnesses[f.Witness] = true
	}
	if !witnesses["/admin"] || !witnesses["/admin/public"] {
		t.Errorf("expected witnesses /admin and /admin/public, got %+v", witnesses)
	}
}

func TestAliasOffBySlash(t *testing.T) {
	tests := []struct {
		name        string
		conf        string
		wantFinding bool
		wantWitness string
	}{
		{
			name: "vulnerable plain prefix alias",
			conf: `
server {
    location /static {
        alias /var/www/static/;
    }
}
`,
			wantFinding: true,
			wantWitness: "/static../",
		},
		{
			name: "safe matching trailing slashes",
			conf: `
server {
    location /static/ {
        alias /var/www/static/;
    }
}
`,
			wantFinding: false,
		},
		{
			name: "safe neither has trailing slash",
			conf: `
server {
    location /static {
        alias /var/www/static;
    }
}
`,
			wantFinding: false,
		},
		{
			name: "blocked by dot-dot regex",
			conf: `
server {
    location /static {
        alias /var/www/static/;
    }
    location ~ \.\. {
        return 403;
    }
}
`,
			wantFinding: false,
		},
		{
			name: "caret-tilde skips dot-dot blocking regex",
			conf: `
server {
    location ^~ /static {
        alias /var/www/static/;
    }
    location ~ \.\. {
        return 403;
    }
}
`,
			wantFinding: true,
			wantWitness: "/static../",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Analyze(tc.conf, AnalyzeOptions{})
			if err != nil {
				t.Fatalf("Analyze error: %v", err)
			}
			var aliasFindings []Finding
			for _, f := range res.Findings {
				if f.Kind == FindingAliasTraversal {
					aliasFindings = append(aliasFindings, f)
				}
			}
			if tc.wantFinding {
				if len(aliasFindings) != 1 {
					t.Fatalf("got %d alias findings, want 1: %+v", len(aliasFindings), aliasFindings)
				}
				if aliasFindings[0].Witness != tc.wantWitness {
					t.Errorf("Witness = %q, want %q", aliasFindings[0].Witness, tc.wantWitness)
				}
			} else if len(aliasFindings) != 0 {
				t.Fatalf("got %d alias findings, want 0: %+v", len(aliasFindings), aliasFindings)
			}
		})
	}
}

func TestPrecedenceSemanticsExactness(t *testing.T) {
	conf := `
server {
    location = /admin/login { proxy_pass http://exact; }
    location ^~ /admin { proxy_pass http://caret; }
    location /admin/files { proxy_pass http://plain_longer; }
    location ~ ^/admin/files/.*\.php$ { proxy_pass http://php; }
    location ~* \.(php|json)$ { proxy_pass http://regex2; }
    location / { proxy_pass http://root; }
}
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	cs, err := CompileServer(cfg.Servers[0], automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("CompileServer error: %v", err)
	}

	// Effective domains must be pairwise disjoint.
	for i := 0; i < len(cs.Locations); i++ {
		for j := i + 1; j < len(cs.Locations); j++ {
			inter, err := cs.Locations[i].Effective.Intersect(cs.Locations[j].Effective, automata.DefaultMaxStates)
			if err != nil {
				t.Fatalf("Intersect(%d, %d) error: %v", i, j, err)
			}
			if !inter.IsEmpty() {
				w, _ := inter.ShortestWitness()
				t.Errorf("Effective[%d] (%s) and Effective[%d] (%s) overlap on %q",
					i, cs.Locations[i].Location.Display(),
					j, cs.Locations[j].Location.Display(), w)
			}
		}
	}

	// Verify exact winner for concrete URLs.
	urlTests := []struct {
		url      string
		wantRule string
	}{
		{"/admin/login", "location = /admin/login"},
		{"/admin/a.json", "location ^~ /admin"},
		{"/admin/files/index.php", `location ~ ^/admin/files/.*\.php$`},
		{"/admin/files/index.PHP", `location ~* \.(php|json)$`},
		{"/admin/files/data.json", `location ~* \.(php|json)$`},
		{"/admin/files/readme.txt", "location /admin/files"},
		{"/home", "location /"},
		{"/data.JSON", `location ~* \.(php|json)$`},
	}

	for _, tc := range urlTests {
		var winner string
		for _, cl := range cs.Locations {
			if cl.Effective.Accepts(tc.url) {
				if winner != "" {
					t.Errorf("URL %q matched multiple effective domains: %q and %q", tc.url, winner, cl.Location.Display())
				}
				winner = cl.Location.Display()
			}
		}
		if winner != tc.wantRule {
			t.Errorf("URL %q routed to %q, want %q", tc.url, winner, tc.wantRule)
		}
	}
}

func TestUnsupportedDirectivesAndPatternsWarnings(t *testing.T) {
	conf := `
http {
    map $http_upgrade $connection_upgrade {
        default upgrade;
    }

    include conf.d/*.conf;

    server {
        if ($request_method = OPTIONS) {
            return 204;
        }

        rewrite ^/old/(.*)$ /new/$1 permanent;

        location "/admin panel" {
            auth_request /auth;
            proxy_pass http://app;
        }

        location /nested {
            location /nested/child {
                proxy_pass http://child;
            }
        }

        location ~ (admin)/\1 {
            proxy_pass http://backref;
        }
    }
}
`
	res, err := Analyze(conf, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	wantSubstrings := []string{
		"dynamic map block",
		"include directive",
		"dynamic if block",
		"dynamic rewrite directive",
		"outside modeled ASCII range",
		"nested location block",
		"backreference",
	}

	for _, substr := range wantSubstrings {
		found := false
		for _, w := range res.Warnings {
			if w.Kind == WarnUnsupported && strings.Contains(w.Message, substr) {
				if w.Line <= 0 {
					t.Errorf("warning %q missing positive line number: %+v", substr, w)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing UNSUPPORTED warning containing %q; got warnings: %+v", substr, res.Warnings)
		}
	}
}

func TestAccessRulesAndSatisfySemantics(t *testing.T) {
	conf := `
server {
    location /ip_allowlist {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://internal;
    }

    location /deny_only {
        deny all;
    }

    location /allow_all_first {
        allow all;
        deny all;
        proxy_pass http://public;
    }

    location /satisfy_any_auth {
        satisfy any;
        deny all;
        auth_basic "Admin";
        proxy_pass http://admin;
    }

    location /satisfy_any_open {
        satisfy any;
        allow all;
        auth_basic "Admin";
        proxy_pass http://open;
    }
}
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	locs := cfg.Servers[0].Locations
	want := []struct {
		pattern    string
		protected  bool
		isBlocking bool
	}{
		{"/ip_allowlist", true, false},
		{"/deny_only", true, true},
		{"/allow_all_first", false, false},
		{"/satisfy_any_auth", true, false},
		{"/satisfy_any_open", false, false},
	}

	if len(locs) != len(want) {
		t.Fatalf("got %d locations, want %d", len(locs), len(want))
	}
	for i, w := range want {
		got := locs[i]
		if got.Pattern != w.pattern || got.Protected != w.protected || got.IsBlocking != w.isBlocking {
			t.Errorf("loc[%d] %s: got (protected=%v, blocking=%v), want (protected=%v, blocking=%v)",
				i, got.Pattern, got.Protected, got.IsBlocking, w.protected, w.isBlocking)
		}
	}
}

func TestCompactExactLocationSyntax(t *testing.T) {
	conf := `
server {
    location =/favicon.ico {
        return 204;
    }

    location /admin {
        auth_request /auth;
        proxy_pass http://admin;
    }

    location =/admin/health {
        proxy_pass http://health;
    }
}
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	locs := cfg.Servers[0].Locations
	if locs[0].Modifier != ModExact || locs[0].Pattern != "/favicon.ico" {
		t.Fatalf("loc[0] = (%q, %q), want (%q, %q)", locs[0].Modifier, locs[0].Pattern, ModExact, "/favicon.ico")
	}
	if locs[2].Modifier != ModExact || locs[2].Pattern != "/admin/health" {
		t.Fatalf("loc[2] = (%q, %q), want (%q, %q)", locs[2].Modifier, locs[2].Pattern, ModExact, "/admin/health")
	}

	res, err := AnalyzeConfig(cfg, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("AnalyzeConfig error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Witness != "/admin/health" {
		t.Errorf("Witness = %q, want %q", res.Findings[0].Witness, "/admin/health")
	}
	if res.Findings[0].Reason != "exact match overrides protected rule" {
		t.Errorf("Reason = %q, want %q", res.Findings[0].Reason, "exact match overrides protected rule")
	}
}

func TestUTF8BOMConfig(t *testing.T) {
	conf := "\xef\xbb\xbfserver {\n    location /static {\n        alias /var/www/static/;\n    }\n}\n"
	res, err := Analyze(conf, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze with UTF-8 BOM error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Witness != "/static../" {
		t.Fatalf("expected alias traversal finding with UTF-8 BOM, got %+v", res.Findings)
	}
}

func TestInlineCaseFlagLookaheadAlternationBypass(t *testing.T) {
	conf := `
server {
    location /PRIV {
        auth_basic "x";
        proxy_pass http://priv;
    }

    location ~ "(?i)^/zzz(?!x)|^/priv" {
        proxy_pass http://open;
    }
}
`
	res, err := Analyze(conf, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != FindingAuthBypass {
		t.Errorf("Kind = %q, want %q", f.Kind, FindingAuthBypass)
	}
	if f.Witness != "/PRIV" {
		t.Errorf("Witness = %q, want %q", f.Witness, "/PRIV")
	}
}

func TestInheritedAuthOffFlags(t *testing.T) {
	conf := `
http {
    auth_request /auth;
    auth_basic "Global";

    server {
        auth_request off;
        auth_basic off;

        location /x {
            proxy_pass http://open;
        }

        location /re_enabled {
            auth_request /local_auth;
            auth_basic "Local";
            proxy_pass http://secured;
        }
    }
}
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	locs := cfg.Servers[0].Locations
	if len(locs) != 2 {
		t.Fatalf("got %d locations, want 2", len(locs))
	}

	if !locs[0].Auth.AuthRequestOff || !locs[0].Auth.AuthBasicOff {
		t.Errorf("loc /x did not inherit off flags: %+v", locs[0].Auth)
	}
	if locs[0].Protected {
		t.Errorf("loc /x Protected = true, want false")
	}

	if locs[1].Auth.AuthRequestOff || locs[1].Auth.AuthBasicOff {
		t.Errorf("loc /re_enabled kept off flags after re-enabling: %+v", locs[1].Auth)
	}
	if !locs[1].Protected {
		t.Errorf("loc /re_enabled Protected = false, want true")
	}
}

func TestNamedCaptureGroupWithLookahead(t *testing.T) {
	conf := `
server {
    location /admin/ {
        auth_request /auth;
        proxy_pass http://admin;
    }

    location ~ "^/admin/(?<path>(?!public)secret/.*\.json)$" {
        proxy_pass http://open;
    }
}
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	cs, err := CompileServer(cfg.Servers[0], automata.DefaultMaxStates)
	if err != nil {
		t.Fatalf("CompileServer error: %v", err)
	}
	regexLoc := cs.Locations[1]
	if !regexLoc.Raw.Accepts("/admin/secret/a.json") {
		t.Errorf("expected regex to accept /admin/secret/a.json")
	}
	if regexLoc.Raw.Accepts("/admin<p>.json") {
		t.Errorf("expected regex to reject /admin<p>.json")
	}

	res, err := AnalyzeConfig(cfg, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("AnalyzeConfig error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Witness != "/admin/secret/.json" {
		t.Errorf("Witness = %q, want %q", res.Findings[0].Witness, "/admin/secret/.json")
	}
}

func TestAllowAllAfterAllowCIDRSemantics(t *testing.T) {
	conf := `
server {
    location /allow_after_cidr {
        allow 10.0.0.0/8;
        allow all;
        deny all;
        proxy_pass http://open;
    }

    location /satisfy_any_allow_after_cidr {
        satisfy any;
        allow 10.0.0.0/8;
        allow all;
        auth_basic "Admin";
        proxy_pass http://open;
    }

    location /satisfy_any_deny_before_allow_all {
        satisfy any;
        deny 192.168.1.5;
        allow all;
        auth_basic "Admin";
        proxy_pass http://open;
    }
}
`
	cfg, err := Parse(conf)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	locs := cfg.Servers[0].Locations
	if locs[0].Protected || locs[0].IsBlocking {
		t.Errorf("/allow_after_cidr: got (protected=%v, blocking=%v), want (false, false)", locs[0].Protected, locs[0].IsBlocking)
	}
	if locs[1].Protected {
		t.Errorf("/satisfy_any_allow_after_cidr: got protected=true, want false")
	}
	if locs[2].Protected {
		t.Errorf("/satisfy_any_deny_before_allow_all: got protected=true, want false (allow all bypasses auth under satisfy any)")
	}
}

func TestNginxURIDomainStartsWithSlash(t *testing.T) {
	t.Run("caret-tilde root suppresses all unanchored regexes", func(t *testing.T) {
		conf := `
server {
    location ^~ / {
        auth_request /auth;
        proxy_pass http://app;
    }
    location ~* \.json$ {
        proxy_pass http://static;
    }
    location ~ admin {
        auth_request /auth;
        proxy_pass http://admin;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings, want 0: %+v", len(res.Findings), res.Findings)
		}
	})

	t.Run("unanchored regex conflict witness starts with leading slash", func(t *testing.T) {
		conf := `
server {
    location ~* \.json$ {
        proxy_pass http://static;
    }
    location ~ admin {
        auth_request /auth;
        proxy_pass http://admin;
    }
}
`
		res, err := Analyze(conf, AnalyzeOptions{})
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
		}
		if !strings.HasPrefix(res.Findings[0].Witness, "/") {
			t.Errorf("Witness = %q, want leading '/'", res.Findings[0].Witness)
		}
		if res.Findings[0].Witness != "/admin.json" {
			t.Errorf("Witness = %q, want %q", res.Findings[0].Witness, "/admin.json")
		}
	})
}

func TestUnquotedVariableInterpolationLexing(t *testing.T) {
	conf := `
server {
    listen 80;
    location /old {
        return 301 https://${host}${request_uri};
    }
    location /assets {
        alias /var/www/${app}/;
    }
}
`
	res, err := Analyze(conf, AnalyzeOptions{})
	if err != nil {
		t.Fatalf("Analyze error with ${var} interpolation: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 alias finding: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Kind != FindingAliasTraversal || res.Findings[0].AliasPath != "/var/www/${app}/" {
		t.Errorf("unexpected finding: %+v", res.Findings[0])
	}
}
