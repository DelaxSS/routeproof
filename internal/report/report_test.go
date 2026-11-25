package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"routeproof/internal/nextjs"
	"routeproof/internal/nginx"
)

func TestWriteTextWithFindingsAndWarnings(t *testing.T) {
	res := &nginx.Result{
		Findings: []nginx.Finding{
			{
				Kind:            nginx.FindingAuthBypass,
				Severity:        nginx.SeverityMedium,
				ServerName:      "app.example.com",
				ServerLine:      2,
				Witness:         "/public",
				Reason:          "auth_basic off override",
				ProtectedRule:   "location /",
				ProtectedLine:   5,
				ProtectedSource: "auth_basic",
				WinningRule:     "location /public",
				WinningLine:     10,
			},
			{
				Kind:            nginx.FindingAuthBypass,
				Severity:        nginx.SeverityHigh,
				ServerName:      "app.example.com",
				ServerLine:      2,
				Witness:         "/admin/a.json",
				Reason:          "regex overrides prefix (missing ^~ modifier)",
				ProtectedRule:   "location /admin/",
				ProtectedLine:   14,
				ProtectedSource: "auth_request /auth",
				WinningRule:     `location ~* /[^/]+\.json$`,
				WinningLine:     19,
			},
		},
		Warnings: []nginx.Warning{
			{
				Kind:    nginx.WarnUnsupported,
				Line:    25,
				Context: "if",
				Message: "dynamic if block is not modeled",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, "nginx.conf", res); err != nil {
		t.Fatalf("WriteText error: %v", err)
	}
	out := buf.String()

	// HIGH finding must be sorted ahead of MEDIUM finding.
	highIdx := strings.Index(out, "[HIGH] AUTH_BYPASS")
	medIdx := strings.Index(out, "[MEDIUM] AUTH_BYPASS")
	if highIdx < 0 || medIdx < 0 || highIdx > medIdx {
		t.Fatalf("expected HIGH finding before MEDIUM finding:\n%s", out)
	}

	wants := []string{
		"Target: nginx.conf",
		"Witness:   /admin/a.json",
		"Protected: location /admin/ (line 14, auth_request /auth)",
		`Winning:   location ~* /[^/]+\.json$ (line 19)`,
		"Reason:    regex overrides prefix (missing ^~ modifier)",
		"Warnings:",
		"[UNSUPPORTED] (line 25, if) dynamic if block is not modeled",
		"Summary: 2 finding(s) (1 high, 1 medium), 1 warning(s)",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteJSONDeterministicAndNonNullEmptySlices(t *testing.T) {
	t.Run("empty slices serialize as []", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteJSON(&buf, "clean.conf", &nginx.Result{}); err != nil {
			t.Fatalf("WriteJSON error: %v", err)
		}
		raw := buf.String()
		if !strings.Contains(raw, `"findings": []`) {
			t.Errorf("expected empty findings array [], got:\n%s", raw)
		}
		if !strings.Contains(raw, `"warnings": []`) {
			t.Errorf("expected empty warnings array [], got:\n%s", raw)
		}

		var decoded JSONReport
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		if decoded.Target != "clean.conf" {
			t.Errorf("Target = %q, want clean.conf", decoded.Target)
		}
		if decoded.Summary != (Summary{FindingsCount: 0, HighCount: 0, MediumCount: 0, WarningsCount: 0}) {
			t.Errorf("unexpected summary: %+v", decoded.Summary)
		}
	})

	t.Run("counts and ordering are deterministic", func(t *testing.T) {
		res := &nginx.Result{
			Findings: []nginx.Finding{
				{
					Kind:          nginx.FindingAliasTraversal,
					Severity:      nginx.SeverityHigh,
					ServerLine:    1,
					Witness:       "/static../",
					Reason:        "alias ends with '/' while location prefix lacks trailing '/'",
					ProtectedRule: "location /static",
					ProtectedLine: 4,
					WinningRule:   "location /static",
					WinningLine:   3,
					AliasPath:     "/var/www/static/",
				},
			},
			Warnings: []nginx.Warning{
				{Kind: nginx.WarnStateLimit, Line: 12, Context: "loc", Message: "limit"},
				{Kind: nginx.WarnUnsupported, Line: 3, Context: "map", Message: "map"},
			},
		}

		var buf bytes.Buffer
		if err := WriteJSON(&buf, "app.conf", res); err != nil {
			t.Fatalf("WriteJSON error: %v", err)
		}

		var decoded JSONReport
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		wantSum := Summary{FindingsCount: 1, HighCount: 1, MediumCount: 0, WarningsCount: 2}
		if decoded.Summary != wantSum {
			t.Errorf("Summary = %+v, want %+v", decoded.Summary, wantSum)
		}
		if len(decoded.Warnings) != 2 || decoded.Warnings[0].Line != 3 || decoded.Warnings[1].Line != 12 {
			t.Errorf("warnings not sorted by line: %+v", decoded.Warnings)
		}
	})

	t.Run("tie-breaking is independent of input order", func(t *testing.T) {
		f1 := nginx.Finding{
			Kind:            nginx.FindingAuthBypass,
			Severity:        nginx.SeverityHigh,
			ServerLine:      1,
			Witness:         "/admin/secret",
			Reason:          "unprotected location matches protected prefix",
			ProtectedRule:   "--protected /admin",
			ProtectedLine:   0,
			ProtectedSource: "--protected",
			WinningRule:     "location /admin/secret",
			WinningLine:     5,
		}
		f2 := nginx.Finding{
			Kind:            nginx.FindingAuthBypass,
			Severity:        nginx.SeverityHigh,
			ServerLine:      1,
			Witness:         "/admin/secret",
			Reason:          "unprotected location matches protected prefix",
			ProtectedRule:   "--protected /admin/secret",
			ProtectedLine:   0,
			ProtectedSource: "--protected",
			WinningRule:     "location /admin/secret",
			WinningLine:     5,
		}

		repA := Build("app.conf", &nginx.Result{Findings: []nginx.Finding{f1, f2}})
		repB := Build("app.conf", &nginx.Result{Findings: []nginx.Finding{f2, f1}})

		if repA.Findings[0].ProtectedRule != repB.Findings[0].ProtectedRule ||
			repA.Findings[1].ProtectedRule != repB.Findings[1].ProtectedRule {
			t.Fatalf("non-deterministic sort order: A=%+v B=%+v", repA.Findings, repB.Findings)
		}
		if repA.Findings[0].ProtectedRule != "--protected /admin" {
			t.Errorf("first finding = %q, want --protected /admin", repA.Findings[0].ProtectedRule)
		}
	})
}

func TestWriteNextJSTextAndJSON(t *testing.T) {
	t.Run("text formats middleware, findings, warnings, and summary", func(t *testing.T) {
		res := &nextjs.Result{
			MiddlewareFile: "middleware.ts",
			HasAuthSignal:  true,
			AuthSignals:    []string{"cookies", "NextResponse.redirect"},
			RoutesCount:    2,
			Findings: []nextjs.Finding{
				{
					Kind:           nextjs.FindingMiddlewareGap,
					Severity:       nextjs.SeverityMedium,
					Witness:        "/blog/a.",
					Reason:         "route partially escapes middleware matcher coverage",
					RouteFile:      "app/blog/[slug]/page.tsx",
					RouteKind:      nextjs.RouteAppPage,
					RoutePattern:   "/blog/[slug]",
					MiddlewareFile: "middleware.ts",
				},
				{
					Kind:           nextjs.FindingMiddlewareGap,
					Severity:       nextjs.SeverityHigh,
					Witness:        "/api/admin/a.",
					Reason:         "route partially escapes middleware matcher coverage",
					RouteFile:      "app/api/admin/[file]/route.ts",
					RouteKind:      nextjs.RouteAppRoute,
					RoutePattern:   "/api/admin/[file]",
					MiddlewareFile: "middleware.ts",
				},
			},
			Warnings: []nextjs.Warning{
				{
					Kind:    nextjs.WarnUnsupported,
					File:    "middleware.ts",
					Line:    12,
					Context: "config.matcher",
					Message: "conditional matcher (missing) is not modeled",
				},
			},
		}

		var buf bytes.Buffer
		if err := WriteNextJSText(&buf, "./my-app", res); err != nil {
			t.Fatalf("WriteNextJSText error: %v", err)
		}
		out := buf.String()

		highIdx := strings.Index(out, "[HIGH] MIDDLEWARE_COVERAGE_GAP")
		medIdx := strings.Index(out, "[MEDIUM] MIDDLEWARE_COVERAGE_GAP")
		if highIdx < 0 || medIdx < 0 || highIdx > medIdx {
			t.Fatalf("expected HIGH before MEDIUM:\n%s", out)
		}

		wants := []string{
			"Target: ./my-app",
			"Middleware: middleware.ts (auth signals: NextResponse.redirect, cookies)",
			"Witness: /api/admin/a.",
			"Route:   /api/admin/[file] (app-route, app/api/admin/[file]/route.ts)",
			"Warnings:",
			"[UNSUPPORTED] (middleware.ts:12, config.matcher)",
			"Summary: 2 finding(s) (1 high, 1 medium, 0 low), 1 warning(s) across 2 route(s)",
		}
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in output:\n%s", want, out)
			}
		}
	})

	t.Run("json serializes empty slices as [] and counts severities", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteNextJSJSON(&buf, "./clean-app", &nextjs.Result{
			MiddlewareFile: "src/middleware.ts",
			RoutesCount:    3,
		}); err != nil {
			t.Fatalf("WriteNextJSJSON error: %v", err)
		}
		raw := buf.String()
		for _, want := range []string{`"auth_signals": []`, `"findings": []`, `"warnings": []`} {
			if !strings.Contains(raw, want) {
				t.Errorf("expected %s in JSON:\n%s", want, raw)
			}
		}

		var decoded NextJSJSONReport
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		if decoded.Target != "./clean-app" || decoded.RoutesCount != 3 {
			t.Errorf("unexpected report metadata: %+v", decoded)
		}
		if decoded.Summary != (NextJSSummary{}) {
			t.Errorf("unexpected summary: %+v", decoded.Summary)
		}
	})

	t.Run("counts LOW severity and INVALID warnings deterministically", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteNextJSJSON(&buf, "./app", &nextjs.Result{
			MiddlewareFile: "middleware.ts",
			RoutesCount:    1,
			Findings: []nextjs.Finding{
				{
					Kind:           nextjs.FindingMiddlewareGap,
					Severity:       nextjs.SeverityLow,
					Witness:        "/about",
					Reason:         "route is not covered by middleware matcher",
					RouteFile:      "app/about/page.tsx",
					RouteKind:      nextjs.RouteAppPage,
					RoutePattern:   "/about",
					MiddlewareFile: "middleware.ts",
				},
			},
			Warnings: []nextjs.Warning{
				{Kind: nextjs.WarnInvalid, File: "middleware.ts", Line: 4, Context: "/bad(", Message: "unclosed '('"},
			},
		})
		if err != nil {
			t.Fatalf("WriteNextJSJSON error: %v", err)
		}
		var decoded NextJSJSONReport
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		want := NextJSSummary{FindingsCount: 1, LowCount: 1, WarningsCount: 1}
		if decoded.Summary != want {
			t.Errorf("Summary = %+v, want %+v", decoded.Summary, want)
		}
	})
}
