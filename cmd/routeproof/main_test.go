package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"routeproof/internal/report"
)

func writeTempConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp conf: %v", err)
	}
	return path
}

func TestCLIVersionAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("--version exit = %d, want %d", code, exitOK)
	}
	if got := strings.TrimSpace(stdout.String()); got != "routeproof v0.2.0" {
		t.Errorf("--version stdout = %q, want %q", got, "routeproof v0.2.0")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"unknown"}, &stdout, &stderr); code != exitError {
		t.Fatalf("unknown command exit = %d, want %d", code, exitError)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"nginx"}, &stdout, &stderr); code != exitError {
		t.Fatalf("missing path exit = %d, want %d", code, exitError)
	}
}

func TestCLINginxTextJSONAndExitCodes(t *testing.T) {
	vulnPath := writeTempConf(t, `
server {
    location /admin/ {
        auth_request /auth;
        proxy_pass http://admin;
    }
    location ~* /[^/]+\.json$ {
        proxy_pass http://static;
    }
}
`)

	t.Run("text output without fail-on-finding exits 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"nginx", vulnPath}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitOK, stderr.String())
		}
		if !strings.Contains(stdout.String(), "/admin/a.json") {
			t.Errorf("expected witness /admin/a.json in stdout:\n%s", stdout.String())
		}
	})

	t.Run("fail-on-finding exits 1 when findings exist", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"nginx", "--fail-on-finding", vulnPath}, &stdout, &stderr)
		if code != exitFinding {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitFinding, stderr.String())
		}
	})

	t.Run("json output decodes cleanly", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"nginx", "--json", vulnPath}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitOK, stderr.String())
		}
		var rep report.JSONReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("json.Unmarshal error: %v\nraw:\n%s", err, stdout.String())
		}
		if rep.Summary.FindingsCount != 1 || rep.Summary.HighCount != 1 {
			t.Errorf("unexpected summary: %+v", rep.Summary)
		}
		if rep.Findings[0].Witness != "/admin/a.json" {
			t.Errorf("Witness = %q, want /admin/a.json", rep.Findings[0].Witness)
		}
	})
}

func TestCLINginxRepeatableProtectedAndCleanExit(t *testing.T) {
	confPath := writeTempConf(t, `
server {
    location ^~ /admin {
        auth_request /auth;
        proxy_pass http://admin;
    }
    location /internal {
        proxy_pass http://internal;
    }
    location /metrics {
        proxy_pass http://metrics;
    }
}
`)

	t.Run("clean config with fail-on-finding exits 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"nginx", "--fail-on-finding", confPath}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, exitOK, stdout.String(), stderr.String())
		}
	})

	t.Run("repeatable --protected flags catch multiple prefixes", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"nginx",
			"--json",
			"--fail-on-finding",
			"--protected", "/internal",
			"--protected", "/metrics",
			confPath,
		}, &stdout, &stderr)
		if code != exitFinding {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitFinding, stderr.String())
		}
		var rep report.JSONReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		if rep.Summary.FindingsCount != 2 {
			t.Fatalf("FindingsCount = %d, want 2: %+v", rep.Summary.FindingsCount, rep.Findings)
		}
	})

	t.Run("parse error and missing file exit 2", func(t *testing.T) {
		badPath := writeTempConf(t, "server { location /admin { ")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"nginx", badPath}, &stdout, &stderr); code != exitError {
			t.Fatalf("parse error exit = %d, want %d", code, exitError)
		}
		if code := run([]string{"nginx", filepath.Join(t.TempDir(), "missing.conf")}, &stdout, &stderr); code != exitError {
			t.Fatalf("missing file exit = %d, want %d", code, exitError)
		}
		if code := run([]string{"nginx", "--max-states", "0", confPath}, &stdout, &stderr); code != exitError {
			t.Fatalf("invalid max-states exit = %d, want %d", code, exitError)
		}
	})
}

func writeNextJSProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return dir
}

func TestCLINextJSCommand(t *testing.T) {
	projDir := writeNextJSProject(t, map[string]string{
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
	})

	t.Run("text output without fail-on-finding exits 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"nextjs", projDir}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitOK, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "[HIGH] MIDDLEWARE_COVERAGE_GAP") || !strings.Contains(out, "/api/admin/a.") {
			t.Errorf("unexpected text output:\n%s", out)
		}
	})

	t.Run("json and fail-on-finding exit 1 with decoded findings", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"nextjs", "--json", "--fail-on-finding", projDir}, &stdout, &stderr)
		if code != exitFinding {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitFinding, stderr.String())
		}
		var rep report.NextJSJSONReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("json.Unmarshal error: %v\nraw:\n%s", err, stdout.String())
		}
		if rep.Summary.FindingsCount != 1 || rep.Summary.HighCount != 1 {
			t.Errorf("unexpected summary: %+v", rep.Summary)
		}
		if rep.MiddlewareFile != "middleware.ts" || !rep.HasAuthSignal {
			t.Errorf("unexpected middleware metadata: %+v", rep)
		}
	})

	t.Run("protected flag upgrades uncovered route to HIGH", func(t *testing.T) {
		noAuthDir := writeNextJSProject(t, map[string]string{
			"middleware.ts": `
export function middleware() {}
export const config = { matcher: ['/public/:path*'] };
`,
			"app/secret/page.tsx": "export default function Secret() {}",
		})
		var stdout, stderr bytes.Buffer
		code := run([]string{"nextjs", "--json", "--fail-on-finding", "--protected", "/secret", noAuthDir}, &stdout, &stderr)
		if code != exitFinding {
			t.Fatalf("exit = %d, want %d; stderr=%s", code, exitFinding, stderr.String())
		}
		var rep report.NextJSJSONReport
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		if rep.Summary.HighCount != 1 || rep.Findings[0].ProtectedMatch != "/secret" {
			t.Errorf("unexpected report: %+v", rep)
		}
	})

	t.Run("missing middleware and invalid args exit 2", func(t *testing.T) {
		emptyDir := t.TempDir()
		var stdout, stderr bytes.Buffer
		if code := run([]string{"nextjs", emptyDir}, &stdout, &stderr); code != exitError {
			t.Fatalf("missing middleware exit = %d, want %d", code, exitError)
		}
		if code := run([]string{"nextjs"}, &stdout, &stderr); code != exitError {
			t.Fatalf("missing dir arg exit = %d, want %d", code, exitError)
		}
	})
}
