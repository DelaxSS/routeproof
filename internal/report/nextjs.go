package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"routeproof/internal/nextjs"
)

// NextJSSummary aggregates finding and warning counts for Next.js reports.
type NextJSSummary struct {
	FindingsCount int `json:"findings_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	WarningsCount int `json:"warnings_count"`
}

// NextJSJSONReport is the deterministic machine-readable schema for Next.js analysis.
type NextJSJSONReport struct {
	Target         string           `json:"target"`
	MiddlewareFile string           `json:"middleware_file"`
	HasAuthSignal  bool             `json:"has_auth_signal"`
	AuthSignals    []string         `json:"auth_signals"`
	RoutesCount    int              `json:"routes_count"`
	Findings       []nextjs.Finding `json:"findings"`
	Warnings       []nextjs.Warning `json:"warnings"`
	Summary        NextJSSummary    `json:"summary"`
}

// BuildNextJS constructs a normalized, deterministically sorted NextJSJSONReport.
func BuildNextJS(target string, res *nextjs.Result) NextJSJSONReport {
	authSignals := make([]string, 0)
	findings := make([]nextjs.Finding, 0)
	warnings := make([]nextjs.Warning, 0)
	var mwFile string
	var hasAuth bool
	var routesCount int

	if res != nil {
		mwFile = res.MiddlewareFile
		hasAuth = res.HasAuthSignal
		routesCount = res.RoutesCount
		authSignals = append(authSignals, res.AuthSignals...)
		findings = append(findings, res.Findings...)
		warnings = append(warnings, res.Warnings...)
	}

	sort.Strings(authSignals)
	sort.Slice(findings, func(i, j int) bool {
		return compareNextJSFinding(findings[i], findings[j])
	})
	sort.Slice(warnings, func(i, j int) bool {
		return compareNextJSWarning(warnings[i], warnings[j])
	})

	sum := NextJSSummary{
		FindingsCount: len(findings),
		WarningsCount: len(warnings),
	}
	for _, f := range findings {
		switch f.Severity {
		case nextjs.SeverityHigh:
			sum.HighCount++
		case nextjs.SeverityMedium:
			sum.MediumCount++
		case nextjs.SeverityLow:
			sum.LowCount++
		}
	}

	return NextJSJSONReport{
		Target:         target,
		MiddlewareFile: mwFile,
		HasAuthSignal:  hasAuth,
		AuthSignals:    authSignals,
		RoutesCount:    routesCount,
		Findings:       findings,
		Warnings:       warnings,
		Summary:        sum,
	}
}

// WriteNextJSJSON encodes a Next.js analysis result as deterministic indented JSON.
func WriteNextJSJSON(w io.Writer, target string, res *nextjs.Result) error {
	rep := BuildNextJS(target, res)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// WriteNextJSText formats Next.js middleware coverage findings and warnings for terminal output.
func WriteNextJSText(w io.Writer, target string, res *nextjs.Result) error {
	rep := BuildNextJS(target, res)

	if target != "" {
		if _, err := fmt.Fprintf(w, "Target: %s\n", target); err != nil {
			return err
		}
	}
	if rep.MiddlewareFile != "" {
		if rep.HasAuthSignal && len(rep.AuthSignals) > 0 {
			if _, err := fmt.Fprintf(w, "Middleware: %s (auth signals: %s)\n", rep.MiddlewareFile, strings.Join(rep.AuthSignals, ", ")); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "Middleware: %s (no auth signals detected)\n", rep.MiddlewareFile); err != nil {
				return err
			}
		}
	}

	if len(rep.Findings) == 0 {
		if _, err := fmt.Fprintln(w, "No middleware coverage gaps detected."); err != nil {
			return err
		}
	} else {
		for i, f := range rep.Findings {
			if i > 0 {
				if _, err := fmt.Fprintln(w); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "[%s] %s\n", f.Severity, f.Kind); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Witness: %s\n", f.Witness); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Route:   %s (%s, %s)\n", f.RoutePattern, f.RouteKind, f.RouteFile); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Reason:  %s\n", f.Reason); err != nil {
				return err
			}
		}
	}

	if len(rep.Warnings) > 0 {
		if _, err := fmt.Fprintln(w, "\nWarnings:"); err != nil {
			return err
		}
		for _, warn := range rep.Warnings {
			loc := formatNextJSWarnLoc(warn)
			var err error
			if loc != "" {
				_, err = fmt.Fprintf(w, "  [%s] (%s) %s\n", warn.Kind, loc, warn.Message)
			} else {
				_, err = fmt.Fprintf(w, "  [%s] %s\n", warn.Kind, warn.Message)
			}
			if err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintf(
		w,
		"\nSummary: %d finding(s) (%d high, %d medium, %d low), %d warning(s) across %d route(s)\n",
		rep.Summary.FindingsCount,
		rep.Summary.HighCount,
		rep.Summary.MediumCount,
		rep.Summary.LowCount,
		rep.Summary.WarningsCount,
		rep.RoutesCount,
	)
	return err
}

func formatNextJSWarnLoc(w nextjs.Warning) string {
	var parts []string
	if w.File != "" && w.Line > 0 {
		parts = append(parts, fmt.Sprintf("%s:%d", w.File, w.Line))
	} else if w.File != "" {
		parts = append(parts, w.File)
	} else if w.Line > 0 {
		parts = append(parts, fmt.Sprintf("line %d", w.Line))
	}
	if w.Context != "" {
		parts = append(parts, w.Context)
	}
	return strings.Join(parts, ", ")
}

func nextJSSeverityRank(s nextjs.Severity) int {
	switch s {
	case nextjs.SeverityHigh:
		return 0
	case nextjs.SeverityMedium:
		return 1
	case nextjs.SeverityLow:
		return 2
	default:
		return 3
	}
}

func compareNextJSFinding(a, b nextjs.Finding) bool {
	if ra, rb := nextJSSeverityRank(a.Severity), nextJSSeverityRank(b.Severity); ra != rb {
		return ra < rb
	}
	if a.RoutePattern != b.RoutePattern {
		return a.RoutePattern < b.RoutePattern
	}
	if a.RouteFile != b.RouteFile {
		return a.RouteFile < b.RouteFile
	}
	if a.Witness != b.Witness {
		return a.Witness < b.Witness
	}
	if a.ProtectedMatch != b.ProtectedMatch {
		return a.ProtectedMatch < b.ProtectedMatch
	}
	return a.Reason < b.Reason
}

func compareNextJSWarning(a, b nextjs.Warning) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Context != b.Context {
		return a.Context < b.Context
	}
	return a.Message < b.Message
}
