package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"routeproof/internal/nginx"
)

// Summary aggregates finding and warning counts for reporting.
type Summary struct {
	FindingsCount int `json:"findings_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	WarningsCount int `json:"warnings_count"`
}

// JSONReport is the deterministic machine-readable output schema.
type JSONReport struct {
	Target   string          `json:"target"`
	Findings []nginx.Finding `json:"findings"`
	Warnings []nginx.Warning `json:"warnings"`
	Summary  Summary         `json:"summary"`
}

// Build constructs a normalized, deterministically sorted JSONReport.
func Build(target string, res *nginx.Result) JSONReport {
	findings := make([]nginx.Finding, 0)
	warnings := make([]nginx.Warning, 0)
	if res != nil {
		findings = append(findings, res.Findings...)
		warnings = append(warnings, res.Warnings...)
	}

	sort.Slice(findings, func(i, j int) bool {
		return compareFinding(findings[i], findings[j])
	})
	sort.Slice(warnings, func(i, j int) bool {
		return compareWarning(warnings[i], warnings[j])
	})

	sum := Summary{
		FindingsCount: len(findings),
		WarningsCount: len(warnings),
	}
	for _, f := range findings {
		switch f.Severity {
		case nginx.SeverityHigh:
			sum.HighCount++
		case nginx.SeverityMedium:
			sum.MediumCount++
		}
	}

	return JSONReport{
		Target:   target,
		Findings: findings,
		Warnings: warnings,
		Summary:  sum,
	}
}

// WriteJSON encodes the report as deterministic indented JSON.
func WriteJSON(w io.Writer, target string, res *nginx.Result) error {
	rep := Build(target, res)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// WriteText formats findings, warnings, and summary for terminal output.
func WriteText(w io.Writer, target string, res *nginx.Result) error {
	rep := Build(target, res)

	if target != "" {
		if _, err := fmt.Fprintf(w, "Target: %s\n", target); err != nil {
			return err
		}
	}

	if len(rep.Findings) == 0 {
		if _, err := fmt.Fprintln(w, "No bypass or traversal findings detected."); err != nil {
			return err
		}
	} else {
		for i, f := range rep.Findings {
			if i > 0 {
				if _, err := fmt.Fprintln(w); err != nil {
					return err
				}
			}
			header := fmt.Sprintf("[%s] %s", f.Severity, f.Kind)
			if f.ServerName != "" {
				header += fmt.Sprintf(" (server %s, line %d)", f.ServerName, f.ServerLine)
			} else if f.ServerLine > 0 {
				header += fmt.Sprintf(" (server line %d)", f.ServerLine)
			}

			if _, err := fmt.Fprintln(w, header); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Witness:   %s\n", f.Witness); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Protected: %s\n", formatRuleLine(f.ProtectedRule, f.ProtectedLine, f.ProtectedSource)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Winning:   %s\n", formatRuleLine(f.WinningRule, f.WinningLine, "")); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  Reason:    %s\n", f.Reason); err != nil {
				return err
			}
		}
	}

	if len(rep.Warnings) > 0 {
		if _, err := fmt.Fprintln(w, "\nWarnings:"); err != nil {
			return err
		}
		for _, warn := range rep.Warnings {
			loc := ""
			if warn.Line > 0 {
				loc = fmt.Sprintf("line %d", warn.Line)
			}
			if warn.Context != "" {
				if loc != "" {
					loc += ", " + warn.Context
				} else {
					loc = warn.Context
				}
			}
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
		"\nSummary: %d finding(s) (%d high, %d medium), %d warning(s)\n",
		rep.Summary.FindingsCount,
		rep.Summary.HighCount,
		rep.Summary.MediumCount,
		rep.Summary.WarningsCount,
	)
	return err
}

func formatRuleLine(rule string, line int, source string) string {
	switch {
	case line > 0 && source != "":
		return fmt.Sprintf("%s (line %d, %s)", rule, line, source)
	case line > 0:
		return fmt.Sprintf("%s (line %d)", rule, line)
	case source != "":
		return fmt.Sprintf("%s (%s)", rule, source)
	default:
		return rule
	}
}

func severityRank(s nginx.Severity) int {
	switch s {
	case nginx.SeverityHigh:
		return 0
	case nginx.SeverityMedium:
		return 1
	default:
		return 2
	}
}

func compareFinding(a, b nginx.Finding) bool {
	if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
		return ra < rb
	}
	if a.ServerLine != b.ServerLine {
		return a.ServerLine < b.ServerLine
	}
	if a.WinningLine != b.WinningLine {
		return a.WinningLine < b.WinningLine
	}
	if a.ProtectedLine != b.ProtectedLine {
		return a.ProtectedLine < b.ProtectedLine
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Witness != b.Witness {
		return a.Witness < b.Witness
	}
	if a.ProtectedRule != b.ProtectedRule {
		return a.ProtectedRule < b.ProtectedRule
	}
	if a.WinningRule != b.WinningRule {
		return a.WinningRule < b.WinningRule
	}
	if a.ProtectedSource != b.ProtectedSource {
		return a.ProtectedSource < b.ProtectedSource
	}
	return a.Reason < b.Reason
}

func compareWarning(a, b nginx.Warning) bool {
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
