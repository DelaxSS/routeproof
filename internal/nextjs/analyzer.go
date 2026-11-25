package nextjs

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"routeproof/internal/automata"
)

// FindingKind classifies a detected Next.js middleware coverage issue.
type FindingKind string

const (
	FindingMiddlewareGap FindingKind = "MIDDLEWARE_COVERAGE_GAP"
)

// Severity classifies finding urgency.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// AnalyzeOptions configures Next.js middleware coverage analysis.
type AnalyzeOptions struct {
	ProtectedPrefixes []string // Additional URL prefixes treated as protected (--protected).
	MaxStates         int      // Hard DFA state cap; <= 0 uses automata.DefaultMaxStates.
}

// Finding describes a route whose concrete URLs escape Next.js middleware matcher coverage.
type Finding struct {
	Kind           FindingKind `json:"kind"`
	Severity       Severity    `json:"severity"`
	Witness        string      `json:"witness"`
	Reason         string      `json:"reason"`
	RouteFile      string      `json:"route_file"`
	RouteKind      RouteKind   `json:"route_kind"`
	RoutePattern   string      `json:"route_pattern"`
	MiddlewareFile string      `json:"middleware_file"`
	AuthSignals    []string    `json:"auth_signals,omitempty"`
	ProtectedMatch string      `json:"protected_match,omitempty"`
}

// Result aggregates all findings, warnings, and middleware metadata for a Next.js project.
type Result struct {
	MiddlewareFile string    `json:"middleware_file"`
	HasAuthSignal  bool      `json:"has_auth_signal"`
	AuthSignals    []string  `json:"auth_signals"`
	RoutesCount    int       `json:"routes_count"`
	Findings       []Finding `json:"findings"`
	Warnings       []Warning `json:"warnings"`
}

var sensitiveSegments = map[string]bool{
	"admin":     true,
	"dashboard": true,
	"internal":  true,
	"private":   true,
	"account":   true,
	"billing":   true,
	"settings":  true,
	"auth":      true,
}

type compiledPrefix struct {
	prefix string
	dfa    *automata.DFA
}

// AnalyzeDir scans a Next.js project directory and formally checks whether every
// discovered App/Pages Router route is covered by the project's middleware matcher.
func AnalyzeDir(rootDir string, opts AnalyzeOptions) (*Result, error) {
	maxStates := opts.MaxStates
	if maxStates <= 0 {
		maxStates = automata.DefaultMaxStates
	}

	mw, err := LoadMiddleware(rootDir, maxStates)
	if err != nil {
		return nil, err
	}

	routes, routeWarnings, err := DiscoverRoutes(rootDir, maxStates)
	if err != nil {
		return nil, err
	}

	res := &Result{
		MiddlewareFile: mw.File,
		HasAuthSignal:  mw.HasAuthSignal,
		AuthSignals:    append([]string{}, mw.AuthSignals...),
		RoutesCount:    len(routes),
		Findings:       []Finding{},
		Warnings:       make([]Warning, 0, len(mw.Warnings)+len(routeWarnings)),
	}
	res.Warnings = append(res.Warnings, mw.Warnings...)
	res.Warnings = append(res.Warnings, routeWarnings...)

	var protected []compiledPrefix
	for _, p := range opts.ProtectedPrefixes {
		if p == "" {
			continue
		}
		if bad, ok := findOutOfAlphabetByte(p); ok {
			res.Warnings = append(res.Warnings, Warning{
				Kind:    WarnUnsupported,
				Context: "--protected " + p,
				Message: fmt.Sprintf("protected prefix contains byte 0x%02X outside modeled ASCII range 0x21..0x7E", bad),
			})
			continue
		}
		protDFA, err := compileProtectedPrefix(p, maxStates)
		if err != nil {
			wKind := WarnInvalid
			if errors.Is(err, automata.ErrStateLimit) {
				wKind = WarnStateLimit
			}
			res.Warnings = append(res.Warnings, Warning{
				Kind:    wKind,
				Context: "--protected " + p,
				Message: err.Error(),
			})
			continue
		}
		protected = append(protected, compiledPrefix{
			prefix: p,
			dfa:    protDFA,
		})
	}
	sort.Slice(protected, func(i, j int) bool {
		return protected[i].prefix < protected[j].prefix
	})

	// Avoid false positives whenever config.matcher contains dynamic or unmodeled entries,
	// since mw.Coverage is then only a partial lower bound of actual middleware coverage.
	// Conditional (has/missing) matchers are intentionally not suppressed because they can be bypassed.
	hasUnmodeled := false
	for _, m := range mw.Matchers {
		if m.Unmodeled {
			hasUnmodeled = true
		}
	}
	if mw.HasExplicitMatcher && (mw.HasDynamicMatcher || hasUnmodeled) {
		sortWarnings(res.Warnings)
		return res, nil
	}

	coverage := mw.Coverage
	if coverage == nil {
		coverage = automata.Empty()
	}

	for _, route := range routes {
		if route.DFA == nil {
			continue
		}

		gap, err := route.DFA.Difference(coverage, maxStates)
		if err != nil {
			if errors.Is(err, automata.ErrStateLimit) {
				res.Warnings = append(res.Warnings, Warning{
					Kind:    WarnStateLimit,
					File:    route.File,
					Context: route.Pattern,
					Message: err.Error(),
				})
				continue
			}
			return nil, err
		}

		witness, ok := gap.ShortestWitness()
		if !ok {
			continue
		}

		// Prefer the shortest witness inside any matching --protected prefix.
		protectedMatch := ""
		var matchedProtDFA *automata.DFA
		bestProtLen := -1
		for _, cp := range protected {
			protGap, err := gap.Intersect(cp.dfa, maxStates)
			if err != nil {
				if errors.Is(err, automata.ErrStateLimit) {
					res.Warnings = append(res.Warnings, Warning{
						Kind:    WarnStateLimit,
						File:    route.File,
						Context: fmt.Sprintf("%s vs --protected %s", route.Pattern, cp.prefix),
						Message: err.Error(),
					})
					continue
				}
				return nil, err
			}
			if pw, ok := protGap.ShortestWitness(); ok {
				if bestProtLen < 0 || len(pw) < bestProtLen || (len(pw) == bestProtLen && pw < witness) {
					witness = pw
					protectedMatch = cp.prefix
					matchedProtDFA = cp.dfa
					bestProtLen = len(pw)
				}
			}
		}

		partial := false
		if matchedProtDFA != nil {
			if scoped, err := route.DFA.Intersect(matchedProtDFA, maxStates); err == nil {
				if covered, err := scoped.Intersect(coverage, maxStates); err == nil && !covered.IsEmpty() {
					partial = true
				}
			}
		} else {
			if covered, err := route.DFA.Intersect(coverage, maxStates); err == nil && !covered.IsEmpty() {
				partial = true
			}
		}

		severity := classifySeverity(route, mw.HasAuthSignal, protectedMatch)
		reason := describeGapReason(partial, protectedMatch)

		var signals []string
		if len(mw.AuthSignals) > 0 {
			signals = append([]string{}, mw.AuthSignals...)
		}

		res.Findings = append(res.Findings, Finding{
			Kind:           FindingMiddlewareGap,
			Severity:       severity,
			Witness:        witness,
			Reason:         reason,
			RouteFile:      route.File,
			RouteKind:      route.Kind,
			RoutePattern:   route.Pattern,
			MiddlewareFile: mw.File,
			AuthSignals:    signals,
			ProtectedMatch: protectedMatch,
		})
	}

	sort.Slice(res.Findings, func(i, j int) bool {
		return compareFinding(res.Findings[i], res.Findings[j])
	})
	sortWarnings(res.Warnings)

	return res, nil
}

func compileProtectedPrefix(p string, maxStates int) (*automata.DFA, error) {
	if p == "/" || strings.HasSuffix(p, "/") {
		return automata.CompilePrefix(p), nil
	}
	re := "^" + regexp.QuoteMeta(p) + "(?:/.*)?$"
	return automata.Compile(re, automata.CompileOptions{
		Anchored:  true,
		MaxStates: maxStates,
	})
}

func classifySeverity(route Route, hasAuthSignal bool, protectedMatch string) Severity {
	if protectedMatch != "" {
		return SeverityHigh
	}
	if !hasAuthSignal {
		return SeverityLow
	}
	if route.Kind == RouteAppRoute || route.Kind == RoutePagesAPI || hasSensitiveSegment(route.Pattern) {
		return SeverityHigh
	}
	return SeverityMedium
}

func hasSensitiveSegment(pattern string) bool {
	for _, seg := range strings.Split(strings.ToLower(pattern), "/") {
		if sensitiveSegments[seg] {
			return true
		}
	}
	return false
}

func describeGapReason(partial bool, protectedMatch string) string {
	if protectedMatch != "" {
		if partial {
			return fmt.Sprintf("protected prefix %s partially escapes middleware matcher coverage", protectedMatch)
		}
		return fmt.Sprintf("protected prefix %s is not covered by middleware matcher", protectedMatch)
	}
	if partial {
		return "route partially escapes middleware matcher coverage"
	}
	return "route is not covered by middleware matcher"
}

func severityRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default:
		return 3
	}
}

func compareFinding(a, b Finding) bool {
	if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
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

func sortWarnings(warnings []Warning) {
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].File != warnings[j].File {
			return warnings[i].File < warnings[j].File
		}
		if warnings[i].Line != warnings[j].Line {
			return warnings[i].Line < warnings[j].Line
		}
		if warnings[i].Kind != warnings[j].Kind {
			return warnings[i].Kind < warnings[j].Kind
		}
		if warnings[i].Context != warnings[j].Context {
			return warnings[i].Context < warnings[j].Context
		}
		return warnings[i].Message < warnings[j].Message
	})
}
