package nginx

import (
	"errors"
	"fmt"
	"strings"

	"routeproof/internal/automata"
)

// FindingKind classifies a detected routing or authorization vulnerability.
type FindingKind string

const (
	FindingAuthBypass     FindingKind = "AUTH_BYPASS"
	FindingAliasTraversal FindingKind = "ALIAS_TRAVERSAL"
)

// Severity classifies finding urgency.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
)

// AnalyzeOptions configures Nginx configuration analysis.
type AnalyzeOptions struct {
	ProtectedPrefixes []string // Additional URL prefixes treated as protected (--protected).
	MaxStates         int      // Hard DFA state cap; <= 0 uses automata.DefaultMaxStates.
}

// Finding describes a formally proven bypass or traversal with a concrete witness URL.
type Finding struct {
	Kind            FindingKind `json:"kind"`
	Severity        Severity    `json:"severity"`
	ServerName      string      `json:"server_name,omitempty"`
	ServerLine      int         `json:"server_line"`
	Witness         string      `json:"witness"`
	Reason          string      `json:"reason"`
	ProtectedRule   string      `json:"protected_rule"`
	ProtectedLine   int         `json:"protected_line"`
	ProtectedSource string      `json:"protected_source"`
	WinningRule     string      `json:"winning_rule"`
	WinningLine     int         `json:"winning_line"`
	AliasPath       string      `json:"alias_path,omitempty"`
}

// Result aggregates all findings and warnings from analyzing an Nginx config.
type Result struct {
	Findings []Finding `json:"findings"`
	Warnings []Warning `json:"warnings"`
}

// AnalyzeFile parses and analyzes an nginx.conf file from disk.
func AnalyzeFile(path string, opts AnalyzeOptions) (*Result, error) {
	cfg, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	return AnalyzeConfig(cfg, opts)
}

// Analyze parses and analyzes an Nginx configuration string.
func Analyze(src string, opts AnalyzeOptions) (*Result, error) {
	cfg, err := Parse(src)
	if err != nil {
		return nil, err
	}
	return AnalyzeConfig(cfg, opts)
}

// AnalyzeConfig runs formal precedence and alias-traversal analysis over a parsed Config.
func AnalyzeConfig(cfg *Config, opts AnalyzeOptions) (*Result, error) {
	maxStates := opts.MaxStates
	if maxStates <= 0 {
		maxStates = automata.DefaultMaxStates
	}

	res := &Result{
		Warnings: append([]Warning(nil), cfg.Warnings...),
	}

	var validPrefixes []string
	for _, p := range opts.ProtectedPrefixes {
		if p == "" {
			continue
		}
		if badByte, ok := findOutOfAlphabetByte(p); ok {
			res.Warnings = append(res.Warnings, Warning{
				Kind:    WarnUnsupported,
				Context: "--protected " + p,
				Message: fmt.Sprintf("protected prefix contains byte 0x%02X outside modeled ASCII range 0x21..0x7E", badByte),
			})
			continue
		}
		validPrefixes = append(validPrefixes, p)
	}

	for _, srv := range cfg.Servers {
		cs, err := CompileServer(srv, maxStates)
		if err != nil {
			if errors.Is(err, automata.ErrStateLimit) {
				res.Warnings = append(res.Warnings, Warning{
					Kind:    WarnStateLimit,
					Line:    srv.Line,
					Context: serverContext(srv),
					Message: err.Error(),
				})
				continue
			}
			return nil, err
		}
		res.Warnings = append(res.Warnings, cs.Warnings...)

		// Unprotected, externally reachable, non-blocking locations are valid bypass targets.
		var targets []CompiledLocation
		for _, cl := range cs.Locations {
			if cl.Unmodeled || cl.Location.Protected || cl.Location.IsInternal || cl.Location.IsBlocking {
				continue
			}
			targets = append(targets, cl)
		}

		// Pass 1: Explicit protected Nginx locations vs unprotected reachable targets.
		coveredPrefixes := make(map[string]bool)
		for _, p := range cs.Locations {
			if p.Unmodeled || !p.Location.Protected {
				continue
			}
			if p.Location.Modifier == ModPrefix || p.Location.Modifier == ModCaretTilde {
				coveredPrefixes[p.Location.Pattern] = true
			}

			for _, u := range targets {
				if p.Location.Index == u.Location.Index {
					continue
				}
				shadow, err := p.Raw.Intersect(u.Effective, maxStates)
				if err != nil {
					if errors.Is(err, automata.ErrStateLimit) {
						res.Warnings = append(res.Warnings, Warning{
							Kind:    WarnStateLimit,
							Line:    u.Location.Line,
							Context: fmt.Sprintf("%s vs %s", p.Location.Display(), u.Location.Display()),
							Message: err.Error(),
						})
						continue
					}
					return nil, err
				}
				witness, ok := shadow.ShortestWitness()
				if !ok {
					continue
				}

				reason, severity := classifyConflict(p.Location, u.Location, false)
				res.Findings = append(res.Findings, Finding{
					Kind:            FindingAuthBypass,
					Severity:        severity,
					ServerName:      srv.ServerName,
					ServerLine:      srv.Line,
					Witness:         witness,
					Reason:          reason,
					ProtectedRule:   p.Location.Display(),
					ProtectedLine:   p.Location.Line,
					ProtectedSource: strings.Join(p.Location.ProtectVia, ", "),
					WinningRule:     u.Location.Display(),
					WinningLine:     u.Location.Line,
				})
			}
		}

		// Pass 2: User-supplied --protected prefixes vs unprotected reachable targets.
		for _, prefix := range validPrefixes {
			if coveredPrefixes[prefix] {
				continue
			}
			intended := automata.CompilePrefix(prefix)
			virtualProt := Location{Modifier: ModPrefix, Pattern: prefix}

			for _, u := range targets {
				shadow, err := intended.Intersect(u.Effective, maxStates)
				if err != nil {
					if errors.Is(err, automata.ErrStateLimit) {
						res.Warnings = append(res.Warnings, Warning{
							Kind:    WarnStateLimit,
							Line:    u.Location.Line,
							Context: fmt.Sprintf("--protected %s vs %s", prefix, u.Location.Display()),
							Message: err.Error(),
						})
						continue
					}
					return nil, err
				}
				witness, ok := shadow.ShortestWitness()
				if !ok {
					continue
				}

				reason, severity := classifyConflict(virtualProt, u.Location, true)
				res.Findings = append(res.Findings, Finding{
					Kind:            FindingAuthBypass,
					Severity:        severity,
					ServerName:      srv.ServerName,
					ServerLine:      srv.Line,
					Witness:         witness,
					Reason:          reason,
					ProtectedRule:   "--protected " + prefix,
					ProtectedLine:   0,
					ProtectedSource: "--protected",
					WinningRule:     u.Location.Display(),
					WinningLine:     u.Location.Line,
				})
			}
		}

		// Pass 3: Off-by-slash alias traversal check verified against EffectiveDomain.
		for _, cl := range cs.Locations {
			loc := cl.Location
			if cl.Unmodeled || loc.IsInternal || loc.IsBlocking || loc.Alias == "" {
				continue
			}
			if loc.Modifier != ModPrefix && loc.Modifier != ModCaretTilde {
				continue
			}
			if strings.HasSuffix(loc.Pattern, "/") || !strings.HasSuffix(loc.Alias, "/") {
				continue
			}

			traversal := automata.CompilePrefix(loc.Pattern + "../")
			hit, err := cl.Effective.Intersect(traversal, maxStates)
			if err != nil {
				if errors.Is(err, automata.ErrStateLimit) {
					res.Warnings = append(res.Warnings, Warning{
						Kind:    WarnStateLimit,
						Line:    loc.Line,
						Context: loc.Display(),
						Message: err.Error(),
					})
					continue
				}
				return nil, err
			}
			witness, ok := hit.ShortestWitness()
			if !ok {
				continue
			}

			res.Findings = append(res.Findings, Finding{
				Kind:            FindingAliasTraversal,
				Severity:        SeverityHigh,
				ServerName:      srv.ServerName,
				ServerLine:      srv.Line,
				Witness:         witness,
				Reason:          "alias ends with '/' while location prefix lacks trailing '/'",
				ProtectedRule:   loc.Display(),
				ProtectedLine:   loc.AliasLine,
				ProtectedSource: "alias " + loc.Alias,
				WinningRule:     loc.Display(),
				WinningLine:     loc.Line,
				AliasPath:       loc.Alias,
			})
		}
	}

	return res, nil
}

func classifyConflict(p, u Location, fromFlag bool) (string, Severity) {
	isRegexU := u.Modifier == ModRegex || u.Modifier == ModRegexCI
	isRegexP := p.Modifier == ModRegex || p.Modifier == ModRegexCI

	disabledAuthReq := u.Auth.AuthRequestOff && p.Auth.AuthRequest != "" && p.Auth.AuthRequest != "off"
	disabledAuthBasic := u.Auth.AuthBasicOff && p.Auth.AuthBasic != "" && p.Auth.AuthBasic != "off"

	if disabledAuthReq {
		if isRegexU {
			return "regex overrides prefix with auth_request off", SeverityHigh
		}
		return "auth_request off override", SeverityMedium
	}
	if disabledAuthBasic {
		if isRegexU {
			return "regex overrides prefix with auth_basic off", SeverityHigh
		}
		return "auth_basic off override", SeverityMedium
	}

	if isRegexU {
		if isRegexP {
			return "earlier regex takes precedence", SeverityHigh
		}
		if fromFlag {
			return "unprotected regex matches protected prefix", SeverityHigh
		}
		return "regex overrides prefix (missing ^~ modifier)", SeverityHigh
	}

	if u.Modifier == ModExact {
		return "exact match overrides protected rule", SeverityHigh
	}

	if u.Modifier == ModCaretTilde {
		if isRegexP {
			return "^~ prefix skips regex evaluation", SeverityHigh
		}
		if fromFlag && len(u.Pattern) <= len(p.Pattern) {
			return "unprotected location matches protected prefix", SeverityHigh
		}
		return "longer unprotected ^~ prefix", SeverityHigh
	}

	if fromFlag && len(u.Pattern) <= len(p.Pattern) {
		return "unprotected location matches protected prefix", SeverityHigh
	}
	return "longer unprotected prefix", SeverityHigh
}

func serverContext(srv Server) string {
	if srv.ServerName != "" {
		return "server " + srv.ServerName
	}
	return fmt.Sprintf("server (line %d)", srv.Line)
}
