package nginx

import (
	"errors"
	"fmt"
	"strings"

	"routeproof/internal/automata"
)

// CompiledLocation pairs a parsed Location with its raw and effective DFAs.
type CompiledLocation struct {
	Location  Location
	Raw       *automata.DFA
	Effective *automata.DFA
	Unmodeled bool
}

// CompiledServer holds compiled raw and effective DFAs for a server block.
type CompiledServer struct {
	Server    Server
	Locations []CompiledLocation
	Warnings  []Warning
}

// CompileServer compiles every modeled location in srv and computes each
// location's exact effective URL language under Nginx precedence rules.
func CompileServer(srv Server, maxStates int) (*CompiledServer, error) {
	if maxStates <= 0 {
		maxStates = automata.DefaultMaxStates
	}

	cs := &CompiledServer{
		Server:    srv,
		Locations: make([]CompiledLocation, len(srv.Locations)),
	}

	// Normalized HTTP request URIs in Nginx always begin with '/'.
	uriDomain := automata.CompilePrefix("/")

	// Step 0: Compile each location's raw matching language.
	for i, loc := range srv.Locations {
		cl := CompiledLocation{
			Location:  loc,
			Raw:       automata.Empty(),
			Effective: automata.Empty(),
		}

		if loc.IsNamed {
			cl.Unmodeled = true
			cs.Locations[i] = cl
			continue
		}
		if loc.HasUnsupportedByte {
			cl.Unmodeled = true
			cs.Locations[i] = cl
			continue
		}
		if badByte, ok := findOutOfAlphabetByte(loc.Pattern); ok {
			cl.Unmodeled = true
			cs.Warnings = append(cs.Warnings, Warning{
				Kind:    WarnUnsupported,
				Line:    loc.Line,
				Context: loc.Display(),
				Message: fmt.Sprintf("location pattern contains byte 0x%02X outside modeled ASCII range 0x21..0x7E", badByte),
			})
			cs.Locations[i] = cl
			continue
		}

		switch loc.Modifier {
		case ModExact:
			cl.Raw = automata.CompileExact(loc.Pattern)
		case ModPrefix, ModCaretTilde:
			cl.Raw = automata.CompilePrefix(loc.Pattern)
		case ModRegex, ModRegexCI:
			d, err := automata.Compile(loc.Pattern, automata.CompileOptions{
				Anchored:        false,
				CaseInsensitive: loc.Modifier == ModRegexCI,
				MaxStates:       maxStates,
			})
			if err == nil {
				d, err = d.Intersect(uriDomain, maxStates)
			}
			if err != nil {
				cl.Unmodeled = true
				kind := WarnInvalid
				if errors.Is(err, automata.ErrUnsupportedRegex) {
					kind = WarnUnsupported
				} else if errors.Is(err, automata.ErrStateLimit) {
					kind = WarnStateLimit
				}
				cs.Warnings = append(cs.Warnings, Warning{
					Kind:    kind,
					Line:    loc.Line,
					Context: loc.Display(),
					Message: err.Error(),
				})
			} else {
				cl.Raw = d
			}
		}

		cs.Locations[i] = cl
	}

	// Step 1: Exact matches (=) take highest priority.
	allExact := automata.Empty()
	for i := range cs.Locations {
		cl := &cs.Locations[i]
		if cl.Unmodeled || cl.Location.Modifier != ModExact {
			continue
		}
		eff, err := cl.Raw.Difference(allExact, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: exact precedence at line %d: %w", cl.Location.Line, err)
		}
		cl.Effective = eff
		allExact, err = allExact.Union(cl.Raw, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: exact union at line %d: %w", cl.Location.Line, err)
		}
	}

	// Step 2: Longest prefix match across all prefix locations (^~ and plain prefix).
	var prefixIndices []int
	for i := range cs.Locations {
		cl := &cs.Locations[i]
		if cl.Unmodeled {
			continue
		}
		if cl.Location.Modifier == ModPrefix || cl.Location.Modifier == ModCaretTilde {
			prefixIndices = append(prefixIndices, i)
		}
	}

	longestPrefix := make(map[int]*automata.DFA, len(prefixIndices))
	allCaretTilde := automata.Empty()

	for _, i := range prefixIndices {
		cl := &cs.Locations[i]
		dom, err := cl.Raw.Difference(allExact, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: prefix exclusion at line %d: %w", cl.Location.Line, err)
		}

		pi := cl.Location.Pattern
		for _, j := range prefixIndices {
			if i == j {
				continue
			}
			pj := cs.Locations[j].Location.Pattern
			if (len(pj) > len(pi) && strings.HasPrefix(pj, pi)) || (pj == pi && j < i) {
				dom, err = dom.Difference(cs.Locations[j].Raw, maxStates)
				if err != nil {
					return nil, fmt.Errorf("nginx: longest-prefix difference at line %d: %w", cl.Location.Line, err)
				}
			}
		}

		longestPrefix[i] = dom
		if cl.Location.Modifier == ModCaretTilde {
			// Winning ^~ prefix skips regex evaluation entirely.
			cl.Effective = dom
			allCaretTilde, err = allCaretTilde.Union(dom, maxStates)
			if err != nil {
				return nil, fmt.Errorf("nginx: ^~ union at line %d: %w", cl.Location.Line, err)
			}
		}
	}

	// Step 3: Regex locations (~ and ~*) evaluated in declaration order.
	blockedBeforeRegex, err := allExact.Union(allCaretTilde, maxStates)
	if err != nil {
		return nil, fmt.Errorf("nginx: pre-regex union at server line %d: %w", srv.Line, err)
	}

	priorRegex := automata.Empty()
	for i := range cs.Locations {
		cl := &cs.Locations[i]
		if cl.Unmodeled {
			continue
		}
		if cl.Location.Modifier != ModRegex && cl.Location.Modifier != ModRegexCI {
			continue
		}
		excluded, err := blockedBeforeRegex.Union(priorRegex, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: regex exclusion at line %d: %w", cl.Location.Line, err)
		}
		eff, err := cl.Raw.Difference(excluded, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: regex effective domain at line %d: %w", cl.Location.Line, err)
		}
		cl.Effective = eff
		priorRegex, err = priorRegex.Union(cl.Raw, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: regex union at line %d: %w", cl.Location.Line, err)
		}
	}
	allRegex := priorRegex

	// Step 4: Plain prefix locations win only when no regex matches.
	for _, i := range prefixIndices {
		cl := &cs.Locations[i]
		if cl.Location.Modifier != ModPrefix {
			continue
		}
		eff, err := longestPrefix[i].Difference(allRegex, maxStates)
		if err != nil {
			return nil, fmt.Errorf("nginx: plain-prefix effective domain at line %d: %w", cl.Location.Line, err)
		}
		cl.Effective = eff
	}

	return cs, nil
}
