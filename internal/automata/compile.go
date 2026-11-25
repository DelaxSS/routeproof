package automata

import (
	"errors"
	"fmt"
	"math/bits"
	"regexp/syntax"
	"strings"
	"unicode"
)

// ErrUnsupportedRegex is returned when a pattern uses constructs outside the
// supported regular language + single-level negative lookahead subset.
var ErrUnsupportedRegex = errors.New("automata: unsupported regex feature")

// CompileOptions configures regex compilation.
type CompileOptions struct {
	Anchored        bool // Match the entire string (^...$) instead of any substring.
	CaseInsensitive bool // Fold ASCII case (equivalent to (?i) or Nginx ~*).
	MaxStates       int  // Hard DFA state cap; <= 0 uses DefaultMaxStates.
}

// CompileExact builds a totalized DFA matching only the exact literal string.
// Returns Empty if literal contains any byte outside [MinByte..MaxByte].
func CompileExact(literal string) *DFA {
	for i := 0; i < len(literal); i++ {
		if literal[i] < MinByte || literal[i] > MaxByte {
			return Empty()
		}
	}
	if len(literal) == 0 {
		return &DFA{
			numStates:   2,
			numClasses:  1,
			start:       0,
			transitions: []int{1, 1},
			accept:      []bool{true, false},
		}
	}

	classOf, charClass, numClasses := literalClasses(literal)
	n := len(literal)
	dead := n + 1
	numStates := n + 2
	trans := make([]int, numStates*numClasses)
	for i := range trans {
		trans[i] = dead
	}
	for i := 0; i < n; i++ {
		trans[i*numClasses+int(charClass[i])] = i + 1
	}

	accept := make([]bool, numStates)
	accept[n] = true

	return &DFA{
		numStates:   numStates,
		numClasses:  numClasses,
		start:       0,
		classOf:     classOf,
		transitions: trans,
		accept:      accept,
	}
}

// CompilePrefix builds a totalized DFA matching all strings starting with prefix.
// Returns Empty if prefix contains any byte outside [MinByte..MaxByte].
func CompilePrefix(prefix string) *DFA {
	if len(prefix) == 0 {
		return Universal()
	}
	for i := 0; i < len(prefix); i++ {
		if prefix[i] < MinByte || prefix[i] > MaxByte {
			return Empty()
		}
	}

	classOf, charClass, numClasses := literalClasses(prefix)
	n := len(prefix)
	dead := n + 1
	numStates := n + 2
	trans := make([]int, numStates*numClasses)
	for i := range trans {
		trans[i] = dead
	}
	for i := 0; i < n; i++ {
		trans[i*numClasses+int(charClass[i])] = i + 1
	}
	// Accept state loops on every byte class.
	accBase := n * numClasses
	for c := 0; c < numClasses; c++ {
		trans[accBase+c] = n
	}

	accept := make([]bool, numStates)
	accept[n] = true

	return &DFA{
		numStates:   numStates,
		numClasses:  numClasses,
		start:       0,
		classOf:     classOf,
		transitions: trans,
		accept:      accept,
	}
}

// literalClasses assigns a distinct equivalence class to each unique byte in s
// and groups any remaining alphabet bytes into one "other" class.
func literalClasses(s string) (classOf [AlphabetSize]uint8, charClass []uint8, numClasses int) {
	var seen [AlphabetSize]bool
	var clsMap [AlphabetSize]uint8
	nextClass := uint8(0)
	charClass = make([]uint8, len(s))
	for i := 0; i < len(s); i++ {
		idx := int(s[i] - MinByte)
		if !seen[idx] {
			seen[idx] = true
			clsMap[idx] = nextClass
			nextClass++
		}
		charClass[i] = clsMap[idx]
	}

	if int(nextClass) < AlphabetSize {
		otherClass := nextClass
		nextClass++
		for i := 0; i < AlphabetSize; i++ {
			if seen[i] {
				classOf[i] = clsMap[i]
			} else {
				classOf[i] = otherClass
			}
		}
	} else {
		classOf = clsMap
	}
	return classOf, charClass, int(nextClass)
}

// Compile compiles a Perl-style regular expression into a minimal totalized DFA.
func Compile(pattern string, opts CompileOptions) (*DFA, error) {
	maxStates := normalizeMaxStates(opts.MaxStates)
	hasNegLookahead, err := validateRawSyntax(pattern)
	if err != nil {
		return nil, err
	}
	if !hasNegLookahead {
		return compilePlain(pattern, opts.Anchored, opts.Anchored, opts.CaseInsensitive, maxStates)
	}
	budget := maxLookaheadExpansions
	return compileWithLookahead(pattern, opts.Anchored, opts.Anchored, opts.CaseInsensitive, maxStates, 0, &budget)
}

// validateRawSyntax rejects unsupported PCRE features before regexp/syntax parsing
// and reports whether the pattern contains any negative lookahead (?!...).
func validateRawSyntax(pattern string) (bool, error) {
	hasNegLookahead := false
	inClass := false
	classStart := -1

	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if inClass {
			if ch == '\\' && i+1 < len(pattern) {
				i++
				continue
			}
			// Skip POSIX classes like [:alpha:] inside [...].
			if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
				if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
					i += 2 + end + 1
					continue
				}
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}

		switch ch {
		case '\\':
			if i+1 >= len(pattern) {
				continue
			}
			next := pattern[i+1]
			switch {
			case next >= '1' && next <= '9':
				return false, fmt.Errorf("%w: backreference \\%c", ErrUnsupportedRegex, next)
			case next == 'k' && i+2 < len(pattern) && (pattern[i+2] == '<' || pattern[i+2] == '\'' || pattern[i+2] == '{'):
				return false, fmt.Errorf("%w: named backreference \\k", ErrUnsupportedRegex)
			case next == 'g' && i+2 < len(pattern) && (pattern[i+2] == '{' || pattern[i+2] == '<' || pattern[i+2] == '\'' || pattern[i+2] == '-' || (pattern[i+2] >= '0' && pattern[i+2] <= '9')):
				return false, fmt.Errorf("%w: backreference \\g", ErrUnsupportedRegex)
			case next == 'Q':
				end := strings.Index(pattern[i+2:], `\E`)
				if end < 0 {
					return hasNegLookahead, nil
				}
				i += 2 + end + 1
				continue
			}
			i++

		case '[':
			inClass = true
			classStart = i + 1
			if classStart < len(pattern) && pattern[classStart] == '^' {
				classStart++
			}

		case '(':
			if i+1 >= len(pattern) {
				continue
			}
			if pattern[i+1] == '*' {
				return false, fmt.Errorf("%w: PCRE verb (*...)", ErrUnsupportedRegex)
			}
			if pattern[i+1] != '?' {
				continue
			}
			rest := pattern[i+2:]
			switch {
			case strings.HasPrefix(rest, "="):
				return false, fmt.Errorf("%w: positive lookahead (?=...)", ErrUnsupportedRegex)
			case strings.HasPrefix(rest, "<="):
				return false, fmt.Errorf("%w: positive lookbehind (?<=...)", ErrUnsupportedRegex)
			case strings.HasPrefix(rest, "<!"):
				return false, fmt.Errorf("%w: negative lookbehind (?<!...)", ErrUnsupportedRegex)
			case strings.HasPrefix(rest, "P="):
				return false, fmt.Errorf("%w: named backreference (?P=...)", ErrUnsupportedRegex)
			case strings.HasPrefix(rest, "("):
				return false, fmt.Errorf("%w: conditional group (?(...))", ErrUnsupportedRegex)
			case strings.HasPrefix(rest, "#"):
				return false, fmt.Errorf("%w: inline comment (?#...)", ErrUnsupportedRegex)
			case strings.HasPrefix(rest, "!"):
				hasNegLookahead = true
			}
		}
	}
	return hasNegLookahead, nil
}

type seqTokenKind uint8

const (
	tokPlain seqTokenKind = iota
	tokNegLookahead
	tokGroup
	tokFlagOnly
)

type seqToken struct {
	kind       seqTokenKind
	raw        string
	body       string
	flagSet    string // flag spec for (?flags) or (?flags:...)
	quantified bool
}

const (
	maxLookaheadDepth      = 16
	maxLookaheadExpansions = 256
	maxNFANodes            = 16384
	maxSubsetWords         = 4_000_000
)

func compileWithLookahead(pattern string, startAnchored, endAnchored, caseInsensitive bool, maxStates, depth int, budget *int) (*DFA, error) {
	if depth > maxLookaheadDepth {
		return nil, fmt.Errorf("%w: negative lookahead nesting limit exceeded", ErrUnsupportedRegex)
	}

	branches, err := splitTopLevelAlternation(pattern)
	if err != nil {
		return nil, err
	}
	if len(branches) > 1 {
		var acc *DFA
		curFold := caseInsensitive
		for _, br := range branches {
			if *budget <= 0 {
				return nil, ErrStateLimit
			}
			*budget--
			d, err := compileWithLookahead(br, startAnchored, endAnchored, curFold, maxStates, depth+1, budget)
			if err != nil {
				return nil, err
			}
			if acc == nil {
				acc = d
			} else {
				acc, err = acc.Union(d, maxStates)
				if err != nil {
					return nil, err
				}
			}
			curFold, err = advanceBranchCaseFlag(curFold, br)
			if err != nil {
				return nil, err
			}
		}
		return acc, nil
	}

	if !containsNegLookahead(pattern) {
		return compilePlain(pattern, startAnchored, endAnchored, caseInsensitive, maxStates)
	}

	tokens, err := parseSequence(pattern)
	if err != nil {
		return nil, err
	}

	activeFold := caseInsensitive
	for i, tok := range tokens {
		switch tok.kind {
		case tokFlagOnly:
			activeFold = applyCaseFlag(activeFold, tok.flagSet)

		case tokGroup:
			if !containsNegLookahead(tok.body) {
				continue
			}
			if tok.quantified {
				return nil, fmt.Errorf("%w: negative lookahead inside quantified group", ErrUnsupportedRegex)
			}
			before := joinTokenRaw(tokens[:i])
			after := joinTokenRaw(tokens[i+1:])
			restore := ""
			if after != "" {
				if activeFold {
					restore = "(?i)"
				} else {
					restore = "(?-i)"
				}
			}
			innerPrefix := ""
			groupFold := activeFold
			if tok.flagSet != "" {
				innerPrefix = "(?" + tok.flagSet + ")"
				groupFold = applyCaseFlag(groupFold, tok.flagSet)
			}

			subBranches, err := splitTopLevelAlternation(tok.body)
			if err != nil {
				return nil, err
			}
			var acc *DFA
			curFold := groupFold
			for _, sb := range subBranches {
				if *budget <= 0 {
					return nil, ErrStateLimit
				}
				*budget--
				branchFoldPrefix := "(?-i)"
				if curFold {
					branchFoldPrefix = "(?i)"
				}
				expanded := before + innerPrefix + branchFoldPrefix + sb + restore + after
				d, err := compileWithLookahead(expanded, startAnchored, endAnchored, caseInsensitive, maxStates, depth+1, budget)
				if err != nil {
					return nil, err
				}
				if acc == nil {
					acc = d
				} else {
					acc, err = acc.Union(d, maxStates)
					if err != nil {
						return nil, err
					}
				}
				curFold, err = advanceBranchCaseFlag(curFold, sb)
				if err != nil {
					return nil, err
				}
			}
			return acc, nil

		case tokNegLookahead:
			if tok.quantified {
				return nil, fmt.Errorf("%w: quantified negative lookahead", ErrUnsupportedRegex)
			}
			if containsNegLookahead(tok.body) {
				return nil, fmt.Errorf("%w: nested negative lookahead", ErrUnsupportedRegex)
			}

			prefixPat := joinTokenRaw(tokens[:i])
			negPat := tok.body
			suffixPat := joinTokenRaw(tokens[i+1:])

			if hasEndAnchor(prefixPat) {
				return nil, fmt.Errorf("%w: end anchor before negative lookahead", ErrUnsupportedRegex)
			}

			dPrefix, err := compilePlain(prefixPat, startAnchored, true, caseInsensitive, maxStates)
			if err != nil {
				return nil, err
			}
			if dPrefix.IsEmpty() {
				return Empty(), nil
			}
			if !dPrefix.onlyEmpty() && (hasStartAnchor(negPat) || hasStartAnchor(suffixPat)) {
				return nil, fmt.Errorf("%w: start anchor after non-empty prefix with negative lookahead", ErrUnsupportedRegex)
			}

			// Exact formal semantics: L((?!R)S) = L(S) \ (L(R) · Σ*).
			dNeg, err := compilePlain(negPat, true, false, activeFold, maxStates)
			if err != nil {
				return nil, err
			}
			dSuffix, err := compileWithLookahead(suffixPat, true, endAnchored, activeFold, maxStates, depth+1, budget)
			if err != nil {
				return nil, err
			}

			tail, err := dSuffix.Difference(dNeg, maxStates)
			if err != nil {
				return nil, err
			}
			if dPrefix.onlyEmpty() {
				return tail, nil
			}
			return dPrefix.Concat(tail, maxStates)
		}
	}

	return compilePlain(pattern, startAnchored, endAnchored, caseInsensitive, maxStates)
}

func advanceBranchCaseFlag(current bool, branch string) (bool, error) {
	tokens, err := parseSequence(branch)
	if err != nil {
		return current, err
	}
	for _, tok := range tokens {
		if tok.kind == tokFlagOnly {
			current = applyCaseFlag(current, tok.flagSet)
		}
	}
	return current, nil
}

func joinTokenRaw(tokens []seqToken) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteString(t.raw)
	}
	return b.String()
}

func applyCaseFlag(current bool, flagSet string) bool {
	neg := false
	for i := 0; i < len(flagSet); i++ {
		switch flagSet[i] {
		case '-':
			neg = true
		case 'i':
			current = !neg
		}
	}
	return current
}

func containsNegLookahead(pattern string) bool {
	inClass := false
	classStart := -1
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if inClass {
			if ch == '\\' && i+1 < len(pattern) {
				i++
				continue
			}
			if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
				if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
					i += 2 + end + 1
					continue
				}
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}
		if ch == '\\' && i+1 < len(pattern) {
			if pattern[i+1] == 'Q' {
				end := strings.Index(pattern[i+2:], `\E`)
				if end < 0 {
					return false
				}
				i += 2 + end + 1
				continue
			}
			i++
			continue
		}
		if ch == '[' {
			inClass = true
			classStart = i + 1
			if classStart < len(pattern) && pattern[classStart] == '^' {
				classStart++
			}
			continue
		}
		if ch == '(' && strings.HasPrefix(pattern[i:], "(?!") {
			return true
		}
	}
	return false
}

func splitTopLevelAlternation(pattern string) ([]string, error) {
	var parts []string
	depth := 0
	inClass := false
	classStart := -1
	start := 0

	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if inClass {
			if ch == '\\' && i+1 < len(pattern) {
				i++
				continue
			}
			if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
				if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
					i += 2 + end + 1
					continue
				}
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}
		switch ch {
		case '\\':
			if i+1 < len(pattern) {
				if pattern[i+1] == 'Q' {
					end := strings.Index(pattern[i+2:], `\E`)
					if end < 0 {
						i = len(pattern)
						continue
					}
					i += 2 + end + 1
					continue
				}
				i++
			}
		case '[':
			inClass = true
			classStart = i + 1
			if classStart < len(pattern) && pattern[classStart] == '^' {
				classStart++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("automata: unmatched ')' in regex %q", pattern)
			}
		case '|':
			if depth == 0 {
				parts = append(parts, pattern[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 || inClass {
		return nil, fmt.Errorf("automata: unclosed group or character class in regex %q", pattern)
	}
	parts = append(parts, pattern[start:])
	return parts, nil
}

// parseSequence splits a single alternation branch into top-level tokens.
func parseSequence(pattern string) ([]seqToken, error) {
	var tokens []seqToken
	i := 0
	for i < len(pattern) {
		start := i
		ch := pattern[i]

		if ch == '\\' {
			if i+1 < len(pattern) {
				if pattern[i+1] == 'Q' {
					end := strings.Index(pattern[i+2:], `\E`)
					if end < 0 {
						i = len(pattern)
					} else {
						i += 2 + end + 2
					}
				} else {
					i += 2
				}
			} else {
				i++
			}
			end, _ := consumeQuantifier(pattern, i)
			tokens = append(tokens, seqToken{kind: tokPlain, raw: pattern[start:end]})
			i = end
			continue
		}

		if ch == '[' {
			endClass, err := scanCharClassEnd(pattern, i)
			if err != nil {
				return nil, err
			}
			end, _ := consumeQuantifier(pattern, endClass)
			tokens = append(tokens, seqToken{kind: tokPlain, raw: pattern[start:end]})
			i = end
			continue
		}

		if ch == '(' {
			closeIdx, err := scanGroupEnd(pattern, i)
			if err != nil {
				return nil, err
			}
			end, quant := consumeQuantifier(pattern, closeIdx+1)
			raw := pattern[start:end]
			inner := pattern[i+1 : closeIdx]

			if strings.HasPrefix(inner, "?!") {
				tokens = append(tokens, seqToken{
					kind:       tokNegLookahead,
					raw:        raw,
					body:       inner[2:],
					quantified: quant,
				})
				i = end
				continue
			}

			if strings.HasPrefix(inner, "?") {
				if kind, flagSet, body, ok := parseGroupHeader(inner); ok {
					tokens = append(tokens, seqToken{
						kind:       kind,
						raw:        raw,
						body:       body,
						flagSet:    flagSet,
						quantified: quant,
					})
					i = end
					continue
				}
			}

			tokens = append(tokens, seqToken{
				kind:       tokGroup,
				raw:        raw,
				body:       inner,
				quantified: quant,
			})
			i = end
			continue
		}

		i++
		end, _ := consumeQuantifier(pattern, i)
		tokens = append(tokens, seqToken{kind: tokPlain, raw: pattern[start:end]})
		i = end
	}
	return tokens, nil
}

// parseGroupHeader classifies (?...) group interiors (excluding lookarounds).
func parseGroupHeader(inner string) (seqTokenKind, string, string, bool) {
	rest := inner[1:] // strip leading '?'
	if strings.HasPrefix(rest, ":") {
		return tokGroup, "", rest[1:], true
	}
	if strings.HasPrefix(rest, "P<") {
		if gt := strings.IndexByte(rest, '>'); gt > 2 {
			return tokGroup, "", rest[gt+1:], true
		}
	}
	if strings.HasPrefix(rest, "<") && len(rest) > 1 && rest[1] != '=' && rest[1] != '!' {
		if gt := strings.IndexByte(rest, '>'); gt > 1 {
			return tokGroup, "", rest[gt+1:], true
		}
	}
	// Inline flags: (?imsU-imsU) or (?imsU-imsU:body)
	j := 0
	for j < len(rest) && (rest[j] == 'i' || rest[j] == 'm' || rest[j] == 's' || rest[j] == 'U' || rest[j] == '-') {
		j++
	}
	if j > 0 && j == len(rest) {
		return tokFlagOnly, rest, "", true
	}
	if j > 0 && j < len(rest) && rest[j] == ':' {
		return tokGroup, rest[:j], rest[j+1:], true
	}
	return tokGroup, "", inner, false
}

func scanCharClassEnd(pattern string, open int) (int, error) {
	i := open + 1
	if i < len(pattern) && pattern[i] == '^' {
		i++
	}
	first := i
	for i < len(pattern) {
		ch := pattern[i]
		if ch == '\\' && i+1 < len(pattern) {
			i += 2
			continue
		}
		if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
			if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
				i += 2 + end + 2
				continue
			}
		}
		if ch == ']' && i > first {
			return i + 1, nil
		}
		i++
	}
	return 0, fmt.Errorf("automata: unclosed character class in regex %q", pattern)
}

func scanGroupEnd(pattern string, open int) (int, error) {
	depth := 1
	inClass := false
	classStart := -1
	for i := open + 1; i < len(pattern); i++ {
		ch := pattern[i]
		if inClass {
			if ch == '\\' && i+1 < len(pattern) {
				i++
				continue
			}
			if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
				if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
					i += 2 + end + 1
					continue
				}
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}
		switch ch {
		case '\\':
			if i+1 < len(pattern) {
				if pattern[i+1] == 'Q' {
					end := strings.Index(pattern[i+2:], `\E`)
					if end < 0 {
						return 0, fmt.Errorf("automata: unclosed '(' in regex %q", pattern)
					}
					i += 2 + end + 1
					continue
				}
				i++
			}
		case '[':
			inClass = true
			classStart = i + 1
			if classStart < len(pattern) && pattern[classStart] == '^' {
				classStart++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("automata: unclosed '(' in regex %q", pattern)
}

func consumeQuantifier(pattern string, i int) (int, bool) {
	if i >= len(pattern) {
		return i, false
	}
	switch pattern[i] {
	case '*', '+', '?':
		i++
		if i < len(pattern) && pattern[i] == '?' {
			i++
		}
		return i, true
	case '{':
		// Match {m}, {m,}, or {m,n}.
		j := i + 1
		digits := 0
		for j < len(pattern) && pattern[j] >= '0' && pattern[j] <= '9' {
			j++
			digits++
		}
		if digits == 0 || j >= len(pattern) {
			return i, false
		}
		if pattern[j] == ',' {
			j++
			for j < len(pattern) && pattern[j] >= '0' && pattern[j] <= '9' {
				j++
			}
		}
		if j < len(pattern) && pattern[j] == '}' {
			j++
			if j < len(pattern) && pattern[j] == '?' {
				j++
			}
			return j, true
		}
	}
	return i, false
}

func hasStartAnchor(pattern string) bool {
	return hasAnchor(pattern, '^', 'A')
}

// normalizeNamedCaptures rewrites PCRE (?<name>...) groups to Go's (?P<name>...) form.
func normalizeNamedCaptures(pattern string) string {
	if !strings.Contains(pattern, "(?<") {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern) + 8)
	inClass := false
	classStart := -1
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if inClass {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(pattern) {
				i++
				b.WriteByte(pattern[i])
				continue
			}
			if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
				if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
					b.WriteString(pattern[i+1 : i+2+end+2])
					i += 2 + end + 1
					continue
				}
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}
		if ch == '\\' && i+1 < len(pattern) {
			if pattern[i+1] == 'Q' {
				end := strings.Index(pattern[i+2:], `\E`)
				if end < 0 {
					b.WriteString(pattern[i:])
					break
				}
				b.WriteString(pattern[i : i+2+end+2])
				i += 2 + end + 1
				continue
			}
			b.WriteByte(ch)
			i++
			b.WriteByte(pattern[i])
			continue
		}
		if ch == '[' {
			inClass = true
			classStart = i + 1
			if classStart < len(pattern) && pattern[classStart] == '^' {
				classStart++
			}
			b.WriteByte(ch)
			continue
		}
		if ch == '(' && i+3 < len(pattern) && pattern[i+1] == '?' && pattern[i+2] == '<' &&
			pattern[i+3] != '=' && pattern[i+3] != '!' {
			if gt := strings.IndexByte(pattern[i+3:], '>'); gt > 0 {
				b.WriteString("(?P<")
				i += 2
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func hasEndAnchor(pattern string) bool {
	return hasAnchor(pattern, '$', 'z')
}

func hasAnchor(pattern string, meta byte, esc byte) bool {
	inClass := false
	classStart := -1
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if inClass {
			if ch == '\\' && i+1 < len(pattern) {
				i++
				continue
			}
			if ch == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
				if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
					i += 2 + end + 1
					continue
				}
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}
		if ch == '\\' && i+1 < len(pattern) {
			if pattern[i+1] == 'Q' {
				end := strings.Index(pattern[i+2:], `\E`)
				if end < 0 {
					return false
				}
				i += 2 + end + 1
				continue
			}
			if pattern[i+1] == esc {
				return true
			}
			i++
			continue
		}
		if ch == '[' {
			inClass = true
			classStart = i + 1
			if classStart < len(pattern) && pattern[classStart] == '^' {
				classStart++
			}
			continue
		}
		if ch == meta {
			return true
		}
	}
	return false
}

// --- NFA construction & subset construction ---

type nfaEdge struct {
	set byteSet
	to  int
}

type nfaState struct {
	eps      []int
	beginEps []int
	endEps   []int
	edges    []nfaEdge
}

type nfa struct {
	states      []nfaState
	hasBeginEps bool
	hasEndEps   bool
	maxNodes    int
}

func (n *nfa) addState() (int, error) {
	if n.maxNodes > 0 && len(n.states) >= n.maxNodes {
		return -1, ErrStateLimit
	}
	id := len(n.states)
	n.states = append(n.states, nfaState{})
	return id, nil
}

func (n *nfa) addEps(from, to int) {
	n.states[from].eps = append(n.states[from].eps, to)
}

func (n *nfa) addBeginEps(from, to int) {
	n.states[from].beginEps = append(n.states[from].beginEps, to)
	n.hasBeginEps = true
}

func (n *nfa) addEndEps(from, to int) {
	n.states[from].endEps = append(n.states[from].endEps, to)
	n.hasEndEps = true
}

func (n *nfa) addEdge(from, to int, set byteSet) {
	if set.isEmpty() {
		return
	}
	n.states[from].edges = append(n.states[from].edges, nfaEdge{set: set, to: to})
}

func compilePlain(pattern string, startAnchored, endAnchored, caseInsensitive bool, maxStates int) (*DFA, error) {
	flags := syntax.Perl
	if caseInsensitive {
		flags |= syntax.FoldCase
	}
	re, err := syntax.Parse(normalizeNamedCaptures(pattern), flags)
	if err != nil {
		return nil, fmt.Errorf("automata: invalid regex %q: %w", pattern, err)
	}

	nodeCap := maxStates * 2
	if nodeCap < 4096 {
		nodeCap = 4096
	}
	if nodeCap > maxNFANodes {
		nodeCap = maxNFANodes
	}
	m := &nfa{maxNodes: nodeCap}
	fragStart, fragEnd, err := m.buildRegexp(re)
	if err != nil {
		return nil, err
	}

	nfaStart := fragStart
	if !startAnchored {
		pre, err := m.addState()
		if err != nil {
			return nil, err
		}
		m.addEdge(pre, pre, allByteSet())
		m.addEps(pre, fragStart)
		nfaStart = pre
	}

	nfaAccept := fragEnd
	if !endAnchored {
		post, err := m.addState()
		if err != nil {
			return nil, err
		}
		m.addEdge(post, post, allByteSet())
		m.addEps(fragEnd, post)
		nfaAccept = post
	}

	return subsetConstruct(m, nfaStart, nfaAccept, maxStates)
}

func (n *nfa) buildRegexp(re *syntax.Regexp) (int, int, error) {
	switch re.Op {
	case syntax.OpNoMatch:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		return s, e, nil

	case syntax.OpEmptyMatch:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		return s, s, nil

	case syntax.OpLiteral:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		cur := s
		fold := re.Flags&syntax.FoldCase != 0
		for _, r := range re.Rune {
			next, err := n.addState()
			if err != nil {
				return 0, 0, err
			}
			n.addEdge(cur, next, runeByteSet(r, fold))
			cur = next
		}
		return s, cur, nil

	case syntax.OpCharClass:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEdge(s, e, charClassByteSet(re.Rune))
		return s, e, nil

	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEdge(s, e, allByteSet())
		return s, e, nil

	case syntax.OpBeginLine, syntax.OpBeginText:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addBeginEps(s, e)
		return s, e, nil

	case syntax.OpEndLine, syntax.OpEndText:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEndEps(s, e)
		return s, e, nil

	case syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, 0, fmt.Errorf("%w: word boundary assertion", ErrUnsupportedRegex)

	case syntax.OpCapture:
		return n.buildRegexp(re.Sub[0])

	case syntax.OpStar:
		subS, subE, err := n.buildRegexp(re.Sub[0])
		if err != nil {
			return 0, 0, err
		}
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEps(s, subS)
		n.addEps(s, e)
		n.addEps(subE, subS)
		n.addEps(subE, e)
		return s, e, nil

	case syntax.OpPlus:
		subS, subE, err := n.buildRegexp(re.Sub[0])
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEps(subE, subS)
		n.addEps(subE, e)
		return subS, e, nil

	case syntax.OpQuest:
		subS, subE, err := n.buildRegexp(re.Sub[0])
		if err != nil {
			return 0, 0, err
		}
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEps(s, subS)
		n.addEps(s, e)
		n.addEps(subE, e)
		return s, e, nil

	case syntax.OpRepeat:
		return n.buildRepeat(re.Sub[0], re.Min, re.Max)

	case syntax.OpConcat:
		if len(re.Sub) == 0 {
			s, err := n.addState()
			if err != nil {
				return 0, 0, err
			}
			return s, s, nil
		}
		start, curEnd, err := n.buildRegexp(re.Sub[0])
		if err != nil {
			return 0, 0, err
		}
		for _, sub := range re.Sub[1:] {
			s, e, err := n.buildRegexp(sub)
			if err != nil {
				return 0, 0, err
			}
			n.addEps(curEnd, s)
			curEnd = e
		}
		return start, curEnd, nil

	case syntax.OpAlternate:
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		for _, sub := range re.Sub {
			subS, subE, err := n.buildRegexp(sub)
			if err != nil {
				return 0, 0, err
			}
			n.addEps(s, subS)
			n.addEps(subE, e)
		}
		return s, e, nil

	default:
		return 0, 0, fmt.Errorf("%w: syntax op %v", ErrUnsupportedRegex, re.Op)
	}
}

func (n *nfa) buildRepeat(sub *syntax.Regexp, minRep, maxRep int) (int, int, error) {
	if maxRep >= 0 && maxRep < minRep {
		s, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		e, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		return s, e, nil
	}

	start, err := n.addState()
	if err != nil {
		return 0, 0, err
	}
	cur := start

	for i := 0; i < minRep; i++ {
		s, e, err := n.buildRegexp(sub)
		if err != nil {
			return 0, 0, err
		}
		n.addEps(cur, s)
		cur = e
	}

	if maxRep == -1 {
		subS, subE, err := n.buildRegexp(sub)
		if err != nil {
			return 0, 0, err
		}
		end, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEps(cur, subS)
		n.addEps(cur, end)
		n.addEps(subE, subS)
		n.addEps(subE, end)
		return start, end, nil
	}

	if maxRep > minRep {
		end, err := n.addState()
		if err != nil {
			return 0, 0, err
		}
		n.addEps(cur, end)
		for i := minRep; i < maxRep; i++ {
			s, e, err := n.buildRegexp(sub)
			if err != nil {
				return 0, 0, err
			}
			n.addEps(cur, s)
			n.addEps(e, end)
			cur = e
		}
		return start, end, nil
	}

	return start, cur, nil
}

func runeByteSet(r rune, fold bool) byteSet {
	var bs byteSet
	if !fold {
		if r >= rune(MinByte) && r <= rune(MaxByte) {
			bs.set(byte(r))
		}
		return bs
	}
	cur := r
	for {
		if cur >= rune(MinByte) && cur <= rune(MaxByte) {
			bs.set(byte(cur))
		}
		next := unicode.SimpleFold(cur)
		if next == r {
			break
		}
		cur = next
	}
	return bs
}

func charClassByteSet(ranges []rune) byteSet {
	var bs byteSet
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if hi < rune(MinByte) || lo > rune(MaxByte) {
			continue
		}
		if lo < rune(MinByte) {
			lo = rune(MinByte)
		}
		if hi > rune(MaxByte) {
			hi = rune(MaxByte)
		}
		for r := lo; r <= hi; r++ {
			bs.set(byte(r))
		}
	}
	return bs
}

// partitionAlphabet computes the coarsest byte equivalence classes induced by NFA edges.
func partitionAlphabet(m *nfa) (classOf [AlphabetSize]uint8, repByte []byte, numClasses int) {
	all := allByteSet()
	blocks := []byteSet{all}

	for i := range m.states {
		for _, edge := range m.states[i].edges {
			if edge.set.isEmpty() || edge.set == all {
				continue
			}
			n := len(blocks)
			for j := 0; j < n; j++ {
				in := blocks[j].and(edge.set)
				if in.isEmpty() {
					continue
				}
				out := blocks[j].andNot(edge.set)
				if out.isEmpty() {
					continue
				}
				blocks[j] = out
				blocks = append(blocks, in)
			}
			if len(blocks) == AlphabetSize {
				goto done
			}
		}
	}

done:
	numClasses = len(blocks)
	repByte = make([]byte, numClasses)
	for c, blk := range blocks {
		repByte[c] = blk.firstByte()
		for i := 0; i < AlphabetSize; i++ {
			if blk.has(MinByte + byte(i)) {
				classOf[i] = uint8(c)
			}
		}
	}
	return classOf, repByte, numClasses
}

func subsetConstruct(m *nfa, startState, acceptState, maxStates int) (*DFA, error) {
	classOf, repByte, numClasses := partitionAlphabet(m)
	numNFA := len(m.states)
	words := (numNFA + 63) / 64

	stack := make([]int, 0, 64)
	closure := func(seed []uint64, followBegin, followEnd bool) []uint64 {
		res := make([]uint64, words)
		copy(res, seed)
		stack = stack[:0]
		for w, val := range res {
			for val != 0 {
				tz := bits.TrailingZeros64(val)
				stack = append(stack, w*64+tz)
				val &= val - 1
			}
		}
		for len(stack) > 0 {
			u := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			st := &m.states[u]
			for _, v := range st.eps {
				if (res[v/64] & (1 << (v % 64))) == 0 {
					res[v/64] |= 1 << (v % 64)
					stack = append(stack, v)
				}
			}
			if followBegin {
				for _, v := range st.beginEps {
					if (res[v/64] & (1 << (v % 64))) == 0 {
						res[v/64] |= 1 << (v % 64)
						stack = append(stack, v)
					}
				}
			}
			if followEnd {
				for _, v := range st.endEps {
					if (res[v/64] & (1 << (v % 64))) == 0 {
						res[v/64] |= 1 << (v % 64)
						stack = append(stack, v)
					}
				}
			}
		}
		return res
	}

	isAccepting := func(set []uint64, atStart bool) bool {
		if (set[acceptState/64] & (1 << (acceptState % 64))) != 0 {
			return true
		}
		if !m.hasEndEps {
			return false
		}
		endSet := closure(set, atStart && m.hasBeginEps, true)
		return (endSet[acceptState/64] & (1 << (acceptState % 64))) != 0
	}

	keyBuf := make([]byte, words*8)
	encodeKey := func(set []uint64) []byte {
		for i, w := range set {
			off := i * 8
			keyBuf[off] = byte(w)
			keyBuf[off+1] = byte(w >> 8)
			keyBuf[off+2] = byte(w >> 16)
			keyBuf[off+3] = byte(w >> 24)
			keyBuf[off+4] = byte(w >> 32)
			keyBuf[off+5] = byte(w >> 40)
			keyBuf[off+6] = byte(w >> 48)
			keyBuf[off+7] = byte(w >> 56)
		}
		return keyBuf
	}

	seed := make([]uint64, words)
	seed[startState/64] |= 1 << (startState % 64)
	startSet := closure(seed, m.hasBeginEps, false)
	startAcc := isAccepting(startSet, true)
	nonStartAcc := isAccepting(startSet, false)

	seen := make(map[string]int, 64)
	if startAcc == nonStartAcc {
		seen[string(encodeKey(startSet))] = 0
	}

	dfaSets := [][]uint64{startSet}
	accept := []bool{startAcc}
	transitions := make([]int, numClasses)
	moved := make([]uint64, words)

	for id := 0; id < len(dfaSets); id++ {
		curSet := dfaSets[id]
		base := id * numClasses
		for c := 0; c < numClasses; c++ {
			clear(moved)
			b := repByte[c]
			for w, val := range curSet {
				for val != 0 {
					tz := bits.TrailingZeros64(val)
					u := w*64 + tz
					val &= val - 1
					for _, edge := range m.states[u].edges {
						if edge.set.has(b) {
							moved[edge.to/64] |= 1 << (edge.to % 64)
						}
					}
				}
			}
			nextSet := closure(moved, false, false)
			k := encodeKey(nextSet)
			nextID, ok := seen[string(k)]
			if !ok {
				if len(dfaSets) >= maxStates || (len(dfaSets)+1)*words > maxSubsetWords {
					return nil, ErrStateLimit
				}
				nextID = len(dfaSets)
				seen[string(k)] = nextID
				dfaSets = append(dfaSets, nextSet)
				accept = append(accept, isAccepting(nextSet, false))
				transitions = append(transitions, make([]int, numClasses)...)
			}
			transitions[base+c] = nextID
		}
	}

	res := &DFA{
		numStates:   len(dfaSets),
		numClasses:  numClasses,
		start:       0,
		classOf:     classOf,
		transitions: transitions,
		accept:      accept,
	}
	return res.Minimize(), nil
}

func concatDFAs(a, b *DFA, maxStates int) (*DFA, error) {
	classSetsA := dfaClassByteSets(a)
	classSetsB := dfaClassByteSets(b)

	off := a.numStates
	acceptState := a.numStates + b.numStates
	m := &nfa{
		states: make([]nfaState, acceptState+1),
	}

	for s := 0; s < a.numStates; s++ {
		base := s * a.numClasses
		for c := 0; c < a.numClasses; c++ {
			m.addEdge(s, a.transitions[base+c], classSetsA[c])
		}
		if a.accept[s] {
			m.addEps(s, off+b.start)
		}
	}

	for s := 0; s < b.numStates; s++ {
		base := s * b.numClasses
		for c := 0; c < b.numClasses; c++ {
			m.addEdge(off+s, off+b.transitions[base+c], classSetsB[c])
		}
		if b.accept[s] {
			m.addEps(off+s, acceptState)
		}
	}

	return subsetConstruct(m, a.start, acceptState, maxStates)
}

func dfaClassByteSets(d *DFA) []byteSet {
	sets := make([]byteSet, d.numClasses)
	for i := 0; i < AlphabetSize; i++ {
		sets[d.classOf[i]].set(MinByte + byte(i))
	}
	return sets
}
