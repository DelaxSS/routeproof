package nextjs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"routeproof/internal/automata"
)

// ErrNoMiddleware is returned when no Next.js middleware file is found in a project.
var ErrNoMiddleware = errors.New("nextjs: middleware file not found")

// MatcherEntry represents a single parsed entry from config.matcher.
type MatcherEntry struct {
	Raw         string        `json:"raw"`
	Regex       string        `json:"regex,omitempty"`
	Line        int           `json:"line"`
	Conditional bool          `json:"conditional,omitempty"`
	Unmodeled   bool          `json:"unmodeled,omitempty"`
	DFA         *automata.DFA `json:"-"`
}

// Middleware represents the parsed Next.js middleware configuration and signals.
type Middleware struct {
	File               string         `json:"file"`
	HasExplicitMatcher bool           `json:"has_explicit_matcher"`
	HasDynamicMatcher  bool           `json:"has_dynamic_matcher"`
	Matchers           []MatcherEntry `json:"matchers"`
	Coverage           *automata.DFA  `json:"-"`
	HasAuthSignal      bool           `json:"has_auth_signal"`
	AuthSignals        []string       `json:"auth_signals"`
	Warnings           []Warning      `json:"warnings"`
}

var middlewareCandidates = []string{
	"middleware.ts",
	"middleware.js",
	filepath.Join("src", "middleware.ts"),
	filepath.Join("src", "middleware.js"),
}

// FindMiddleware locates middleware.{ts,js} matching Next.js's src/ directory rules:
// if routes exist under root app/ or pages/, only root middleware is checked;
// if routes exist only under src/app/ or src/pages/, only src/middleware is checked.
func FindMiddleware(rootDir string) (string, bool) {
	_, hasRootApp := firstExistingDir(rootDir, "app")
	_, hasRootPages := firstExistingDir(rootDir, "pages")
	_, hasSrcApp := firstExistingDir(rootDir, filepath.Join("src", "app"))
	_, hasSrcPages := firstExistingDir(rootDir, filepath.Join("src", "pages"))

	candidates := middlewareCandidates
	if hasRootApp || hasRootPages {
		candidates = []string{"middleware.ts", "middleware.js"}
	} else if hasSrcApp || hasSrcPages {
		candidates = []string{filepath.Join("src", "middleware.ts"), filepath.Join("src", "middleware.js")}
	}

	for _, rel := range candidates {
		full := filepath.Join(rootDir, rel)
		info, err := os.Stat(full)
		if err == nil && !info.IsDir() {
			return full, true
		}
	}
	return "", false
}

// LoadMiddleware locates and parses the project's Next.js middleware file.
func LoadMiddleware(rootDir string, maxStates int) (*Middleware, error) {
	path, ok := FindMiddleware(rootDir)
	if !ok {
		return nil, ErrNoMiddleware
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(rootDir, path)
	if err != nil {
		rel = path
	}
	return ParseMiddleware(filepath.ToSlash(rel), string(data), maxStates)
}

// ParseMiddleware parses a Next.js middleware source string into a Middleware model.
func ParseMiddleware(filePath, src string, maxStates int) (*Middleware, error) {
	if maxStates <= 0 {
		maxStates = automata.DefaultMaxStates
	}

	src = strings.TrimPrefix(src, "\xef\xbb\xbf")
	tokens := lexJS(src)

	mw := &Middleware{
		File:        filePath,
		Matchers:    []MatcherEntry{},
		AuthSignals: []string{},
		Warnings:    []Warning{},
	}

	cfgStart, cfgEnd, objStart, objEnd, dynLine, status := findConfigObject(tokens)
	switch status {
	case configObjectStatic:
		parseConfigObject(mw, tokens, objStart, objEnd, maxStates)
	case configObjectDynamic:
		mw.HasExplicitMatcher = true
		mw.HasDynamicMatcher = true
		mw.Warnings = append(mw.Warnings, Warning{
			Kind:    WarnUnsupported,
			File:    mw.File,
			Line:    dynLine,
			Context: "config",
			Message: "dynamic middleware config export is not modeled",
		})
	}

	if !mw.HasExplicitMatcher {
		// Without config.matcher, Next.js runs middleware on all routes (^/.*).
		mw.Coverage = automata.CompilePrefix("/")
	} else {
		cov := automata.Empty()
		for i := range mw.Matchers {
			entry := &mw.Matchers[i]
			// Conditional matchers (has/missing) can be bypassed by omitting/adding headers/cookies/queries.
			if entry.Unmodeled || entry.Conditional || entry.DFA == nil {
				continue
			}
			nextCov, err := cov.Union(entry.DFA, maxStates)
			if err != nil {
				if errors.Is(err, automata.ErrStateLimit) {
					mw.Warnings = append(mw.Warnings, Warning{
						Kind:    WarnStateLimit,
						File:    mw.File,
						Line:    entry.Line,
						Context: entry.Raw,
						Message: err.Error(),
					})
					continue
				}
				return nil, err
			}
			cov = nextCov
		}
		mw.Coverage = cov
	}

	mw.AuthSignals = detectAuthSignals(tokens, cfgStart, cfgEnd)
	mw.HasAuthSignal = len(mw.AuthSignals) > 0

	return mw, nil
}

// MatcherToRegex converts a Next.js path-to-regexp matcher string into an anchored regex.
func MatcherToRegex(pattern string) (string, error) {
	if pattern == "" {
		return "", errors.New("nextjs: empty matcher pattern")
	}

	var b strings.Builder
	b.WriteByte('^')

	i := 0
	n := len(pattern)
	for i < n {
		ch := pattern[i]

		// Escaped literal outside custom regex groups.
		if ch == '\\' && i+1 < n {
			b.WriteString(regexp.QuoteMeta(string(pattern[i+1])))
			i += 2
			continue
		}

		// Slash-prefixed optional/repeated anonymous regex group: /admin/(settings)? or /(en|fr)?/admin.
		if ch == '/' && i+1 < n && pattern[i+1] == '(' {
			closeIdx, err := scanBalancedParen(pattern, i+1)
			if err != nil {
				return "", err
			}
			if closeIdx+1 < n && (pattern[closeIdx+1] == '?' || pattern[closeIdx+1] == '*') {
				mod := pattern[closeIdx+1]
				onlyRoot := i == 0 && closeIdx+2 == n
				if !onlyRoot {
					b.WriteString("(?:/")
					b.WriteString(pattern[i+1 : closeIdx+1])
					b.WriteByte(')')
					b.WriteByte(mod)
					i = closeIdx + 2
					continue
				}
			}
		}

		// Standalone custom regex group (...), e.g. /((?!_next/static|.*\..*).*).
		if ch == '(' {
			closeIdx, err := scanBalancedParen(pattern, i)
			if err != nil {
				return "", err
			}
			b.WriteString(pattern[i : closeIdx+1])
			i = closeIdx + 1
			if i < n && (pattern[i] == '*' || pattern[i] == '+' || pattern[i] == '?') {
				b.WriteByte(pattern[i])
				i++
			}
			continue
		}

		// Slash-prefixed parameter: /:name, /:name*, /:name+, /:name?, /:name(re)[*+?].
		if ch == '/' && i+1 < n && pattern[i+1] == ':' && i+2 < n && isParamStart(pattern[i+2]) {
			j := i + 2
			for j < n && isParamChar(pattern[j]) {
				j++
			}
			hasCustom := false
			customRe := ""
			if j < n && pattern[j] == '(' {
				closeIdx, err := scanBalancedParen(pattern, j)
				if err != nil {
					return "", err
				}
				hasCustom = true
				customRe = pattern[j+1 : closeIdx]
				j = closeIdx + 1
			}
			var mod byte
			if j < n && (pattern[j] == '*' || pattern[j] == '+' || pattern[j] == '?') {
				mod = pattern[j]
				j++
			}

			onlyRoot := i == 0 && j == n
			writeSlashParam(&b, onlyRoot, hasCustom, customRe, mod)
			i = j
			continue
		}

		// Inline parameter not immediately preceded by '/': :name[(re)][*+?].
		if ch == ':' && i+1 < n && isParamStart(pattern[i+1]) {
			j := i + 1
			for j < n && isParamChar(pattern[j]) {
				j++
			}
			hasCustom := false
			customRe := ""
			if j < n && pattern[j] == '(' {
				closeIdx, err := scanBalancedParen(pattern, j)
				if err != nil {
					return "", err
				}
				hasCustom = true
				customRe = pattern[j+1 : closeIdx]
				j = closeIdx + 1
			}
			var mod byte
			if j < n && (pattern[j] == '*' || pattern[j] == '+' || pattern[j] == '?') {
				mod = pattern[j]
				j++
			}

			writeInlineParam(&b, hasCustom, customRe, mod)
			i = j
			continue
		}

		b.WriteString(regexp.QuoteMeta(string(ch)))
		i++
	}

	b.WriteByte('$')
	return b.String(), nil
}

func writeSlashParam(b *strings.Builder, atRoot, hasCustom bool, customRe string, mod byte) {
	if !hasCustom {
		switch mod {
		case '*':
			if atRoot {
				b.WriteString("/.*")
			} else {
				b.WriteString("(?:/.*)?")
			}
		case '+':
			b.WriteString("/.+")
		case '?':
			if atRoot {
				b.WriteString("/(?:[^/]+)?")
			} else {
				b.WriteString("(?:/[^/]+)?")
			}
		default:
			b.WriteString("/[^/]+")
		}
		return
	}

	seg := "(?:" + customRe + ")"
	switch mod {
	case '*':
		if atRoot {
			b.WriteString("/(?:" + seg + "(?:/" + seg + ")*)?")
		} else {
			b.WriteString("(?:/" + seg + "(?:/" + seg + ")*)?")
		}
	case '+':
		b.WriteString("/" + seg + "(?:/" + seg + ")*")
	case '?':
		if atRoot {
			b.WriteString("/(?:" + seg + ")?")
		} else {
			b.WriteString("(?:/" + seg + ")?")
		}
	default:
		b.WriteString("/" + seg)
	}
}

func writeInlineParam(b *strings.Builder, hasCustom bool, customRe string, mod byte) {
	if !hasCustom {
		switch mod {
		case '*':
			b.WriteString(".*")
		case '+':
			b.WriteString(".+")
		case '?':
			b.WriteString("(?:[^/]+)?")
		default:
			b.WriteString("[^/]+")
		}
		return
	}

	seg := "(?:" + customRe + ")"
	switch mod {
	case '*':
		b.WriteString("(?:" + seg + ")*")
	case '+':
		b.WriteString("(?:" + seg + ")+")
	case '?':
		b.WriteString("(?:" + seg + ")?")
	default:
		b.WriteString(seg)
	}
}

func isParamStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isParamChar(b byte) bool {
	return isParamStart(b) || (b >= '0' && b <= '9')
}

func scanBalancedParen(s string, open int) (int, error) {
	depth := 1
	inClass := false
	classStart := -1
	for i := open + 1; i < len(s); i++ {
		ch := s[i]
		if inClass {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == ']' && i > classStart {
				inClass = false
			}
			continue
		}
		if ch == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if ch == '[' {
			inClass = true
			classStart = i + 1
			if classStart < len(s) && s[classStart] == '^' {
				classStart++
			}
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("nextjs: unclosed '(' in matcher %q", s)
}

// --- JS/TS Lexer ---

type jsTokKind uint8

const (
	jsTokIdent jsTokKind = iota
	jsTokString
	jsTokTemplateDyn
	jsTokNumber
	jsTokRegex
	jsTokSpread
	jsTokPunct
)

type jsToken struct {
	kind jsTokKind
	val  string
	line int
}

func lexJS(src string) []jsToken {
	var tokens []jsToken
	i := 0
	n := len(src)
	line := 1
	canStartRegex := true

	for i < n {
		ch := src[i]

		if ch == ' ' || ch == '\t' || ch == '\r' {
			i++
			continue
		}
		if ch == '\n' {
			line++
			i++
			continue
		}

		// Line comment.
		if ch == '/' && i+1 < n && src[i+1] == '/' {
			i += 2
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}

		// Block comment.
		if ch == '/' && i+1 < n && src[i+1] == '*' {
			i += 2
			for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			if i+1 < n {
				i += 2
			} else {
				i = n
			}
			continue
		}

		// Regex literal.
		if ch == '/' && canStartRegex {
			startLine := line
			i++
			inClass := false
			for i < n {
				c := src[i]
				if c == '\n' {
					line++
					i++
					break
				}
				if c == '\\' && i+1 < n {
					i += 2
					continue
				}
				if c == '[' {
					inClass = true
					i++
					continue
				}
				if c == ']' {
					inClass = false
					i++
					continue
				}
				if c == '/' && !inClass {
					i++
					for i < n && isIdentPart(src[i]) {
						i++
					}
					break
				}
				i++
			}
			tokens = append(tokens, jsToken{kind: jsTokRegex, line: startLine})
			canStartRegex = false
			continue
		}

		// Single or double quoted string literal.
		if ch == '\'' || ch == '"' {
			startLine := line
			val, nextI, newLine := readJSString(src, i, line, ch)
			i = nextI
			line = newLine
			tokens = append(tokens, jsToken{kind: jsTokString, val: val, line: startLine})
			canStartRegex = false
			continue
		}

		// Template literal (`...`).
		if ch == '`' {
			startLine := line
			val, isDyn, nextI, newLine := readJSTemplate(src, i, line)
			i = nextI
			line = newLine
			if isDyn {
				tokens = append(tokens, jsToken{kind: jsTokTemplateDyn, val: val, line: startLine})
			} else {
				tokens = append(tokens, jsToken{kind: jsTokString, val: val, line: startLine})
			}
			canStartRegex = false
			continue
		}

		// Spread operator (...).
		if ch == '.' && i+2 < n && src[i+1] == '.' && src[i+2] == '.' {
			tokens = append(tokens, jsToken{kind: jsTokSpread, val: "...", line: line})
			i += 3
			canStartRegex = true
			continue
		}

		// Identifier or keyword.
		if isIdentStart(ch) {
			startLine := line
			start := i
			i++
			for i < n && isIdentPart(src[i]) {
				i++
			}
			word := src[start:i]
			tokens = append(tokens, jsToken{kind: jsTokIdent, val: word, line: startLine})
			canStartRegex = word == "return" || word == "typeof" || word == "case" ||
				word == "in" || word == "of" || word == "throw" ||
				word == "else" || word == "await" || word == "do" ||
				word == "void" || word == "delete"
			continue
		}

		// Numeric literal.
		if ch >= '0' && ch <= '9' {
			startLine := line
			start := i
			i++
			for i < n && ((src[i] >= '0' && src[i] <= '9') || src[i] == '_' || src[i] == '.') {
				i++
			}
			tokens = append(tokens, jsToken{kind: jsTokNumber, val: src[start:i], line: startLine})
			canStartRegex = false
			continue
		}

		// Punctuation.
		tokens = append(tokens, jsToken{kind: jsTokPunct, val: string(ch), line: line})
		canStartRegex = ch != ')' && ch != ']'
		i++
	}

	return tokens
}

func readJSString(src string, open, line int, quote byte) (string, int, int) {
	var b strings.Builder
	i := open + 1
	n := len(src)
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n {
			next := src[i+1]
			switch next {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\n':
				line++
			default:
				// JS string escapes decode \\ -> \, \' -> ', \" -> ", and drop single backslash before other chars.
				b.WriteByte(next)
			}
			i += 2
			continue
		}
		if c == quote {
			return b.String(), i + 1, line
		}
		if c == '\n' {
			line++
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), n, line
}

func readJSTemplate(src string, open, line int) (string, bool, int, int) {
	var b strings.Builder
	i := open + 1
	n := len(src)
	isDyn := false
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n {
			next := src[i+1]
			switch next {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\n':
				line++
			default:
				b.WriteByte(next)
			}
			i += 2
			continue
		}
		if c == '$' && i+1 < n && src[i+1] == '{' {
			isDyn = true
			i += 2
			depth := 1
			for i < n && depth > 0 {
				if src[i] == '\n' {
					line++
					i++
					continue
				}
				if src[i] == '/' && i+1 < n && src[i+1] == '/' {
					i += 2
					for i < n && src[i] != '\n' {
						i++
					}
					continue
				}
				if src[i] == '/' && i+1 < n && src[i+1] == '*' {
					i += 2
					for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
						if src[i] == '\n' {
							line++
						}
						i++
					}
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if src[i] == '\'' || src[i] == '"' {
					_, nextI, newLine := readJSString(src, i, line, src[i])
					i = nextI
					line = newLine
					continue
				}
				if src[i] == '`' {
					_, _, nextI, newLine := readJSTemplate(src, i, line)
					i = nextI
					line = newLine
					continue
				}
				if src[i] == '{' {
					depth++
				} else if src[i] == '}' {
					depth--
				}
				i++
			}
			continue
		}
		if c == '`' {
			return b.String(), isDyn, i + 1, line
		}
		if c == '\n' {
			line++
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), isDyn, n, line
}

func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b == '$'
}

func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

// --- config.matcher extraction ---

type configLookupStatus uint8

const (
	configNotFound configLookupStatus = iota
	configObjectStatic
	configObjectDynamic
)

// findConfigObject locates `export const config = { ... }`, `const config = { ... }; export { config }`,
// or dynamic config exports such as `export const config = defineConfig(...)` / `export { config } from '...'`.
func findConfigObject(tokens []jsToken) (cfgStart, cfgEnd, objStart, objEnd, dynLine int, status configLookupStatus) {
	// Pass 1: top-level export const/let/var config [: Type] = <expr>
	braceDepth := 0
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind == jsTokPunct {
			if tokens[i].val == "{" {
				braceDepth++
			} else if tokens[i].val == "}" && braceDepth > 0 {
				braceDepth--
			}
			continue
		}
		if braceDepth == 0 && i+3 < len(tokens) &&
			tokens[i].kind == jsTokIdent && tokens[i].val == "export" &&
			tokens[i+1].kind == jsTokIdent && (tokens[i+1].val == "const" || tokens[i+1].val == "let" || tokens[i+1].val == "var") &&
			tokens[i+2].kind == jsTokIdent && tokens[i+2].val == "config" {
			osIdx, oeIdx, hasAssign := scanAssignedObject(tokens, i+3)
			if osIdx >= 0 && oeIdx > osIdx {
				return i, oeIdx, osIdx, oeIdx, 0, configObjectStatic
			}
			if hasAssign {
				return i, i + 3, -1, -1, tokens[i].line, configObjectDynamic
			}
		}
	}

	// Pass 2: top-level export { ... config ... } [from '...'] paired with top-level const config = <expr>
	exportLine, isReExport, foundExport := findNamedConfigExport(tokens)
	if foundExport {
		if isReExport {
			return -1, -1, -1, -1, exportLine, configObjectDynamic
		}
		braceDepth = 0
		for i := 0; i < len(tokens); i++ {
			if tokens[i].kind == jsTokPunct {
				if tokens[i].val == "{" {
					braceDepth++
				} else if tokens[i].val == "}" && braceDepth > 0 {
					braceDepth--
				}
				continue
			}
			if braceDepth == 0 && i+2 < len(tokens) &&
				tokens[i].kind == jsTokIdent && (tokens[i].val == "const" || tokens[i].val == "let" || tokens[i].val == "var") &&
				tokens[i+1].kind == jsTokIdent && tokens[i+1].val == "config" {
				osIdx, oeIdx, hasAssign := scanAssignedObject(tokens, i+2)
				if osIdx >= 0 && oeIdx > osIdx {
					return i, oeIdx, osIdx, oeIdx, 0, configObjectStatic
				}
				if hasAssign {
					return i, i + 2, -1, -1, tokens[i].line, configObjectDynamic
				}
			}
		}
		return -1, -1, -1, -1, exportLine, configObjectDynamic
	}

	return -1, -1, -1, -1, 0, configNotFound
}

func findNamedConfigExport(tokens []jsToken) (line int, isReExport bool, found bool) {
	braceDepth := 0
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind == jsTokPunct {
			if tokens[i].val == "{" {
				braceDepth++
			} else if tokens[i].val == "}" && braceDepth > 0 {
				braceDepth--
			}
			continue
		}
		if braceDepth == 0 && i+2 < len(tokens) &&
			tokens[i].kind == jsTokIdent && tokens[i].val == "export" &&
			tokens[i+1].kind == jsTokPunct && tokens[i+1].val == "{" {
			end := matchDelimiter(tokens, i+1, "{", "}")
			if end < 0 {
				continue
			}
			for j := i + 2; j < end; j++ {
				if tokens[j].kind == jsTokIdent && tokens[j].val == "config" {
					reExport := end+1 < len(tokens) && tokens[end+1].kind == jsTokIdent && tokens[end+1].val == "from"
					return tokens[i].line, reExport, true
				}
			}
		}
	}
	return 0, false, false
}

func scanAssignedObject(tokens []jsToken, idx int) (objStart, objEnd int, hasAssign bool) {
	// Skip optional TypeScript type annotation between `config` and `=`.
	depth := 0
	for idx < len(tokens) {
		t := tokens[idx]
		if t.kind == jsTokPunct {
			// Skip TypeScript arrow function types (=>) so '>' does not decrement depth.
			if t.val == "=" && idx+1 < len(tokens) && tokens[idx+1].kind == jsTokPunct && tokens[idx+1].val == ">" {
				idx += 2
				continue
			}
			switch t.val {
			case "(", "[", "{", "<":
				depth++
			case ")", "]", "}", ">":
				if depth > 0 {
					depth--
				}
			case "=":
				if depth == 0 {
					idx++
					if idx < len(tokens) && tokens[idx].kind == jsTokPunct && tokens[idx].val == "{" {
						end := matchDelimiter(tokens, idx, "{", "}")
						if end > idx {
							return idx, end, true
						}
					}
					return -1, -1, true
				}
			case ";":
				if depth == 0 {
					return -1, -1, false
				}
			}
		}
		idx++
	}
	return -1, -1, false
}

func matchDelimiter(tokens []jsToken, openIdx int, openSym, closeSym string) int {
	depth := 1
	for i := openIdx + 1; i < len(tokens); i++ {
		if tokens[i].kind == jsTokPunct {
			if tokens[i].val == openSym {
				depth++
			} else if tokens[i].val == closeSym {
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func parseConfigObject(mw *Middleware, tokens []jsToken, objStart, objEnd, maxStates int) {
	i := objStart + 1
	for i < objEnd {
		t := tokens[i]
		if t.kind == jsTokPunct && t.val == "," {
			i++
			continue
		}
		if t.kind == jsTokSpread {
			mw.HasExplicitMatcher = true
			mw.HasDynamicMatcher = true
			mw.Warnings = append(mw.Warnings, Warning{
				Kind:    WarnUnsupported,
				File:    mw.File,
				Line:    t.line,
				Context: "config",
				Message: "dynamic spread in middleware config is not modeled",
			})
			i = skipValue(tokens, i, objEnd)
			continue
		}

		isMatcherKey := (t.kind == jsTokIdent || t.kind == jsTokString) && t.val == "matcher"
		if i+1 < objEnd && tokens[i+1].kind == jsTokPunct && tokens[i+1].val == ":" {
			valStart := i + 2
			valEnd := skipValue(tokens, valStart, objEnd)
			if isMatcherKey {
				mw.HasExplicitMatcher = true
				parseMatcherValue(mw, tokens, valStart, valEnd, maxStates)
			}
			i = valEnd
			continue
		}
		if t.kind == jsTokIdent && t.val == "matcher" &&
			(i+1 == objEnd || (tokens[i+1].kind == jsTokPunct && tokens[i+1].val == ",")) {
			// ES6 shorthand property: export const config = { matcher }
			mw.HasExplicitMatcher = true
			mw.HasDynamicMatcher = true
			mw.Warnings = append(mw.Warnings, Warning{
				Kind:    WarnUnsupported,
				File:    mw.File,
				Line:    t.line,
				Context: "config.matcher",
				Message: "shorthand matcher property is dynamic and not modeled",
			})
			i++
			continue
		}
		i++
	}
}

// skipValue advances past one JS property value or array element at depth 0.
func skipValue(tokens []jsToken, start, limit int) int {
	depth := 0
	i := start
	for i < limit {
		t := tokens[i]
		if t.kind == jsTokPunct {
			switch t.val {
			case "{", "[", "(":
				depth++
			case "}", "]", ")":
				if depth == 0 {
					return i
				}
				depth--
			case ",":
				if depth == 0 {
					return i
				}
			}
		}
		i++
	}
	return limit
}

// trimTrailingTypeAssertion strips top-level TypeScript `as ...` and `satisfies ...` suffixes.
func trimTrailingTypeAssertion(tokens []jsToken, start, end int) int {
	depth := 0
	for i := start; i < end; i++ {
		t := tokens[i]
		if t.kind == jsTokPunct {
			if t.val == "=" && i+1 < end && tokens[i+1].kind == jsTokPunct && tokens[i+1].val == ">" {
				i++
				continue
			}
			switch t.val {
			case "{", "[", "(", "<":
				depth++
			case "}", "]", ")", ">":
				if depth > 0 {
					depth--
				}
			}
			continue
		}
		if depth == 0 && i > start && t.kind == jsTokIdent && (t.val == "as" || t.val == "satisfies") {
			return i
		}
	}
	return end
}

func parseMatcherValue(mw *Middleware, tokens []jsToken, start, end, maxStates int) {
	end = trimTrailingTypeAssertion(tokens, start, end)
	if start >= end {
		return
	}
	first := tokens[start]

	// Single string literal matcher: matcher: '/admin/:path*'
	if first.kind == jsTokString && start+1 == end {
		mw.Matchers = append(mw.Matchers, compileMatcherEntry(mw, first.val, first.line, false, maxStates))
		return
	}

	// Single object matcher: matcher: { source: '...', has: [...] }
	if first.kind == jsTokPunct && first.val == "{" {
		objEnd := matchDelimiter(tokens, start, "{", "}")
		if objEnd > start && objEnd+1 == end {
			if entry, ok := parseMatcherObject(mw, tokens, start, objEnd, maxStates); ok {
				mw.Matchers = append(mw.Matchers, entry)
			}
			return
		}
	}

	// Array matcher: matcher: [...]
	if first.kind == jsTokPunct && first.val == "[" {
		arrEnd := matchDelimiter(tokens, start, "[", "]")
		if arrEnd > start && arrEnd+1 == end {
			i := start + 1
			for i < arrEnd {
				if tokens[i].kind == jsTokPunct && tokens[i].val == "," {
					i++
					continue
				}
				nextI := skipValue(tokens, i, arrEnd)
				elemEnd := trimTrailingTypeAssertion(tokens, i, nextI)
				if tokens[i].kind == jsTokString && i+1 == elemEnd {
					mw.Matchers = append(mw.Matchers, compileMatcherEntry(mw, tokens[i].val, tokens[i].line, false, maxStates))
				} else if tokens[i].kind == jsTokPunct && tokens[i].val == "{" {
					objEnd := matchDelimiter(tokens, i, "{", "}")
					if objEnd > i && objEnd+1 == elemEnd {
						if entry, ok := parseMatcherObject(mw, tokens, i, objEnd, maxStates); ok {
							mw.Matchers = append(mw.Matchers, entry)
						}
					} else {
						mw.HasDynamicMatcher = true
						mw.Warnings = append(mw.Warnings, Warning{
							Kind:    WarnUnsupported,
							File:    mw.File,
							Line:    tokens[i].line,
							Context: "config.matcher",
							Message: "dynamic matcher expression is not modeled",
						})
					}
				} else {
					mw.HasDynamicMatcher = true
					mw.Warnings = append(mw.Warnings, Warning{
						Kind:    WarnUnsupported,
						File:    mw.File,
						Line:    tokens[i].line,
						Context: "config.matcher",
						Message: "dynamic matcher expression is not modeled",
					})
				}
				i = nextI
			}
			return
		}
	}

	// Dynamic variable, call, concatenation, or template interpolation.
	mw.HasDynamicMatcher = true
	mw.Warnings = append(mw.Warnings, Warning{
		Kind:    WarnUnsupported,
		File:    mw.File,
		Line:    first.line,
		Context: "config.matcher",
		Message: "dynamic matcher expression is not modeled",
	})
}

func parseMatcherObject(mw *Middleware, tokens []jsToken, objStart, objEnd, maxStates int) (MatcherEntry, bool) {
	var source string
	sourceLine := tokens[objStart].line
	hasSource := false
	conditional := false
	condLine := 0
	var condKeys []string

	i := objStart + 1
	for i < objEnd {
		t := tokens[i]
		if t.kind == jsTokPunct && t.val == "," {
			i++
			continue
		}
		if t.kind == jsTokSpread {
			mw.HasDynamicMatcher = true
			mw.Warnings = append(mw.Warnings, Warning{
				Kind:    WarnUnsupported,
				File:    mw.File,
				Line:    t.line,
				Context: "config.matcher",
				Message: "dynamic spread inside matcher object is not modeled",
			})
			i = skipValue(tokens, i, objEnd)
			continue
		}
		if (t.kind == jsTokIdent || t.kind == jsTokString) && i+1 < objEnd && tokens[i+1].kind == jsTokPunct && tokens[i+1].val == ":" {
			key := t.val
			valStart := i + 2
			valEnd := skipValue(tokens, valStart, objEnd)
			switch key {
			case "source":
				srcEnd := trimTrailingTypeAssertion(tokens, valStart, valEnd)
				if valStart < srcEnd && tokens[valStart].kind == jsTokString && valStart+1 == srcEnd {
					source = tokens[valStart].val
					sourceLine = tokens[valStart].line
					hasSource = true
				} else {
					mw.HasDynamicMatcher = true
					mw.Warnings = append(mw.Warnings, Warning{
						Kind:    WarnUnsupported,
						File:    mw.File,
						Line:    t.line,
						Context: "config.matcher.source",
						Message: "dynamic matcher source expression is not modeled",
					})
				}
			case "has", "missing":
				conditional = true
				if condLine == 0 {
					condLine = t.line
				}
				condKeys = append(condKeys, key)
			}
			i = valEnd
			continue
		}
		i++
	}

	if conditional {
		mw.Warnings = append(mw.Warnings, Warning{
			Kind:    WarnUnsupported,
			File:    mw.File,
			Line:    condLine,
			Context: "config.matcher",
			Message: fmt.Sprintf("conditional matcher (%s) is not modeled; header/cookie/query conditions are not evaluated", strings.Join(condKeys, "/")),
		})
	}

	if !hasSource {
		mw.HasDynamicMatcher = true
		mw.Warnings = append(mw.Warnings, Warning{
			Kind:    WarnUnsupported,
			File:    mw.File,
			Line:    tokens[objStart].line,
			Context: "config.matcher",
			Message: "matcher object without static source string is not modeled",
		})
		return MatcherEntry{}, false
	}

	return compileMatcherEntry(mw, source, sourceLine, conditional, maxStates), true
}

func compileMatcherEntry(mw *Middleware, raw string, line int, conditional bool, maxStates int) MatcherEntry {
	entry := MatcherEntry{
		Raw:         raw,
		Line:        line,
		Conditional: conditional,
	}

	if bad, ok := findOutOfAlphabetByte(raw); ok {
		entry.Unmodeled = true
		mw.Warnings = append(mw.Warnings, Warning{
			Kind:    WarnUnsupported,
			File:    mw.File,
			Line:    line,
			Context: raw,
			Message: fmt.Sprintf("matcher contains byte 0x%02X outside modeled ASCII range 0x21..0x7E", bad),
		})
		return entry
	}

	reStr, err := MatcherToRegex(raw)
	if err != nil {
		entry.Unmodeled = true
		mw.Warnings = append(mw.Warnings, Warning{
			Kind:    WarnInvalid,
			File:    mw.File,
			Line:    line,
			Context: raw,
			Message: err.Error(),
		})
		return entry
	}
	entry.Regex = reStr

	dfa, err := automata.Compile(reStr, automata.CompileOptions{
		Anchored:  true,
		MaxStates: maxStates,
	})
	if err != nil {
		entry.Unmodeled = true
		wKind := WarnInvalid
		if errors.Is(err, automata.ErrUnsupportedRegex) {
			wKind = WarnUnsupported
		} else if errors.Is(err, automata.ErrStateLimit) {
			wKind = WarnStateLimit
		}
		mw.Warnings = append(mw.Warnings, Warning{
			Kind:    wKind,
			File:    mw.File,
			Line:    line,
			Context: raw,
			Message: err.Error(),
		})
		return entry
	}

	entry.DFA = dfa
	return entry
}

// --- Transparent auth-signal detection ---

func detectAuthSignals(tokens []jsToken, cfgStart, cfgEnd int) []string {
	found := make(map[string]bool)

	for i := 0; i < len(tokens); i++ {
		// Exclude the export const config = { ... } block itself.
		if cfgStart >= 0 && i >= cfgStart && i <= cfgEnd {
			continue
		}

		t := tokens[i]
		switch t.kind {
		case jsTokNumber:
			if t.val == "401" || t.val == "403" {
				found[t.val] = true
			}

		case jsTokString:
			lower := strings.ToLower(t.val)
			if lower == "authorization" {
				found["authorization"] = true
			} else if lower == "cookie" {
				found["cookie"] = true
			}

		case jsTokIdent:
			// Check NextResponse.redirect specifically.
			if t.val == "NextResponse" && i+2 < len(tokens) &&
				tokens[i+1].kind == jsTokPunct && tokens[i+1].val == "." &&
				tokens[i+2].kind == jsTokIdent && tokens[i+2].val == "redirect" {
				found["NextResponse.redirect"] = true
			}

			lower := strings.ToLower(t.val)
			switch lower {
			case "redirect":
				found["redirect"] = true
			case "gettoken":
				found["getToken"] = true
			case "cookies":
				found["cookies"] = true
			case "cookie":
				found["cookie"] = true
			case "session":
				found["session"] = true
			case "authorization":
				found["authorization"] = true
			case "jwt":
				found["jwt"] = true
			case "token":
				found["token"] = true
			case "auth":
				found["auth"] = true
			default:
				if strings.Contains(lower, "gettoken") {
					found["getToken"] = true
				}
				if strings.Contains(lower, "cookie") {
					if strings.Contains(lower, "cookies") {
						found["cookies"] = true
					} else {
						found["cookie"] = true
					}
				}
				if strings.Contains(lower, "session") {
					found["session"] = true
				}
				if strings.Contains(lower, "authorization") {
					found["authorization"] = true
				}
				if strings.Contains(lower, "jwt") {
					found["jwt"] = true
				}
				if strings.Contains(lower, "token") {
					found["token"] = true
				}
				if containsAuthWord(lower) {
					found["auth"] = true
				}
			}
		}
	}

	signals := make([]string, 0, len(found))
	for sig := range found {
		signals = append(signals, sig)
	}
	sort.Strings(signals)
	return signals
}

func containsAuthWord(lower string) bool {
	if !strings.Contains(lower, "auth") {
		return false
	}
	// Avoid obvious false matches such as "author" / "authors".
	if strings.Contains(lower, "author") && !strings.Contains(lower, "authoriz") {
		return false
	}
	return true
}
