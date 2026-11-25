package nginx

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"routeproof/internal/automata"
)

// Modifier represents an Nginx location matching modifier.
type Modifier string

const (
	ModPrefix     Modifier = ""
	ModExact      Modifier = "="
	ModCaretTilde Modifier = "^~"
	ModRegex      Modifier = "~"
	ModRegexCI    Modifier = "~*"
)

// WarningKind categorizes non-fatal parser and analyzer warnings.
type WarningKind string

const (
	WarnUnsupported WarningKind = "UNSUPPORTED"
	WarnStateLimit  WarningKind = "STATE_LIMIT"
	WarnInvalid     WarningKind = "INVALID"
)

// Warning records an unsupported directive, unmodeled pattern, or resource limit.
type Warning struct {
	Kind    WarningKind `json:"kind"`
	Line    int         `json:"line"`
	Context string      `json:"context,omitempty"`
	Message string      `json:"message"`
}

// AccessRule represents a single allow or deny directive in declaration order.
type AccessRule struct {
	Allow bool
	Value string
	Line  int
}

// AuthConfig tracks access-control directives and scope overrides.
type AuthConfig struct {
	AuthRequest    string
	AuthRequestOff bool
	AuthBasic      string
	AuthBasicOff   bool
	AccessRules    []AccessRule
	Satisfy        string // "all" (default) or "any"
}

func (a AuthConfig) hasAuth() bool {
	return (a.AuthRequest != "" && a.AuthRequest != "off") ||
		(a.AuthBasic != "" && a.AuthBasic != "off")
}

// accessEval summarizes ordered allow/deny rules (first match wins in Nginx).
func (a AuthConfig) accessEval() (hasDenyAll, denyAllOnly, allowAllFirst bool) {
	seenAllow := false
	for _, r := range a.AccessRules {
		if r.Allow {
			if r.Value == "all" {
				return false, false, true
			}
			seenAllow = true
		} else if r.Value == "all" {
			return true, !seenAllow, false
		}
	}
	return false, false, false
}

// IsProtected reports whether this AuthConfig enforces access control.
func (a AuthConfig) IsProtected() bool {
	hasDenyAll, _, allowAllFirst := a.accessEval()
	if a.Satisfy == "any" && allowAllFirst {
		return false
	}
	return a.hasAuth() || hasDenyAll
}

// IsDenyAllBlocking reports whether deny all unconditionally blocks every request.
func (a AuthConfig) IsDenyAllBlocking() bool {
	_, denyAllOnly, _ := a.accessEval()
	if !denyAllOnly {
		return false
	}
	// Under "satisfy any", valid auth_basic/auth_request still grants access.
	if a.Satisfy == "any" && a.hasAuth() {
		return false
	}
	return true
}

// ProtectionSources returns human-readable labels for active protection mechanisms.
func (a AuthConfig) ProtectionSources() []string {
	var sources []string
	if a.AuthRequest != "" && a.AuthRequest != "off" {
		sources = append(sources, "auth_request "+a.AuthRequest)
	}
	if a.AuthBasic != "" && a.AuthBasic != "off" {
		sources = append(sources, "auth_basic")
	}
	hasDenyAll, _, _ := a.accessEval()
	if hasDenyAll {
		sources = append(sources, "deny all")
	}
	return sources
}

// inherit merges child directives over parent directives using Nginx inheritance rules.
func inheritAuth(parent, child AuthConfig, childHasAccess bool) AuthConfig {
	out := AuthConfig{
		AuthRequest:    parent.AuthRequest,
		AuthBasic:      parent.AuthBasic,
		Satisfy:        parent.Satisfy,
		AuthRequestOff: parent.AuthRequestOff,
		AuthBasicOff:   parent.AuthBasicOff,
	}

	if child.AuthRequestOff {
		out.AuthRequest = "off"
		out.AuthRequestOff = true
	} else if child.AuthRequest != "" {
		out.AuthRequest = child.AuthRequest
		out.AuthRequestOff = false
	}

	if child.AuthBasicOff {
		out.AuthBasic = "off"
		out.AuthBasicOff = true
	} else if child.AuthBasic != "" {
		out.AuthBasic = child.AuthBasic
		out.AuthBasicOff = false
	}

	if child.Satisfy != "" {
		out.Satisfy = child.Satisfy
	}

	// Nginx replaces the entire allow/deny list if any allow/deny appears at child scope.
	if childHasAccess {
		out.AccessRules = append([]AccessRule(nil), child.AccessRules...)
	} else {
		out.AccessRules = append([]AccessRule(nil), parent.AccessRules...)
	}

	return out
}

// Location represents a parsed Nginx location block with resolved inheritance.
type Location struct {
	Index              int
	Line               int
	Modifier           Modifier
	Pattern            string
	IsNamed            bool
	HasUnsupportedByte bool
	Auth               AuthConfig
	Protected          bool
	ProtectVia         []string
	IsInternal         bool
	IsBlocking         bool
	ReturnStatus       int
	Alias              string
	AliasLine          int
}

// Display returns the concise Nginx location header (e.g. "location ~* \\.json$").
func (l Location) Display() string {
	if l.Modifier == ModPrefix {
		return "location " + l.Pattern
	}
	return "location " + string(l.Modifier) + " " + l.Pattern
}

// Server represents a parsed Nginx server block.
type Server struct {
	Line       int
	ServerName string
	Listen     []string
	Auth       AuthConfig
	Locations  []Location
}

// Config holds all parsed server blocks and warnings from an nginx.conf source.
type Config struct {
	Servers  []Server
	Warnings []Warning
}

// ParseFile reads and parses an nginx.conf file from disk.
func ParseFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(data))
}

// Parse lexes and parses an Nginx configuration string.
func Parse(src string) (*Config, error) {
	src = strings.TrimPrefix(src, "\xef\xbb\xbf")
	tokens, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{
		tokens: tokens,
		cfg:    &Config{},
	}
	if err := p.parseTopLevel(); err != nil {
		return nil, err
	}
	return p.cfg, nil
}

// --- Lexer ---

type tokKind uint8

const (
	tokWord tokKind = iota
	tokLBrace
	tokRBrace
	tokSemi
	tokEOF
)

type token struct {
	kind tokKind
	val  string
	line int
}

func lex(src string) ([]token, error) {
	var tokens []token
	line := 1
	i := 0
	n := len(src)

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
		if ch == '#' {
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		switch ch {
		case '{':
			tokens = append(tokens, token{kind: tokLBrace, val: "{", line: line})
			i++
			continue
		case '}':
			tokens = append(tokens, token{kind: tokRBrace, val: "}", line: line})
			i++
			continue
		case ';':
			tokens = append(tokens, token{kind: tokSemi, val: ";", line: line})
			i++
			continue
		}

		startLine := line
		var buf strings.Builder
		if ch == '"' || ch == '\'' {
			quote := ch
			i++
			closed := false
			for i < n {
				c := src[i]
				if c == '\\' && i+1 < n {
					next := src[i+1]
					switch next {
					case quote, '\\':
						buf.WriteByte(next)
					case 'n':
						buf.WriteByte('\n')
					case 'r':
						buf.WriteByte('\r')
					case 't':
						buf.WriteByte('\t')
					default:
						// Preserve regex escapes such as \. or \d verbatim.
						buf.WriteByte('\\')
						buf.WriteByte(next)
					}
					if next == '\n' {
						line++
					}
					i += 2
					continue
				}
				if c == quote {
					i++
					closed = true
					break
				}
				if c == '\n' {
					line++
				}
				buf.WriteByte(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("nginx: unterminated quoted string at line %d", startLine)
			}
			tokens = append(tokens, token{kind: tokWord, val: buf.String(), line: startLine})
			continue
		}

		// Unquoted word: ends at whitespace or structural delimiter.
		for i < n {
			c := src[i]
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '{' || c == '}' || c == ';' {
				break
			}
			if c == '$' && i+1 < n && src[i+1] == '{' {
				buf.WriteByte('$')
				buf.WriteByte('{')
				i += 2
				for i < n && src[i] != '}' && src[i] != '\n' && src[i] != ';' {
					buf.WriteByte(src[i])
					i++
				}
				if i < n && src[i] == '}' {
					buf.WriteByte('}')
					i++
				}
				continue
			}
			if c == '\\' && i+1 < n {
				// Keep backslash intact for unquoted regex tokens like \.(json|bak)$.
				buf.WriteByte(c)
				buf.WriteByte(src[i+1])
				if src[i+1] == '\n' {
					line++
				}
				i += 2
				continue
			}
			buf.WriteByte(c)
			i++
		}
		tokens = append(tokens, token{kind: tokWord, val: buf.String(), line: startLine})
	}

	tokens = append(tokens, token{kind: tokEOF, line: line})
	return tokens, nil
}

// --- Recursive-descent parser ---

type parser struct {
	tokens []token
	pos    int
	cfg    *Config
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{kind: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

func (p *parser) warn(kind WarningKind, line int, ctx, msg string) {
	p.cfg.Warnings = append(p.cfg.Warnings, Warning{
		Kind:    kind,
		Line:    line,
		Context: ctx,
		Message: msg,
	})
}

type stmt struct {
	name     string
	args     []string
	line     int
	hasBlock bool
}

// readStmt reads one directive header up to ';' or '{'.
func (p *parser) readStmt() (stmt, error) {
	first := p.next()
	if first.kind != tokWord {
		return stmt{}, fmt.Errorf("nginx: unexpected token %q at line %d", first.val, first.line)
	}
	s := stmt{name: first.val, line: first.line}
	for {
		t := p.peek()
		switch t.kind {
		case tokWord:
			p.next()
			s.args = append(s.args, t.val)
		case tokSemi:
			p.next()
			return s, nil
		case tokLBrace:
			p.next()
			s.hasBlock = true
			return s, nil
		case tokEOF:
			return stmt{}, fmt.Errorf("nginx: unexpected EOF in directive %q started at line %d", s.name, s.line)
		case tokRBrace:
			return stmt{}, fmt.Errorf("nginx: unexpected '}' in directive %q at line %d", s.name, t.line)
		}
	}
}

// skipBlock skips tokens until the matching '}' for an already-consumed '{'.
func (p *parser) skipBlock(openLine int) error {
	depth := 1
	for depth > 0 {
		t := p.next()
		switch t.kind {
		case tokLBrace:
			depth++
		case tokRBrace:
			depth--
		case tokEOF:
			return fmt.Errorf("nginx: unclosed block started at line %d", openLine)
		}
	}
	return nil
}

func (p *parser) parseTopLevel() error {
	var rootAuth AuthConfig
	var rootHasAccess bool

	for p.peek().kind != tokEOF {
		if p.peek().kind == tokRBrace {
			t := p.next()
			return fmt.Errorf("nginx: unexpected '}' at line %d", t.line)
		}
		if p.peek().kind == tokSemi {
			p.next()
			continue
		}
		s, err := p.readStmt()
		if err != nil {
			return err
		}
		switch s.name {
		case "http":
			if !s.hasBlock {
				return fmt.Errorf("nginx: expected '{' after http at line %d", s.line)
			}
			if err := p.parseHTTP(rootAuth); err != nil {
				return err
			}
		case "server":
			if !s.hasBlock {
				return fmt.Errorf("nginx: expected '{' after server at line %d", s.line)
			}
			rs, err := p.parseServerRaw(s.line)
			if err != nil {
				return err
			}
			p.cfg.Servers = append(p.cfg.Servers, resolveServer(rs, rootAuth))
		case "map":
			p.warn(WarnUnsupported, s.line, "map", "dynamic map block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return err
				}
			}
		case "include":
			p.warn(WarnUnsupported, s.line, "include", fmt.Sprintf("include directive is not followed: %s", strings.Join(s.args, " ")))
		default:
			applyAuthDirective(&rootAuth, &rootHasAccess, s)
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type rawServer struct {
	srv       Server
	localAuth AuthConfig
	hasAccess bool
	rawLocs   []rawLocation
}

func (p *parser) parseHTTP(parentAuth AuthConfig) error {
	var localAuth AuthConfig
	var localHasAccess bool
	var rawServers []rawServer

	for p.peek().kind != tokEOF && p.peek().kind != tokRBrace {
		if p.peek().kind == tokSemi {
			p.next()
			continue
		}
		s, err := p.readStmt()
		if err != nil {
			return err
		}
		switch s.name {
		case "server":
			if !s.hasBlock {
				return fmt.Errorf("nginx: expected '{' after server at line %d", s.line)
			}
			rs, err := p.parseServerRaw(s.line)
			if err != nil {
				return err
			}
			rawServers = append(rawServers, rs)
		case "map":
			p.warn(WarnUnsupported, s.line, "map", "dynamic map block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return err
				}
			}
		case "include":
			p.warn(WarnUnsupported, s.line, "include", fmt.Sprintf("include directive is not followed: %s", strings.Join(s.args, " ")))
		default:
			applyAuthDirective(&localAuth, &localHasAccess, s)
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return err
				}
			}
		}
	}
	if p.peek().kind != tokRBrace {
		return fmt.Errorf("nginx: unclosed http block")
	}
	p.next()

	effHTTP := inheritAuth(parentAuth, localAuth, localHasAccess)
	for _, rs := range rawServers {
		p.cfg.Servers = append(p.cfg.Servers, resolveServer(rs, effHTTP))
	}
	return nil
}

type rawLocation struct {
	loc       Location
	localAuth AuthConfig
	hasAccess bool
}

func (p *parser) parseServerRaw(serverLine int) (rawServer, error) {
	rs := rawServer{
		srv: Server{Line: serverLine},
	}

	for p.peek().kind != tokEOF && p.peek().kind != tokRBrace {
		if p.peek().kind == tokSemi {
			p.next()
			continue
		}
		s, err := p.readStmt()
		if err != nil {
			return rawServer{}, err
		}
		switch s.name {
		case "server_name":
			if len(s.args) > 0 {
				rs.srv.ServerName = strings.Join(s.args, " ")
			}
		case "listen":
			if len(s.args) > 0 {
				rs.srv.Listen = append(rs.srv.Listen, strings.Join(s.args, " "))
			}
		case "location":
			if !s.hasBlock {
				return rawServer{}, fmt.Errorf("nginx: expected '{' after location at line %d", s.line)
			}
			rl, err := p.parseLocation(s, len(rs.rawLocs))
			if err != nil {
				return rawServer{}, err
			}
			rs.rawLocs = append(rs.rawLocs, rl)
		case "if":
			p.warn(WarnUnsupported, s.line, "if", "dynamic if block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawServer{}, err
				}
			}
		case "rewrite":
			p.warn(WarnUnsupported, s.line, "rewrite", fmt.Sprintf("dynamic rewrite directive is not modeled: %s", strings.Join(s.args, " ")))
		case "include":
			p.warn(WarnUnsupported, s.line, "include", fmt.Sprintf("include directive is not followed: %s", strings.Join(s.args, " ")))
		case "map":
			p.warn(WarnUnsupported, s.line, "map", "dynamic map block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawServer{}, err
				}
			}
		default:
			applyAuthDirective(&rs.localAuth, &rs.hasAccess, s)
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawServer{}, err
				}
			}
		}
	}
	if p.peek().kind != tokRBrace {
		return rawServer{}, fmt.Errorf("nginx: unclosed server block started at line %d", serverLine)
	}
	p.next()
	return rs, nil
}

func resolveServer(rs rawServer, parentAuth AuthConfig) Server {
	srv := rs.srv
	srv.Auth = inheritAuth(parentAuth, rs.localAuth, rs.hasAccess)
	srv.Locations = make([]Location, 0, len(rs.rawLocs))
	for _, rl := range rs.rawLocs {
		loc := rl.loc
		loc.Auth = inheritAuth(srv.Auth, rl.localAuth, rl.hasAccess)
		loc.Protected = loc.Auth.IsProtected()
		loc.ProtectVia = loc.Auth.ProtectionSources()
		loc.IsBlocking = loc.Auth.IsDenyAllBlocking() || isBlockingStatus(loc.ReturnStatus)
		srv.Locations = append(srv.Locations, loc)
	}
	return srv
}

func (p *parser) parseLocation(header stmt, index int) (rawLocation, error) {
	mod, pat, err := parseLocationHeader(header)
	if err != nil {
		return rawLocation{}, err
	}

	loc := Location{
		Index:    index,
		Line:     header.line,
		Modifier: mod,
		Pattern:  pat,
		IsNamed:  mod == ModPrefix && strings.HasPrefix(pat, "@"),
	}

	if !loc.IsNamed {
		if badByte, ok := findOutOfAlphabetByte(pat); ok {
			loc.HasUnsupportedByte = true
			p.warn(
				WarnUnsupported,
				header.line,
				loc.Display(),
				fmt.Sprintf("location pattern contains byte 0x%02X outside modeled ASCII range 0x21..0x7E", badByte),
			)
		}
	}

	var localAuth AuthConfig
	var localHasAccess bool

	for p.peek().kind != tokEOF && p.peek().kind != tokRBrace {
		if p.peek().kind == tokSemi {
			p.next()
			continue
		}
		s, err := p.readStmt()
		if err != nil {
			return rawLocation{}, err
		}
		switch s.name {
		case "internal":
			loc.IsInternal = true
		case "return":
			if len(s.args) > 0 {
				if code, err := strconv.Atoi(s.args[0]); err == nil {
					loc.ReturnStatus = code
				}
			}
		case "alias":
			if len(s.args) > 0 {
				loc.Alias = s.args[0]
				loc.AliasLine = s.line
			}
		case "location":
			p.warn(WarnUnsupported, s.line, loc.Display(), "nested location block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawLocation{}, err
				}
			}
		case "if":
			p.warn(WarnUnsupported, s.line, loc.Display(), "dynamic if block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawLocation{}, err
				}
			}
		case "rewrite":
			p.warn(WarnUnsupported, s.line, loc.Display(), fmt.Sprintf("dynamic rewrite directive is not modeled: %s", strings.Join(s.args, " ")))
		case "include":
			p.warn(WarnUnsupported, s.line, loc.Display(), fmt.Sprintf("include directive is not followed: %s", strings.Join(s.args, " ")))
		case "limit_except":
			p.warn(WarnUnsupported, s.line, loc.Display(), "limit_except block is not modeled")
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawLocation{}, err
				}
			}
		default:
			applyAuthDirective(&localAuth, &localHasAccess, s)
			if s.hasBlock {
				if err := p.skipBlock(s.line); err != nil {
					return rawLocation{}, err
				}
			}
		}
	}
	if p.peek().kind != tokRBrace {
		return rawLocation{}, fmt.Errorf("nginx: unclosed location block started at line %d", header.line)
	}
	p.next()

	return rawLocation{
		loc:       loc,
		localAuth: localAuth,
		hasAccess: localHasAccess,
	}, nil
}

func parseLocationHeader(s stmt) (Modifier, string, error) {
	switch len(s.args) {
	case 1:
		arg := s.args[0]
		if strings.HasPrefix(arg, "=") && len(arg) > 1 {
			return ModExact, arg[1:], nil
		}
		return ModPrefix, arg, nil
	case 2:
		switch Modifier(s.args[0]) {
		case ModExact, ModCaretTilde, ModRegex, ModRegexCI:
			return Modifier(s.args[0]), s.args[1], nil
		default:
			return "", "", fmt.Errorf("nginx: unknown location modifier %q at line %d", s.args[0], s.line)
		}
	default:
		return "", "", fmt.Errorf("nginx: invalid location header at line %d", s.line)
	}
}

func applyAuthDirective(auth *AuthConfig, hasAccess *bool, s stmt) {
	if len(s.args) == 0 {
		return
	}
	val := s.args[0]
	switch s.name {
	case "auth_request":
		if val == "off" {
			auth.AuthRequest = "off"
			auth.AuthRequestOff = true
		} else {
			auth.AuthRequest = val
			auth.AuthRequestOff = false
		}
	case "auth_basic":
		if val == "off" {
			auth.AuthBasic = "off"
			auth.AuthBasicOff = true
		} else {
			auth.AuthBasic = val
			auth.AuthBasicOff = false
		}
	case "deny":
		*hasAccess = true
		auth.AccessRules = append(auth.AccessRules, AccessRule{Allow: false, Value: val, Line: s.line})
	case "allow":
		*hasAccess = true
		auth.AccessRules = append(auth.AccessRules, AccessRule{Allow: true, Value: val, Line: s.line})
	case "satisfy":
		auth.Satisfy = val
	}
}

func isBlockingStatus(code int) bool {
	return code == 401 || code == 403 || code == 404 || code == 444
}

func findOutOfAlphabetByte(s string) (byte, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] < automata.MinByte || s[i] > automata.MaxByte {
			return s[i], true
		}
	}
	return 0, false
}
