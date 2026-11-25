package nextjs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"routeproof/internal/automata"
)

// RouteKind identifies how a Next.js route is defined.
type RouteKind string

const (
	RouteAppPage   RouteKind = "app-page"
	RouteAppRoute  RouteKind = "app-route"
	RoutePagesPage RouteKind = "pages-page"
	RoutePagesAPI  RouteKind = "pages-api"
)

// WarningKind categorizes non-fatal Next.js discovery and parsing warnings.
type WarningKind string

const (
	WarnUnsupported WarningKind = "UNSUPPORTED"
	WarnStateLimit  WarningKind = "STATE_LIMIT"
	WarnInvalid     WarningKind = "INVALID"
)

// Warning records an unsupported construct, unmodeled pattern, or resource limit.
type Warning struct {
	Kind    WarningKind `json:"kind"`
	File    string      `json:"file,omitempty"`
	Line    int         `json:"line,omitempty"`
	Context string      `json:"context,omitempty"`
	Message string      `json:"message"`
}

// Route represents a discovered Next.js HTTP route compiled to an anchored DFA.
type Route struct {
	File    string        `json:"file"`
	Kind    RouteKind     `json:"kind"`
	Pattern string        `json:"pattern"`
	Regex   string        `json:"regex"`
	DFA     *automata.DFA `json:"-"`
}

var (
	appPageExts  = map[string]bool{".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".mdx": true}
	appRouteExts = map[string]bool{".ts": true, ".tsx": true, ".js": true, ".jsx": true}
	pagesExts    = map[string]bool{".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".mdx": true}
	pagesSpecial = map[string]bool{"_app": true, "_document": true, "_error": true, "404": true, "500": true}
)

// DiscoverRoutes scans App Router (app/ or src/app/) and Pages Router (pages/ or src/pages/)
// under rootDir, returning all compiled HTTP routes and any non-fatal warnings.
func DiscoverRoutes(rootDir string, maxStates int) ([]Route, []Warning, error) {
	if maxStates <= 0 {
		maxStates = automata.DefaultMaxStates
	}

	var routes []Route
	var warnings []Warning

	if appDir, ok := firstExistingDir(rootDir, "app", filepath.Join("src", "app")); ok {
		r, w, err := scanAppRouter(rootDir, appDir, maxStates)
		if err != nil {
			return nil, nil, err
		}
		routes = append(routes, r...)
		warnings = append(warnings, w...)
	}

	if pagesDir, ok := firstExistingDir(rootDir, "pages", filepath.Join("src", "pages")); ok {
		r, w, err := scanPagesRouter(rootDir, pagesDir, maxStates)
		if err != nil {
			return nil, nil, err
		}
		routes = append(routes, r...)
		warnings = append(warnings, w...)
	}

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Pattern != routes[j].Pattern {
			return routes[i].Pattern < routes[j].Pattern
		}
		if routes[i].Kind != routes[j].Kind {
			return routes[i].Kind < routes[j].Kind
		}
		return routes[i].File < routes[j].File
	})

	return routes, warnings, nil
}

func firstExistingDir(rootDir string, candidates ...string) (string, bool) {
	for _, rel := range candidates {
		full := filepath.Join(rootDir, rel)
		info, err := os.Stat(full)
		if err == nil && info.IsDir() {
			return full, true
		}
	}
	return "", false
}

func scanAppRouter(rootDir, appDir string, maxStates int) ([]Route, []Warning, error) {
	var routes []Route
	var warnings []Warning

	err := filepath.WalkDir(appDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == appDir {
			return nil
		}

		name := d.Name()
		if d.IsDir() {
			if name == "node_modules" || name == ".next" {
				return filepath.SkipDir
			}
			// Skip private folders (_folder). Parallel route slots (@slot) remain routable with @slot stripped.
			if strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			// Intercepted routes ((.)foo, (..)foo, (...)foo) are client-side overlays.
			if strings.HasPrefix(name, "(.") {
				rel, _ := filepath.Rel(rootDir, path)
				warnings = append(warnings, Warning{
					Kind:    WarnUnsupported,
					File:    filepath.ToSlash(rel),
					Context: name,
					Message: "intercepted route directory is not modeled",
				})
				return filepath.SkipDir
			}
			return nil
		}

		kind, ok := classifyAppFile(name)
		if !ok {
			return nil
		}

		relFromApp, err := filepath.Rel(appDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		relFromRoot, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(relFromRoot)

		var segs []string
		if relFromApp != "." {
			for _, seg := range strings.Split(filepath.ToSlash(relFromApp), "/") {
				if isRouteGroup(seg) || strings.HasPrefix(seg, "@") {
					continue
				}
				segs = append(segs, seg)
			}
		}

		route, warn := buildRoute(relSlash, kind, segs, maxStates)
		if warn != nil {
			warnings = append(warnings, *warn)
			return nil
		}
		routes = append(routes, route)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return routes, warnings, nil
}

func classifyAppFile(name string) (RouteKind, bool) {
	if strings.HasSuffix(strings.ToLower(name), ".d.ts") {
		return "", false
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if base == "page" && appPageExts[ext] {
		return RouteAppPage, true
	}
	if base == "route" && appRouteExts[ext] {
		return RouteAppRoute, true
	}
	return "", false
}

func isRouteGroup(seg string) bool {
	return len(seg) >= 2 && strings.HasPrefix(seg, "(") && strings.HasSuffix(seg, ")") && !strings.HasPrefix(seg, "(.")
}

func scanPagesRouter(rootDir, pagesDir string, maxStates int) ([]Route, []Warning, error) {
	var routes []Route
	var warnings []Warning

	err := filepath.WalkDir(pagesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == pagesDir {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == "node_modules" || name == ".next" {
				return filepath.SkipDir
			}
			return nil
		}

		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".d.ts") {
			return nil
		}
		ext := filepath.Ext(lower)
		if !pagesExts[ext] {
			return nil
		}

		relFromPages, err := filepath.Rel(pagesDir, path)
		if err != nil {
			return err
		}
		relSlashPages := filepath.ToSlash(relFromPages)
		relNoExt := strings.TrimSuffix(relSlashPages, filepath.Ext(relSlashPages))
		parts := strings.Split(relNoExt, "/")

		// Skip Next.js special root files (_app, _document, _error, 404, 500).
		if len(parts) == 1 && pagesSpecial[parts[0]] {
			return nil
		}

		kind := RoutePagesPage
		if len(parts) > 1 && parts[0] == "api" {
			kind = RoutePagesAPI
		}

		if parts[len(parts)-1] == "index" {
			parts = parts[:len(parts)-1]
		}

		relFromRoot, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		route, warn := buildRoute(filepath.ToSlash(relFromRoot), kind, parts, maxStates)
		if warn != nil {
			warnings = append(warnings, *warn)
			return nil
		}
		routes = append(routes, route)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return routes, warnings, nil
}

func buildRoute(relFile string, kind RouteKind, segs []string, maxStates int) (Route, *Warning) {
	for _, seg := range segs {
		if bad, ok := findOutOfAlphabetByte(seg); ok {
			return Route{}, &Warning{
				Kind:    WarnUnsupported,
				File:    relFile,
				Context: "/" + strings.Join(segs, "/"),
				Message: fmt.Sprintf("route segment %q contains byte 0x%02X outside modeled ASCII range 0x21..0x7E", seg, bad),
			}
		}
	}

	pattern := "/"
	if len(segs) > 0 {
		pattern = "/" + strings.Join(segs, "/")
	}

	reStr := segmentsToRegex(segs)
	dfa, err := automata.Compile(reStr, automata.CompileOptions{
		Anchored:  true,
		MaxStates: maxStates,
	})
	if err != nil {
		wKind := WarnInvalid
		if errors.Is(err, automata.ErrStateLimit) {
			wKind = WarnStateLimit
		} else if errors.Is(err, automata.ErrUnsupportedRegex) {
			wKind = WarnUnsupported
		}
		return Route{}, &Warning{
			Kind:    wKind,
			File:    relFile,
			Context: pattern,
			Message: err.Error(),
		}
	}

	return Route{
		File:    relFile,
		Kind:    kind,
		Pattern: pattern,
		Regex:   reStr,
		DFA:     dfa,
	}, nil
}

// validSegmentRegex matches a single non-empty URL path segment excluding ".", "..", '?', and '#'.
const validSegmentRegex = `(?:[^/.?#][^/?#]*|\.[^/.?#][^/?#]*|\.\.[^/?#]+)`

// segmentsToRegex converts Next.js route segments into an anchored regular expression.
func segmentsToRegex(segs []string) string {
	if len(segs) == 0 {
		return "^/$"
	}

	var b strings.Builder
	b.WriteByte('^')

	for i, seg := range segs {
		switch {
		case strings.HasPrefix(seg, "[[...") && strings.HasSuffix(seg, "]]") && len(seg) > 7:
			// Optional catch-all: root [[...slug]] matches / and /a/b; nested matches /prefix and /prefix/...
			if i == 0 {
				b.WriteString("/(?:" + validSegmentRegex + "(?:/" + validSegmentRegex + ")*)?")
			} else {
				b.WriteString("(?:/" + validSegmentRegex + ")*")
			}
		case strings.HasPrefix(seg, "[...") && strings.HasSuffix(seg, "]") && len(seg) > 5:
			// Required catch-all: matches one or more valid trailing segments.
			b.WriteString("(?:/" + validSegmentRegex + ")+")
		case strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]") && len(seg) > 2:
			// Single dynamic segment.
			b.WriteString("/" + validSegmentRegex)
		default:
			b.WriteByte('/')
			b.WriteString(regexp.QuoteMeta(seg))
		}
	}

	b.WriteByte('$')
	return b.String()
}

func findOutOfAlphabetByte(s string) (byte, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] < automata.MinByte || s[i] > automata.MaxByte {
			return s[i], true
		}
	}
	return 0, false
}
