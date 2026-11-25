package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"routeproof/internal/automata"
	"routeproof/internal/nextjs"
	"routeproof/internal/nginx"
	"routeproof/internal/report"
)

const version = "v0.2.0"

const (
	exitOK      = 0
	exitFinding = 1
	exitError   = 2
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	if val == "" {
		return errors.New("prefix cannot be empty")
	}
	*s = append(*s, val)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitError
	}

	switch args[0] {
	case "--version", "-version", "version":
		fmt.Fprintf(stdout, "routeproof %s\n", version)
		return exitOK
	case "-h", "--help", "help":
		printUsage(stdout)
		return exitOK
	case "nginx":
		return runNginx(args[1:], stdout, stderr)
	case "nextjs":
		return runNextJS(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "routeproof: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return exitError
	}
}

func runNginx(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nginx", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var protected stringSliceFlag
	var jsonOut bool
	var failOnFinding bool
	var maxStates int
	var showVersion bool

	fs.Var(&protected, "protected", "URL prefix to treat as protected (repeatable)")
	fs.BoolVar(&jsonOut, "json", false, "output report as JSON")
	fs.BoolVar(&failOnFinding, "fail-on-finding", false, "exit with status 1 when findings are detected")
	fs.IntVar(&maxStates, "max-states", automata.DefaultMaxStates, "maximum DFA state count per automaton")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: routeproof nginx [flags] <nginx.conf>")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}

	if showVersion {
		fmt.Fprintf(stdout, "routeproof %s\n", version)
		return exitOK
	}

	if maxStates <= 0 {
		fmt.Fprintf(stderr, "routeproof: --max-states must be positive (got %d)\n", maxStates)
		return exitError
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "routeproof: expected exactly one nginx.conf path")
		fs.Usage()
		return exitError
	}

	target := fs.Arg(0)
	res, err := nginx.AnalyzeFile(target, nginx.AnalyzeOptions{
		ProtectedPrefixes: protected,
		MaxStates:         maxStates,
	})
	if err != nil {
		fmt.Fprintf(stderr, "routeproof: %v\n", err)
		return exitError
	}

	if jsonOut {
		err = report.WriteJSON(stdout, target, res)
	} else {
		err = report.WriteText(stdout, target, res)
	}
	if err != nil {
		fmt.Fprintf(stderr, "routeproof: failed to write report: %v\n", err)
		return exitError
	}

	if failOnFinding && len(res.Findings) > 0 {
		return exitFinding
	}
	return exitOK
}

func runNextJS(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nextjs", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var protected stringSliceFlag
	var jsonOut bool
	var failOnFinding bool
	var maxStates int
	var showVersion bool

	fs.Var(&protected, "protected", "URL prefix to treat as protected (repeatable)")
	fs.BoolVar(&jsonOut, "json", false, "output report as JSON")
	fs.BoolVar(&failOnFinding, "fail-on-finding", false, "exit with status 1 when findings are detected")
	fs.IntVar(&maxStates, "max-states", automata.DefaultMaxStates, "maximum DFA state count per automaton")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: routeproof nextjs [flags] <project-dir>")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}

	if showVersion {
		fmt.Fprintf(stdout, "routeproof %s\n", version)
		return exitOK
	}

	if maxStates <= 0 {
		fmt.Fprintf(stderr, "routeproof: --max-states must be positive (got %d)\n", maxStates)
		return exitError
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "routeproof: expected exactly one Next.js project directory")
		fs.Usage()
		return exitError
	}

	target := fs.Arg(0)
	res, err := nextjs.AnalyzeDir(target, nextjs.AnalyzeOptions{
		ProtectedPrefixes: protected,
		MaxStates:         maxStates,
	})
	if err != nil {
		fmt.Fprintf(stderr, "routeproof: %v\n", err)
		return exitError
	}

	if jsonOut {
		err = report.WriteNextJSJSON(stdout, target, res)
	} else {
		err = report.WriteNextJSText(stdout, target, res)
	}
	if err != nil {
		fmt.Fprintf(stderr, "routeproof: failed to write report: %v\n", err)
		return exitError
	}

	if failOnFinding && len(res.Findings) > 0 {
		return exitFinding
	}
	return exitOK
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  routeproof nginx [flags] <nginx.conf>")
	fmt.Fprintln(w, "  routeproof nextjs [flags] <project-dir>")
	fmt.Fprintln(w, "  routeproof --version")
	fmt.Fprintln(w, "\nCommands:")
	fmt.Fprintln(w, "  nginx    Analyze Nginx location precedence and authorization rules")
	fmt.Fprintln(w, "  nextjs   Analyze Next.js middleware matcher coverage across App/Pages routes")
}
