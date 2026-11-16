package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jvch0512/tfplan-guard/internal/guard"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func usage(w io.Writer) int {
	fmt.Fprintln(w, "usage: tfplan-guard PLAN.json|- [--tsv] [--fail-on medium|high|critical]")
	fmt.Fprintln(w, "Exit: 0 ok, 1 findings at or above --fail-on, 2 bad input.")
	return 2
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	path, tsv, fail := "", false, ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--tsv":
			tsv = true
		case a == "--fail-on":
			i++
			if i >= len(args) || (args[i] != "medium" && args[i] != "high" && args[i] != "critical") {
				return usage(stderr)
			}
			fail = args[i]
		case strings.HasPrefix(a, "-") && a != "-":
			return usage(stderr)
		default:
			if path != "" {
				return usage(stderr)
			}
			path = a
		}
	}
	if path == "" {
		return usage(stderr)
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot read %s\n", path)
		return 2
	}
	fs, n, err := guard.Review(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if tsv {
		fmt.Fprintf(stdout, "# %d resource changes, %d findings\n", n, len(fs))
		for _, f := range fs {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", f.Severity, f.Rule, f.Where, f.Message)
		}
	} else {
		fmt.Fprintf(stdout, "%d resource changes, %d findings\n", n, len(fs))
		for _, f := range fs {
			fmt.Fprintf(stdout, "%-8s %s %s\n         %s\n", strings.ToUpper(f.Severity), f.Rule, f.Where, f.Message)
		}
	}
	floor := map[string]int{"critical": 0, "high": 1, "medium": 2}
	if r, ok := floor[fail]; ok {
		for _, f := range fs {
			if guard.Rank(f.Severity) <= r {
				return 1
			}
		}
	}
	return 0
}
