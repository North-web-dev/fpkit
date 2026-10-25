package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/North-web-dev/fpkit/internal/fetch"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printCheck(res *fetch.CheckResult, reflector string) {
	fmt.Printf("profile=%s reflector=%s\n", res.Profile, reflector)
	for _, f := range res.Fields {
		mark := "OK  "
		if !f.Match {
			mark = "DRIFT"
		}
		fmt.Printf("  [%s] %-7s expected=%s measured=%s\n", mark, f.Field, orNA(f.Expected), orNA(f.Measured))
	}
	if res.Mismatch {
		fmt.Println("result: MISMATCH — client does not read as the target browser")
	} else {
		fmt.Println("result: MATCH — client reads as the target browser")
	}
}

func orNA(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
