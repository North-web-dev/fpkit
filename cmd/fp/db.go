package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/North-web-dev/fpkit/data"
)

func cmdDB(args []string) error {
	db, err := data.Load()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: fp db list | show <name> | ja4 <value>")
	}
	switch args[0] {
	case "list":
		return dbList(db)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: fp db show <name>")
		}
		return dbShow(db, args[1])
	case "ja4":
		if len(args) < 2 {
			return fmt.Errorf("usage: fp db ja4 <value>")
		}
		dbJA4(db, args[1])
		return nil
	default:
		return fmt.Errorf("unknown db subcommand %q (list|show|ja4)", args[0])
	}
}

func dbList(db *data.DB) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "NAME\tKIND\tVERDICT\tJA4\tLABEL\n")
	for _, e := range db.Entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Name, e.Kind, e.Verdict, e.TLS.JA4, e.Label)
	}
	tw.Flush()
	fmt.Printf("\n%d entries from: ", len(db.Entries))
	var srcs []string
	for _, s := range db.Sources {
		srcs = append(srcs, s.Name)
	}
	fmt.Println(strings.Join(srcs, ", "))
	return nil
}

func dbShow(db *data.DB, name string) error {
	e, ok := db.Get(name)
	if !ok {
		return fmt.Errorf("no entry named %q (try 'fp db list')", name)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}

func dbJA4(db *data.DB, value string) {
	v := db.Classify(value)
	var mark string
	switch {
	case v.Browser:
		mark = "browser ✅"
	case v.Verdict == "browser-engine":
		mark = "browser engine 🧪"
	case v.Known:
		mark = "NOT a browser ❌"
	default:
		mark = "unknown ❓"
	}
	fmt.Printf("%s\n  %s — %s\n", value, v.Label, mark)
	if len(v.Matches) > 0 {
		for _, m := range v.Matches {
			fmt.Printf("  · %-18s %-12s %s (measured %s via %s)\n", m.Name, m.Category, m.Label, m.Provenance.Measured, m.Provenance.Source)
		}
	}
}
