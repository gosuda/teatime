package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"tokenhub/internal/connector"
)

func diagnose(ctx context.Context, args []string, deep bool, stdout, stderr io.Writer) error {
	f := flags("status", stderr)
	defaultPath, err := connector.DefaultConfigPath(false)
	if err != nil {
		return err
	}
	path := f.String("config", defaultPath, "Connector configuration saved by setup")
	asJSON := f.Bool("json", false, "machine-readable diagnostics")
	if err := parse(f, args); err != nil {
		return err
	}
	cfg, err := connector.Load(*path)
	if err != nil {
		return errors.New("connector_config_unavailable_run_setup")
	}
	checks := connector.Diagnose(ctx, cfg, deep)
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(checks); err != nil {
			return err
		}
	} else {
		for _, c := range checks {
			fmt.Fprintf(stdout, "%s: %s (%s)\n", c.Name, c.State, c.Detail)
			if deep && c.Action != "" && c.State != "ok" {
				fmt.Fprintln(stdout, "  "+c.Action)
			}
		}
	}
	for _, c := range checks {
		if c.State == "failed" || c.State == "unavailable" || c.State == "delayed" || c.State == "stale" {
			return errors.New("connector_checks_failed")
		}
	}
	return nil
}
