package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"tokenhub/internal/buildinfo"
	"tokenhub/internal/connector"
	"tokenhub/internal/endpoint"
	"tokenhub/internal/gjl"
	"tokenhub/internal/privatefs"
)

func main() {
	log.SetOutput(io.Discard)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "hubconn:", err)
		os.Exit(1)
	}
}

func flags(name string, output io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(output)
	return f
}

func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected_connector_arguments")
	}
	return nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stdout, "hubconn setup <Hub URL> | run | status | doctor | enroll | inspect | version\nLocal Connector executable. Use <command> -h for options.")
		return nil
	}
	switch args[0] {
	case "setup":
		return setup(ctx, args[1:], os.Stdin, stdout, stderr)
	case "status", "doctor":
		return diagnose(ctx, args[1:], args[0] == "doctor", stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "hubconn "+buildinfo.Version)
		return nil
	case "enroll":
		f := flags("enroll", stderr)
		base := f.String("hub", "", "Hub HTTPS origin")
		name := f.String("name", "", "device name")
		state := f.String("state", "", "private Connector state directory")
		dev := f.Bool("dev-http", false, "allow HTTP to a literal loopback address only")
		ca := f.String("ca", "", "optional Hub CA PEM file")
		webURL := f.String("web-url", "", "public website for device approval")
		pin := f.String("tls-pin", "", "Hub TLS public-key SHA256")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		if *name == "" || *state == "" {
			return errors.New("name_and_state_required")
		}
		client, err := connector.HTTPClient(*base, *dev, *ca, *pin)
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		unlock, err := privatefs.Lock(*state, "connector")
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := os.Lstat(filepath.Join(*state, "identity.json")); err == nil {
			return errors.New("device_already_enrolled")
		} else if !os.IsNotExist(err) {
			return errors.New("identity_unavailable")
		}
		if *webURL == "" {
			*webURL, err = connector.WebOrigin(ctx, client, *base, *dev)
			if err != nil {
				return err
			}
		}
		if _, err = endpoint.Parse(*webURL, *dev); err != nil {
			return errors.New("invalid_web_url")
		}
		return connector.Enroll(ctx, client, *base, *name, *state, func(code string) {
			fmt.Fprintf(stdout, "Open %s/#devices?code=%s and approve this device.\nOne-time code: %s\n", *webURL, code, code)
		})
	case "run":
		f := flags("run", stderr)
		defaultPath, err := connector.DefaultConfigPath(false)
		if err != nil {
			return err
		}
		path := f.String("config", defaultPath, "Connector configuration saved by setup")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		cfg, err := connector.Load(*path)
		if err != nil {
			return err
		}
		unlock, err := privatefs.Lock(cfg.StateDir, "connector")
		if err != nil {
			return err
		}
		defer unlock()
		runner, err := connector.New(cfg)
		if err != nil {
			return err
		}
		defer runner.Close()
		fmt.Fprintln(stdout, "Connector running; select and publish services in the Hub.")
		return runner.Run(ctx)
	case "inspect":
		f := flags("inspect", stderr)
		address := f.String("ipc", "", "explicit gjl native IPC address")
		if err := parse(f, args[1:]); err != nil {
			return err
		}
		client, err := gjl.New(*address)
		if err != nil {
			return err
		}
		defer client.Close()
		doc, err := client.Config(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "gjl IPC v1 available; revision=%d listeners=%d routes=%d\n", doc.Revision, len(doc.Listeners), len(doc.Routes))
		return nil
	default:
		return errors.New("unknown_command")
	}
}
