package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"tokenhub/internal/connector"
	"tokenhub/internal/endpoint"
	"tokenhub/internal/gjl"
	"tokenhub/internal/model"
	"tokenhub/internal/privatefs"
)

type prompts struct {
	input  *bufio.Reader
	output io.Writer
}

func (p prompts) ask(label, fallback string) (string, error) {
	fmt.Fprintf(p.output, "%s [%s]: ", label, fallback)
	line, err := p.input.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", errors.New("setup_input_required")
	}
	line = strings.TrimSpace(line)
	if line == "" {
		line = fallback
	}
	return line, nil
}
func openBrowser(address string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	case "darwin":
		cmd = exec.Command("open", address)
	default:
		cmd = exec.Command("xdg-open", address)
	}
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}
func freeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", errors.New("local_port_unavailable")
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func setup(ctx context.Context, args []string, input io.Reader, stdout, stderr io.Writer) error {
	f := flags("setup", stderr)
	name := f.String("name", "", "device name (otherwise prompt)")
	profile := f.String("profile", "installed", "installed or development gjl profile")
	purpose := f.String("purpose", "register", "register device, use a service, or provide a service")
	config := f.String("config", "", "private configuration path (automatic by default)")
	state := f.String("state", "", "private state directory (automatic by default)")
	ipc := f.String("ipc", "", "optional explicit native IPC address")
	dev := f.Bool("dev-http", false, "allow literal loopback Hub HTTP for QA")
	ca := f.String("ca", "", "optional Hub CA PEM file")
	webURL := f.String("web-url", "", "public browser origin used for device approval")
	pin := f.String("tls-pin", "", "Hub TLS public-key SHA256 from the public website")
	noBrowser := f.Bool("no-browser", false, "print approval URL without opening a browser")
	// Support the documented URL-first invocation as well as flags-first.
	var base string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		base = args[0]
		args = args[1:]
	}
	if err := f.Parse(args); err != nil {
		return err
	}
	if base == "" && f.NArg() == 1 {
		base = f.Arg(0)
	} else if f.NArg() != 0 {
		return errors.New("setup_requires_one_hub_url")
	}
	base = strings.TrimRight(base, "/")
	client, err := connector.HTTPClient(base, *dev, *ca, *pin)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	if *webURL == "" {
		*webURL, err = connector.WebOrigin(ctx, client, base, *dev)
		if err != nil {
			return err
		}
	}
	if _, err = endpoint.Parse(*webURL, *dev); err != nil {
		return errors.New("invalid_web_url")
	}
	p := prompts{bufio.NewReader(input), stdout}
	if *purpose != "register" && *purpose != "use" && *purpose != "provide" {
		return errors.New("invalid_setup_purpose")
	}
	if *profile != "installed" && *profile != "development" {
		return errors.New("invalid_gjl_profile")
	}
	development := *profile == "development"
	if *ipc == "" {
		*ipc, err = gjl.ProfileAddress(development)
		if err != nil {
			return err
		}
	}
	if development && !strings.Contains(*ipc, "development") {
		return errors.New("development_ipc_required")
	}
	local, err := gjl.New(*ipc)
	if err != nil {
		return err
	}
	defer local.Close()
	if *config == "" {
		*config, err = connector.DefaultConfigPath(development)
		if err != nil {
			return err
		}
	}
	*config, err = filepath.Abs(*config)
	if err != nil {
		return err
	}
	if *state == "" {
		*state = filepath.Join(filepath.Dir(*config), "state")
	}
	*state, err = filepath.Abs(*state)
	if err != nil {
		return err
	}
	cfg := connector.Config{HubURL: base, WebURL: *webURL, TLSKeyPin: *pin, StateDir: *state, IPC: *ipc, DevHTTP: *dev, CAFile: *ca, Publish: []connector.Publish{}, Bindings: []gjl.Binding{}}
	if *ca != "" {
		cfg.CAFile, err = filepath.Abs(*ca)
		if err != nil {
			return err
		}
	}
	unlock, err := privatefs.Lock(*state, "connector")
	if err != nil {
		if err.Error() == "state_already_in_use" {
			return errors.New("connector_state_busy: stop hubconn run with Ctrl+C, then retry setup")
		}
		return errors.New("connector_state_unavailable")
	}
	defer unlock()
	// Re-registering preserves both purposes and the approved identity.
	if _, statErr := os.Lstat(*config); statErr == nil {
		existing, loadErr := connector.Load(*config)
		if loadErr != nil {
			return errors.New("setup_existing_config_invalid")
		}
		if existing.HubURL != base || existing.StateDir != *state {
			return errors.New("setup_profile_conflict_use_separate_config")
		}
		if existing.IPC != cfg.IPC {
			return errors.New("setup_gjl_profile_conflict_use_separate_config")
		}
		if existing.TLSKeyPin != "" && cfg.TLSKeyPin != existing.TLSKeyPin {
			return errors.New("setup_hub_key_changed_use_separate_config")
		}
		cfg = existing
		cfg.WebURL = *webURL
	} else if !os.IsNotExist(statErr) {
		return errors.New("connector_config_unavailable")
	}
	if _, err = os.Lstat(filepath.Join(*state, "identity.json")); os.IsNotExist(err) {
		if *name == "" {
			host, _ := os.Hostname()
			*name, err = p.ask("Device name", host)
			if err != nil {
				return err
			}
		}
		if *name == "" || len(*name) > 80 {
			return errors.New("invalid_device_name")
		}
		err = connector.Enroll(ctx, client, base, *name, *state, func(code string) {
			address := *webURL + "/#devices?code=" + code
			fmt.Fprintf(stdout, "Approve this device: %s\nOne-time code: %s\n", address, code)
			if !*noBrowser {
				openBrowser(address)
			}
		})
		if err != nil {
			return err
		}
	} else if err != nil {
		return errors.New("identity_unavailable")
	}
	// Registration must survive a missing daemon, cancelled local setup, or
	// unavailable Routes. No gjl connection is needed to validate this identity.
	runner, err := connector.New(cfg)
	if err != nil {
		return err
	}
	runner.Close()
	if err = connector.SaveConfig(*config, cfg); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Device registration saved: %s\n", *config)
	if *purpose != "register" {
		options, discoverErr := connector.DiscoverSetup(ctx, local)
		if discoverErr != nil {
			printSetupNext(stdout, cfg, *config, *profile)
			return errors.New("gjl_setup_unavailable: device registration is saved; start the selected gjl daemon, then retry setup with --purpose " + *purpose)
		}
		if err = configureLocal(p, &cfg, options, *purpose); err != nil {
			printSetupNext(stdout, cfg, *config, *profile)
			return err
		}
		if err = connector.SaveConfig(*config, cfg); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "Setup saved: %s\n", *config)
	printSetupNext(stdout, cfg, *config, *profile)
	return nil
}

func configureLocal(p prompts, cfg *connector.Config, options connector.SetupOptions, purpose string) error {
	stdout := p.output
	var err error
	if purpose == "provide" {
		publications := append([]connector.Publish(nil), options.Gates...)
		if options.VaultReady != nil && *options.VaultReady {
			key := "vault-rpc"
			for _, previous := range cfg.Publish {
				if model.ServiceKind(previous.Kind) == "vault" {
					key = previous.ListenerID
				}
			}
			publications = append(publications, connector.Publish{Kind: "vault", ListenerID: key})
		} else if options.VaultReady == nil {
			fmt.Fprintln(stdout, "Vault readiness could not be read; existing Vault publication settings are preserved. Check gjl IPC and retry.")
		}
		return configurePublishing(p, cfg, publications)
	}
	for _, v := range options.Vaults {
		options.Door = append(options.Door, v.Binding())
	}
	if options.VaultError != nil {
		fmt.Fprintln(stdout, "Vault connections could not be read. Check gjl IPC and retry for Vault setup.")
	}
	priorConsumer := cfg.Consumer
	cfg.Consumer = nil
	if len(options.Door) > 0 {
		fmt.Fprintln(stdout, "Door Routes and Vault connections (0 skips consuming):")
		for i, b := range options.Door {
			label := "Gate Route " + b.RouteID
			if model.ServiceKind(b.Kind) == "vault" {
				label = "Vault connection " + b.ConnectionID
			}
			fmt.Fprintf(stdout, "  %d. %s → %s\n", i+1, label, b.ServerName)
		}
		fallback := "1"
		if priorConsumer != nil {
			for i, b := range options.Door {
				if b.RouteID == priorConsumer.RouteID && b.ConnectionID == priorConsumer.ConnectionID && model.ServiceKind(b.Kind) == model.ServiceKind(priorConsumer.Kind) {
					fallback = strconv.Itoa(i + 1)
				}
			}
		}
		value, e := p.ask("Door Route / Vault connection", fallback)
		if e != nil {
			return e
		}
		n, e := strconv.Atoi(value)
		if e != nil || n < 0 || n > len(options.Door) {
			return errors.New("invalid_route_selection")
		}
		if n > 0 {
			b := options.Door[n-1]
			cfg.Consumer = &b
			if model.ServiceKind(b.Kind) == "vault" {
				for _, v := range options.Vaults {
					if v.ID == b.Identity {
						cfg.Listen = connector.VaultLocalAddress(v.RPCBaseURL)
					}
				}
			}
			if cfg.Listen == "" {
				cfg.Listen, err = freeAddress()
			}
			if err != nil {
				return err
			}
			if cfg.BootstrapListen == "" {
				cfg.BootstrapListen, err = freeAddress()
			}
			if err != nil {
				return err
			}
			if cfg.Listen == cfg.BootstrapListen {
				return errors.New("distinct_listener_required")
			}
		} else {
			cfg.Listen, cfg.BootstrapListen = "", ""
			cfg.Bindings = nil
		}
	} else {
		if priorConsumer != nil && model.ServiceKind(priorConsumer.Kind) == "vault" && options.VaultError != nil {
			return errors.New("vault_connections_unavailable_previous_settings_preserved")
		}
		fmt.Fprintln(stdout, "No paired Door Route or local Vault connection. Your device stays registered. Select a service on the website and run Connector for certificate registration. For Gate, prepare the Door Route/Listener. For Vault, submit its certificate connection using the printed RPC and registration endpoints, then repeat --purpose use before collecting the certificate. Complete pairing approval and credential grants in gjl.")
		if cfg.Listen == "" {
			cfg.Listen, err = freeAddress()
		}
		if err != nil {
			return err
		}
		if cfg.BootstrapListen == "" {
			cfg.BootstrapListen, err = freeAddress()
		}
		if err != nil {
			return err
		}
	}
	if cfg.Listen != "" && cfg.Listen == cfg.BootstrapListen {
		return errors.New("distinct_listener_required")
	}
	return nil
}

func configurePublishing(p prompts, cfg *connector.Config, gates []connector.Publish) error {
	if len(gates) == 0 {
		fmt.Fprintln(p.output, "No eligible Gate Listener or running Vault. Your device stays registered. In gjl, prepare a Gate provider Route and paired-Door TLS Listener, or start Vault with its credential RPC and certificate registration listeners, then repeat --purpose provide.")
		return nil
	}
	previous := map[string]connector.Publish{}
	for _, gate := range cfg.Publish {
		previous[gate.ListenerID] = gate
	}
	cfg.Publish = nil
	// Preserve unavailable publications; absence after a failed read is not consent to remove them.
	for _, prior := range previous {
		if model.ServiceKind(prior.Kind) != "vault" {
			continue
		}
		found := false
		for _, candidate := range gates {
			if candidate.Kind == "vault" {
				found = true
			}
		}
		if !found {
			cfg.Publish = append(cfg.Publish, prior)
		}
	}
	for _, gate := range gates {
		kind := "Gate"
		if model.ServiceKind(gate.Kind) == "vault" {
			kind = "Vault"
		}
		fallback := "no"
		if prior, ok := previous[gate.ListenerID]; ok {
			if model.ServiceKind(prior.Kind) != model.ServiceKind(gate.Kind) {
				return errors.New("publication_key_conflict")
			}
			gate = prior
			fallback = "yes"
		}
		value, e := p.ask("Share local "+kind+" "+gate.ListenerID+"? yes/no", fallback)
		if e != nil {
			return e
		}
		if value == "yes" {
			if kind == "Vault" {
				gate.Address, e = p.ask("Local Vault credential RPC address (loopback IP:port)", gate.Address)
				if e != nil {
					return e
				}
			}
			gate.ServerName, e = p.ask(kind+" certificate server name", gate.ServerName)
			if e != nil {
				return e
			}
			if gate.ServerName == "" {
				return errors.New("service_server_name_required")
			}
			gate.Bootstrap, e = p.ask("Local "+kind+" certificate registration address (optional)", gate.Bootstrap)
			if e != nil {
				return e
			}
			if gate.Bootstrap != "" {
				host, port, e := net.SplitHostPort(gate.Bootstrap)
				portNumber, portErr := strconv.ParseUint(port, 10, 16)
				if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || portErr != nil || portNumber == 0 {
					return errors.New("loopback_bootstrap_required")
				}
			}
			if !gate.Valid() {
				return errors.New("invalid_publish")
			}
			for _, existing := range cfg.Publish {
				if existing.ListenerID == gate.ListenerID {
					return errors.New("publication_key_conflict")
				}
			}
			cfg.Publish = append(cfg.Publish, gate)
		} else if value != "no" {
			return errors.New("invalid_publish_selection")
		}
	}
	if len(cfg.Publish) > 16 {
		return errors.New("publish_limit")
	}
	return nil
}

// Output shell syntax, not Go string literals (Windows paths must not gain
// doubled backslashes). Follow-up commands retain the selected profile/config.
func commandQuote(value string) string {
	if runtime.GOOS == "windows" {
		return "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func printSetupNext(stdout io.Writer, cfg connector.Config, config, profile string) {
	configArg := " --config " + commandQuote(config)
	defaultPath, _ := connector.DefaultConfigPath(false)
	if config == defaultPath {
		configArg = ""
	}
	fmt.Fprintf(stdout, "Run: hubconn run%s\n", configArg)
	fmt.Fprintf(stdout, "Continue on the website: %s/#devices\n", cfg.WebURL)
	fmt.Fprintln(stdout, "Registration is complete. Route and certificate setup can be continued later. Stop hubconn run with Ctrl+C before changing its local settings.")
	base := "hubconn setup " + commandQuote(cfg.HubURL) + " --web-url " + commandQuote(cfg.WebURL) + " --profile " + profile + " --ipc " + commandQuote(cfg.IPC) + " --config " + commandQuote(config) + " --state " + commandQuote(cfg.StateDir)
	if cfg.TLSKeyPin != "" {
		base += " --tls-pin " + cfg.TLSKeyPin
	}
	if cfg.CAFile != "" {
		base += " --ca " + commandQuote(cfg.CAFile)
	}
	if cfg.DevHTTP {
		base += " --dev-http"
	}
	fmt.Fprintf(stdout, "Use a service: %s --purpose use\nProvide a service: %s --purpose provide\n", base, base)
	fmt.Fprintln(stdout, "gjl Desktop and setup help: https://gjl.io/ | https://github.com/gjl-io/gjl")
	if cfg.Consumer != nil {
		if model.ServiceKind(cfg.Consumer.Kind) == "vault" {
			fmt.Fprintf(stdout, "Vault connection: %s; select its Vault service in My devices. Complete certificate collection, pairing approval and per-credential grants in gjl.\n", cfg.Consumer.ConnectionID)
		} else {
			fmt.Fprintf(stdout, "Door Route: %s; select a service in My devices.\n", cfg.Consumer.RouteID)
		}
	}
	if cfg.Listen != "" {
		fmt.Fprintf(stdout, "Gate / Vault RPC endpoint: https://%s\n", cfg.Listen)
	}
	if cfg.BootstrapListen != "" {
		fmt.Fprintf(stdout, "First certificate registration endpoint: https://%s\n", cfg.BootstrapListen)
	}
}
