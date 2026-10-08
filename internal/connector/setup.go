package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"tokenhub/internal/gjl"
	"tokenhub/internal/privatefs"
)

func DefaultConfigPath(development bool) (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("user_config_unavailable")
	}
	base = filepath.Join(base, "hubconn")
	if development {
		base = filepath.Join(base, "development")
	}
	return filepath.Join(base, "connector.json"), nil
}
func SaveConfig(path string, cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return privatefs.Write(path, raw)
}

// SetupOptions are derived exclusively from the selected local gjl profile.
// Neither Hub metadata nor user-provided URLs can supply certificate trust.
type SetupOptions struct {
	Door       []gjl.Binding
	Gates      []Publish
	VaultReady *bool
	Vaults     []gjl.VaultCertificate
	VaultError error
}

func DiscoverSetup(ctx context.Context, client *gjl.Client) (SetupOptions, error) {
	doc, err := client.Config(ctx)
	if err != nil {
		return SetupOptions{}, err
	}
	result, err := discoverSetupDocument(doc)
	if err != nil {
		return result, err
	}
	result.discoverVault(ctx, client)
	return result, nil
}

func (o *SetupOptions) discoverVault(ctx context.Context, client *gjl.Client) {
	ready, err := client.VaultReady(ctx)
	if err == nil {
		o.VaultReady = &ready
	}
	certificates, err := client.VaultCertificates(ctx)
	o.VaultError = err
	if err != nil {
		return
	}
	for _, v := range certificates {
		if VaultLocalAddress(v.RPCBaseURL) != "" && v.Usable() {
			o.Vaults = append(o.Vaults, v)
		}
	}
}

func VaultLocalAddress(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != "https://"+u.Host || !loopback(u.Host) {
		return ""
	}
	return u.Host
}

func consumerBindings(b *gjl.Binding) []gjl.Binding {
	if b == nil {
		return nil
	}
	return []gjl.Binding{*b}
}

func discoverSetupDocument(doc gjl.Document) (SetupOptions, error) {
	var result SetupOptions
	routes := map[string]gjl.Route{}
	for _, raw := range doc.Routes {
		var route gjl.Route
		if json.Unmarshal(raw, &route) != nil {
			return result, errors.New("ipc_protocol_invalid")
		}
		routes[route.ID] = route
		if route.Role == "door" && route.Target == "gate" {
			var fields struct {
				Identity   string `json:"gate_client_identity_ref"`
				Trust      string `json:"gate_server_trust_ref"`
				ServerName string `json:"gate_server_name"`
			}
			if json.Unmarshal(raw, &fields) == nil && fields.Identity != "" && fields.Trust != "" && fields.ServerName != "" {
				result.Door = append(result.Door, gjl.Binding{RouteID: route.ID, Identity: fields.Identity, Trust: fields.Trust, ServerName: fields.ServerName})
			}
		}
	}
	for _, l := range doc.Listeners {
		route := routes[l.RouteID]
		if l.Role == "gate" && l.Transport == "gate_paired_door_mtls" && len(l.Matchers) == 0 && route.Role == "gate" && route.Target == "provider" {
			if _, err := localTarget(l.Address); err == nil {
				result.Gates = append(result.Gates, Publish{ListenerID: l.ID})
			}
		}
	}
	return result, nil
}
