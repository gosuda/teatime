package connector

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	hubendpoint "tokenhub/internal/endpoint"
	"tokenhub/internal/gjl"
	"tokenhub/internal/model"
	"tokenhub/internal/privatefs"
)

type Publish struct {
	Kind       string `json:"kind,omitempty"`
	Address    string `json:"rpc_address,omitempty"`
	ListenerID string `json:"listener_id"`
	ServerName string `json:"server_name"`
	Bootstrap  string `json:"bootstrap_address,omitempty"`
}
type Config struct {
	HubURL          string        `json:"hub_url"`
	WebURL          string        `json:"web_url,omitempty"`
	TLSKeyPin       string        `json:"hub_tls_key_pin,omitempty"`
	StateDir        string        `json:"state_dir"`
	CAFile          string        `json:"hub_ca_file,omitempty"`
	DevHTTP         bool          `json:"allow_loopback_http"`
	IPC             string        `json:"gjl_ipc"`
	Listen          string        `json:"listen,omitempty"`
	BootstrapListen string        `json:"bootstrap_listen,omitempty"`
	Publish         []Publish     `json:"publish"`
	Bindings        []gjl.Binding `json:"bindings"`
	Consumer        *gjl.Binding  `json:"consumer,omitempty"`
}
type Identity struct {
	HubURL   string `json:"hub_url"`
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
}

func Load(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF {
		return cfg, errors.New("invalid_connector_config")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return cfg, err
	}
	if cfg.StateDir == "" {
		return cfg, errors.New("state_dir_required")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		cfg.StateDir = filepath.Join(base, cfg.StateDir)
	}
	if cfg.CAFile != "" && !filepath.IsAbs(cfg.CAFile) {
		cfg.CAFile = filepath.Join(base, cfg.CAFile)
	}
	if cfg.WebURL != "" {
		if _, err := hubendpoint.Parse(cfg.WebURL, cfg.DevHTTP); err != nil {
			return cfg, errors.New("invalid_web_url")
		}
	}
	validationHTTP, err := HTTPClient(cfg.HubURL, cfg.DevHTTP, cfg.CAFile, cfg.TLSKeyPin)
	if err != nil {
		return cfg, err
	}
	validationHTTP.CloseIdleConnections()
	if cfg.IPC == "" {
		return cfg, errors.New("gjl_ipc_required")
	}
	ipc, err := gjl.New(cfg.IPC)
	if err != nil {
		return cfg, err
	}
	ipc.Close()
	if cfg.Consumer != nil && !cfg.Consumer.Valid() {
		return cfg, errors.New("invalid_consumer_binding")
	}
	for _, address := range []string{cfg.Listen, cfg.BootstrapListen} {
		if address != "" && !loopback(address) {
			return cfg, errors.New("loopback_listener_required")
		}
	}
	if cfg.BootstrapListen != "" && (cfg.Listen == "" || cfg.Listen == cfg.BootstrapListen) {
		return cfg, errors.New("distinct_listener_required")
	}
	if len(cfg.Publish) > 16 {
		return cfg, errors.New("publish_limit")
	}
	seen := map[string]bool{}
	vaults := 0
	for _, p := range cfg.Publish {
		if !p.Valid() || seen[p.ListenerID] {
			return cfg, errors.New("invalid_publish")
		}
		if model.ServiceKind(p.Kind) == "vault" {
			vaults++
		}
		seen[p.ListenerID] = true
	}
	if vaults > 1 {
		return cfg, errors.New("invalid_publish")
	}
	seen = map[string]bool{}
	for _, b := range cfg.Bindings {
		if b.ServiceID == "" || !b.Valid() || seen[b.ServiceID] {
			return cfg, errors.New("invalid_binding")
		}
		seen[b.ServiceID] = true
	}
	return cfg, nil
}

func (p Publish) Valid() bool {
	if p.ListenerID == "" || !model.Identifier(p.ListenerID) || p.ServerName == "" || !model.Identifier(p.ServerName) || p.Bootstrap != "" && !loopback(p.Bootstrap) {
		return false
	}
	switch model.ServiceKind(p.Kind) {
	case "gate":
		return p.Address == ""
	case "vault":
		return loopback(p.Address) && p.Address != p.Bootstrap
	default:
		return false
	}
}
func loopback(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip, e := netip.ParseAddr(host)
	n, portErr := strconv.ParseUint(port, 10, 16)
	return err == nil && e == nil && ip.IsLoopback() && portErr == nil && n > 0
}
func HTTPClient(base string, dev bool, caFile string, pins ...string) (*http.Client, error) {
	u, err := hubendpoint.Parse(base, dev)
	if err != nil {
		return nil, errors.New("invalid_hub_url")
	}
	ip, _ := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && dev && ip.IsLoopback()) {
		return nil, errors.New("hub_https_required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if len(pins) > 1 {
		return nil, errors.New("hub_tls_pin_invalid")
	}
	if len(pins) == 1 && pins[0] != "" {
		pin, err := hex.DecodeString(pins[0])
		if err != nil || len(pin) != sha256.Size || u.Scheme != "https" || caFile != "" {
			return nil, errors.New("hub_tls_pin_invalid")
		}
		// A pin is supplied by the HTTPS website's install command, never learned
		// from this connection. Replace CA trust with exact key trust while still
		// verifying the certificate's IP/name, expiry and server-auth usage.
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("hub_tls_pin_mismatch")
			}
			leaf := state.PeerCertificates[0]
			digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if !bytes.Equal(digest[:], pin) {
				return errors.New("hub_tls_pin_mismatch")
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: u.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("hub_ca_unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("hub_ca_invalid")
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func SaveIdentity(dir string, id Identity) error {
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return privatefs.Write(filepath.Join(dir, "identity.json"), raw)
}
func readIdentity(dir, hub string) (Identity, error) {
	var id Identity
	path := filepath.Join(dir, "identity.json")
	if err := privatefs.File(path); err != nil {
		return id, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return id, errors.New("enroll_required")
	}
	if json.Unmarshal(raw, &id) != nil || len(id.Token) != 43 || id.HubURL != strings.TrimRight(hub, "/") {
		return id, errors.New("identity_invalid")
	}
	return id, nil
}
