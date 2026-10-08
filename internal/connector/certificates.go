package connector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"time"
	"tokenhub/internal/gjl"
)

type certSource struct {
	ID   string `json:"id"`
	Path string `json:"certificate_path"`
}
type certCatalog struct {
	Catalog struct {
		Servers []certSource `json:"server_identities"`
		Clients []certSource `json:"client_identities"`
		Trust   []struct {
			ID string `json:"id"`
		} `json:"server_trust_bundles"`
	} `json:"catalog"`
}

func loadCertCatalog(ctx context.Context, ipc *gjl.Client) certCatalog {
	var catalog certCatalog
	_ = ipc.Call(ctx, "GET", "/v1/tls-material/catalog", nil, &catalog)
	return catalog
}

// Read only a public certificate selected by a daemon-owned reference. Never
// open private_key_path, persist certificate content, or expose file errors.
func certificateState(path, serverName string) (string, string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return "unavailable", "certificate_file_unavailable"
	}
	f, err := os.Open(path)
	if err != nil {
		return "unavailable", "certificate_file_unavailable"
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "unavailable", "certificate_file_changed"
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return "unavailable", "certificate_file_unavailable"
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "failed", "certificate_invalid"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "failed", "certificate_invalid"
	}
	if serverName != "" && cert.VerifyHostname(serverName) != nil {
		return "failed", "certificate_name_mismatch"
	}
	if time.Now().Before(cert.NotBefore) || !cert.NotAfter.After(time.Now()) {
		return "failed", "certificate_expired_or_not_yet_valid"
	}
	if time.Until(cert.NotAfter) < 7*24*time.Hour {
		return "warning", "certificate_expiring"
	}
	return "ok", "certificate_valid"
}
func (catalog certCatalog) clientState(binding gjl.Binding) (string, string, bool) {
	trust := false
	for _, v := range catalog.Catalog.Trust {
		if v.ID == binding.Trust {
			trust = true
		}
	}
	for _, v := range catalog.Catalog.Clients {
		if v.ID == binding.Identity {
			if !trust {
				return "failed", "certificate_trust_missing", true
			}
			state, detail := certificateState(v.Path, "")
			return state, detail, true
		}
	}
	return "unavailable", "certificate_status_unavailable", false
}
