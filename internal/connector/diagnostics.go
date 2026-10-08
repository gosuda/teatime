package connector

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"tokenhub/internal/gjl"
	"tokenhub/internal/model"
)

type Check struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Action string `json:"action,omitempty"`
}
type HubStatus struct {
	Device       model.Device    `json:"device"`
	Services     []model.Service `json:"services"`
	LatestReport string          `json:"latest_report"`
}

func safeCode(err error, fallback string) string {
	if err == nil {
		return "ok"
	}
	var e *APIError
	if errors.As(err, &e) {
		return e.Code
	}
	switch err.Error() {
	case "ipc_unavailable", "ipc_rejected", "ipc_protocol_invalid", "route_conflict", "pairing_required":
		return err.Error()
	}
	return fallback
}
func Diagnose(ctx context.Context, cfg Config, deep bool) []Check {
	checks := []Check{}
	add := func(name, state, detail, action string) { checks = append(checks, Check{name, state, detail, action}) }
	httpClient, err := HTTPClient(cfg.HubURL, cfg.DevHTTP, cfg.CAFile, cfg.TLSKeyPin)
	var remote HubStatus
	if err != nil {
		add("hub", "failed", "hub_tls_config_invalid", "Check the Hub CA and HTTPS URL")
	} else {
		defer httpClient.CloseIdleConnections()
		api := &API{Base: cfg.HubURL, HTTP: httpClient}
		var health map[string]any
		err = api.Call(ctx, "GET", "/healthz", nil, &health)
		add("hub", checkState(err), safeCode(err, "hub_unavailable"), "Check Hub availability and organization lookup permissions")
		id, e := readIdentity(cfg.StateDir, cfg.HubURL)
		if e != nil {
			add("device", "failed", "enroll_required", "Run hubconn setup")
		} else {
			api.Token = id.Token
			e = api.Call(ctx, "GET", "/api/connector/status", nil, &remote)
			add("device", checkState(e), safeCode(e, "device_auth_unavailable"), "Approve enrollment or ask the Hub operator to check membership")
		}
	}
	ipc, e := gjl.New(cfg.IPC)
	var doc gjl.Document
	if e == nil {
		defer ipc.Close()
		doc, e = ipc.Config(ctx)
	}
	add("gjl_ipc", checkState(e), safeCode(e, "ipc_unavailable"), "Start the gjl daemon in the selected profile")
	bindings := append([]gjl.Binding(nil), cfg.Bindings...)
	if cfg.Consumer != nil {
		bindings = append(bindings, *cfg.Consumer)
	}
	if len(bindings) == 0 {
		add("route", "not_configured", "no_consumer_route", "Run setup after preparing a Door-to-Gate Route or local Vault certificate connection")
	} else if e != nil {
		add("route", "unavailable", "ipc_unavailable", "")
	} else {
		state, detail := "ok", "local_route_present"
		for _, b := range bindings {
			if model.ServiceKind(b.Kind) == "vault" {
				if err := ipc.ValidateVault(ctx, b, cfg.Listen); err != nil {
					state, detail = "failed", safeCode(err, "vault_connection_unavailable")
				}
				continue
			}
			found := false
			for _, raw := range doc.Routes {
				var v struct {
					gjl.Route
					Upstream   string `json:"upstream"`
					Identity   string `json:"gate_client_identity_ref"`
					Trust      string `json:"gate_server_trust_ref"`
					ServerName string `json:"gate_server_name"`
				}
				if json.Unmarshal(raw, &v) == nil && v.ID == b.RouteID && v.Role == "door" && v.Target == "gate" {
					found = true
					if remote.Device.Applied != "" && (b.ServiceID == "" || b.ServiceID == remote.Device.Selected) && (v.Upstream != "https://"+cfg.Listen || v.Identity != b.Identity || v.Trust != b.Trust || v.ServerName != b.ServerName) {
						state, detail = "failed", "route_conflict"
					}
				}
			}
			if !found {
				state, detail = "failed", "pairing_required"
			}
		}
		if remote.Device.Selected != "" && remote.Device.Selected != remote.Device.Applied {
			state, detail = "pending", "route_not_applied"
		}
		add("route", state, detail, "Select an approved service; resolve local Route conflicts")
	}
	if !deep {
		add("certificates", "unchecked", "run_doctor", "Run hubconn doctor for certificate expiry checks")
	} else if ipc == nil || e != nil {
		add("certificates", "unavailable", "ipc_unavailable", "")
	} else {
		catalog := loadCertCatalog(ctx, ipc)
		gateBindings := []gjl.Binding{}
		for _, b := range bindings {
			if model.ServiceKind(b.Kind) == "gate" {
				gateBindings = append(gateBindings, b)
				continue
			}
			err := ipc.ValidateVault(ctx, b, cfg.Listen)
			add("vault_connection", checkState(err), safeCode(err, "vault_connection_unavailable"), "Use the enrolled local RPC address; collect the certificate and approve pairing in gjl")
			runtimeCatalog, err := ipc.VaultCatalog(ctx)
			state, detail := "pending", "vault_credential_bindings_required"
			if err != nil {
				state, detail = "unavailable", safeCode(err, "vault_catalog_unavailable")
			} else {
				for _, v := range runtimeCatalog.Connections {
					if v.ID == b.ConnectionID && v.Certificate == b.Identity && v.RPCBaseURL == "https://"+cfg.Listen && v.Trust == b.Trust && v.ServerName == b.ServerName {
						state, detail = "ok", "vault_credential_bindings_present"
					}
				}
			}
			add("vault_credentials", state, detail, "In gjl, approve this Door and grant individual credentials, bind them to the Vault connection, then select them in a Door provider Route")
		}
		if len(gateBindings) > 0 {
			var result struct {
				Bindings []struct {
					Identity   string    `json:"identity_ref"`
					Trust      string    `json:"server_trust_ref"`
					ServerName string    `json:"server_name"`
					State      string    `json:"state"`
					Expires    time.Time `json:"certificate_not_after"`
				} `json:"bindings"`
			}
			lookupErr := ipc.Call(ctx, "GET", "/v1/door/gate/certificates/status", nil, &result)
			state, detail := "ok", "certificate_valid"
			rank := map[string]int{"ok": 0, "warning": 1, "unavailable": 2, "failed": 3}
			for _, b := range gateBindings {
				candidateState, candidateDetail := "unavailable", "certificate_status_unavailable"
				native := false
				for _, v := range result.Bindings {
					if v.Identity == b.Identity && v.Trust == b.Trust && v.ServerName == b.ServerName {
						native = true
						candidateState, candidateDetail = "ok", "certificate_valid"
						if v.State != "ready" || !v.Expires.After(time.Now()) {
							candidateState, candidateDetail = "failed", "certificate_pairing_or_renewal_required"
						} else if time.Until(v.Expires) < 7*24*time.Hour {
							candidateState, candidateDetail = "warning", "certificate_expiring"
						}
					}
				}
				if !native {
					externalState, externalDetail, present := catalog.clientState(b)
					if present {
						candidateState, candidateDetail = externalState, externalDetail
					} else if lookupErr == nil {
						candidateState, candidateDetail = "failed", "certificate_pairing_required"
					}
				}
				if rank[candidateState] > rank[state] {
					state, detail = candidateState, candidateDetail
				}
			}
			add("certificates", state, detail, "Complete or renew certificate registration in gjl")
		} else if len(bindings) == 0 {
			add("certificates", "not_configured", "no_consumer_binding", "")
		}
		gatePublications := []Publish{}
		for _, p := range cfg.Publish {
			if model.ServiceKind(p.Kind) == "gate" {
				gatePublications = append(gatePublications, p)
				continue
			}
			ready, err := ipc.VaultReady(ctx)
			state, detail := checkState(err), safeCode(err, "vault_status_unavailable")
			if err == nil && !ready {
				state, detail = "failed", "vault_not_running"
			}
			if !p.Valid() {
				state, detail = "failed", "invalid_publish"
			}
			add("vault_publication", state, detail, "Start Vault in the selected gjl profile and check the allowlisted local RPC and certificate registration addresses")
			var cert struct {
				Expires time.Time `json:"authority_not_after"`
			}
			err = ipc.Call(ctx, "POST", "/v1/vault/certificates/status", map[string]any{"version": "v1", "limit": 1}, &cert)
			state, detail = checkState(err), safeCode(err, "vault_certificate_status_unavailable")
			if err == nil && !cert.Expires.After(time.Now()) {
				state, detail = "failed", "vault_authority_expired"
			}
			add("vault_certificates", state, detail, "Check Vault certificate authority in gjl")
		}
		if len(gatePublications) > 0 {
			var result struct {
				Expires time.Time `json:"authority_not_after"`
			}
			err := ipc.Call(ctx, "POST", "/v1/gate/certificates/status", map[string]any{"version": "v1", "limit": 100}, &result)
			state, detail := checkState(err), safeCode(err, "gate_certificate_status_unavailable")
			if err == nil && !result.Expires.After(time.Now()) {
				state, detail = "failed", "gate_authority_expired"
			}
			product := false
			for _, p := range gatePublications {
				serverFound := false
				for _, l := range doc.Listeners {
					if l.ID == p.ListenerID {
						if l.ClientTrust == "gjl-product-gate-doors" {
							product = true
						}
						for _, v := range catalog.Catalog.Servers {
							if v.ID == l.ServerIdentity {
								serverFound = true
								certState, certDetail := certificateState(v.Path, p.ServerName)
								add("gate_server_certificate", certState, certDetail, "Renew the Gate server certificate")
							}
						}
					}
				}
				if !serverFound {
					add("gate_server_certificate", "unknown", "certificate_source_unavailable", "Check the Gate server certificate in gjl")
				}
			}
			if err != nil && !product {
				state, detail = "unchecked", "external_gate_trust_check_server_certificate"
			}
			add("gate_certificates", state, detail, "Check Gate certificate authority in gjl")
		}
	}
	var snapshot Snapshot
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, "status.json"))
	if err != nil || json.Unmarshal(raw, &snapshot) != nil || time.Since(snapshot.Updated) > 45*time.Second {
		add("runtime", "stale", "connector_not_running_or_snapshot_stale", "Run hubconn run")
	} else {
		state := "ok"
		if snapshot.Status != "ready" || snapshot.Hub != "ok" {
			state = "degraded"
		}
		detail := snapshot.Status
		if snapshot.Hub != "ok" {
			detail = snapshot.Hub
		}
		add("runtime", state, detail, "")
	}
	path := filepath.Join(cfg.StateDir, "outbox.db")
	if _, err := os.Stat(path); err != nil {
		add("usage_sync", "unavailable", "outbox_unavailable", "Run Connector to initialize local reporting")
	} else {
		u := url.URL{Path: filepath.ToSlash(path)}
		db, err := sql.Open("sqlite", "file:"+u.EscapedPath()+"?mode=ro")
		if err == nil {
			defer db.Close()
			var pending int
			err = db.QueryRowContext(ctx, "SELECT count(*) FROM deliveries WHERE pending=1").Scan(&pending)
			if err == nil {
				state, detail := "ok", "no_pending_reports"
				if pending > 0 {
					state, detail = "pending", "reports_pending"
				}
				if snapshot.Usage != "" {
					state, detail = "delayed", snapshot.Usage
				}
				add("usage_sync", state, detail, "Check Hub access and the published Gate usage ledger")
			}
		}
		if err != nil {
			add("usage_sync", "unavailable", "outbox_read_failed", "Check state permissions and disk space")
		}
	}
	return checks
}
func checkState(err error) string {
	if err != nil {
		return "failed"
	}
	return "ok"
}
