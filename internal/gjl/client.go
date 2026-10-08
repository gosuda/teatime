// Package gjl implements a narrow IPC v1 adapter, without importing gjl internals.
package gjl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"tokenhub/internal/model"
)

type Client struct{ HTTP *http.Client }

func New(address string) (*Client, error) {
	if err := validateAddress(address); err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, address) }, DisableCompression: true}
	return &Client{HTTP: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.HTTP.CloseIdleConnections() }
func (c *Client) Call(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errors.New("ipc_encode_failed")
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://gjl"+path, reader)
	if err != nil {
		return errors.New("ipc_request_failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("ipc_unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode == 409 {
		return errors.New("route_conflict")
	}
	if res.StatusCode != 200 {
		return errors.New("ipc_rejected")
	}
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		return errors.New("ipc_protocol_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return errors.New("ipc_response_limit")
	}
	if json.Unmarshal(raw, out) != nil {
		return errors.New("ipc_protocol_invalid")
	}
	return nil
}

type Listener struct {
	ID             string            `json:"id"`
	Role           string            `json:"role"`
	Address        string            `json:"address"`
	Transport      string            `json:"transport_mode"`
	RouteID        string            `json:"route_id"`
	Matchers       []json.RawMessage `json:"route_matchers"`
	ServerIdentity string            `json:"server_identity_ref"`
	ClientTrust    string            `json:"client_trust_ref"`
}
type Route struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Target   string `json:"target"`
	Provider string `json:"provider_surface"`
	Usage    bool   `json:"usage_tracking_enabled"`
}
type Document struct {
	Schema    int               `json:"schema_version"`
	Revision  uint64            `json:"revision"`
	Listeners []Listener        `json:"listeners"`
	Routes    []json.RawMessage `json:"routes"`
}

func (c *Client) Config(ctx context.Context) (Document, error) {
	var v struct {
		Config Document `json:"config"`
	}
	err := c.Call(ctx, "GET", "/v1/config", nil, &v)
	if err == nil && (v.Config.Schema != 1 || v.Config.Revision < 1) {
		err = errors.New("ipc_protocol_invalid")
	}
	return v.Config, err
}

type Binding struct {
	Kind         string `json:"kind,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	ServiceID    string `json:"service_id"`
	RouteID      string `json:"door_route_id"`
	Identity     string `json:"identity_ref"`
	Trust        string `json:"trust_ref"`
	ServerName   string `json:"server_name"`
}

func (b Binding) Valid() bool {
	if b.Identity == "" || b.Trust == "" || b.ServerName == "" {
		return false
	}
	switch model.ServiceKind(b.Kind) {
	case "gate":
		return b.RouteID != "" && b.ConnectionID == ""
	case "vault":
		return b.ConnectionID != "" && b.RouteID == ""
	default:
		return false
	}
}

func (c *Client) Apply(ctx context.Context, b Binding, address string) error {
	if !b.Valid() {
		return errors.New("pairing_required")
	}
	if model.ServiceKind(b.Kind) == "vault" {
		return c.ValidateVault(ctx, b, address)
	}
	doc, err := c.Config(ctx)
	if err != nil {
		return err
	}
	for _, raw := range doc.Routes {
		var route Route
		if json.Unmarshal(raw, &route) != nil {
			return errors.New("ipc_protocol_invalid")
		}
		if route.ID != b.RouteID {
			continue
		}
		if route.Role != "door" || route.Target != "gate" {
			return errors.New("route_conflict")
		}
		var values map[string]any
		if json.Unmarshal(raw, &values) != nil {
			return errors.New("ipc_protocol_invalid")
		}
		target := map[string]any{"upstream": "https://" + address, "gate_client_identity_ref": b.Identity, "gate_server_trust_ref": b.Trust, "gate_server_name": b.ServerName, "usage_tracking_enabled": false}
		changed := false
		for k, v := range target {
			if values[k] != v {
				changed = true
			}
			values[k] = v
		}
		if !changed {
			return nil
		}
		var response struct {
			Config Document `json:"config"`
		}
		err = c.Call(ctx, "PUT", "/v1/config/routes/put", map[string]any{"expected_revision": doc.Revision, "route": values}, &response)
		if err == nil && response.Config.Revision != doc.Revision+1 {
			return errors.New("ipc_protocol_invalid")
		}
		return err
	}
	return errors.New("pairing_required")
}

type LedgerRecord struct {
	model.Usage
	Role   string `json:"role"`
	Latest struct {
		Amount          *string `json:"amount_usd"`
		Kind            string  `json:"kind"`
		Reason          string  `json:"reason"`
		Version         string  `json:"pricing_version"`
		PricingRevision int64   `json:"pricing_revision"`
		Revision        int64   `json:"revision"`
	} `json:"latest"`
}
type Page struct {
	Records []LedgerRecord `json:"records"`
	Cursor  string         `json:"next_cursor"`
}

func (c *Client) Usage(ctx context.Context, route, listener, cursor string, since ...time.Time) (Page, error) {
	var page Page
	filter := map[string]string{"role": "gate", "route_id": route, "listener_id": listener}
	if len(since) > 0 && !since[0].IsZero() {
		filter["start"] = since[0].UTC().Format(time.RFC3339Nano)
	}
	err := c.Call(ctx, "POST", "/v1/usage/query", map[string]any{"filter": filter, "cursor": cursor, "limit": 100}, &page)
	for i := range page.Records {
		v := &page.Records[i]
		v.Amount = v.Latest.Amount
		v.AmountKind = v.Latest.Kind
		v.UnpricedReason = v.Latest.Reason
		v.PricingVersion = v.Latest.Version
		v.PricingRevision = v.Latest.PricingRevision
		v.CalculationRevision = v.Latest.Revision
	}
	return page, err
}
