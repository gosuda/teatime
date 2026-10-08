package gjl

import (
	"context"
	"errors"
	"time"
)

// Vault has a dedicated credential RPC server, not a configuration Listener.
// Addresses are explicitly allowlisted in the local Connector configuration.
func (c *Client) VaultReady(ctx context.Context) (bool, error) {
	var status struct {
		Instances []struct {
			Role      string `json:"role"`
			Lifecycle string `json:"lifecycle"`
		} `json:"instances"`
	}
	if err := c.Call(ctx, "GET", "/v1/status", nil, &status); err != nil {
		return false, err
	}
	for _, instance := range status.Instances {
		if instance.Role == "vault" {
			return instance.Lifecycle == "running", nil
		}
	}
	return false, errors.New("ipc_protocol_invalid")
}

type VaultConnection struct {
	ID          string `json:"id"`
	RPCBaseURL  string `json:"rpc_base_url"`
	ServerName  string `json:"server_name"`
	Trust       string `json:"server_trust_ref"`
	Certificate string `json:"certificate_binding_id"`
}
type VaultCatalog struct {
	Schema      int               `json:"schema_version"`
	Revision    uint64            `json:"revision"`
	Connections []VaultConnection `json:"connections"`
	Bindings    []struct {
		ConnectionID string `json:"connection_id"`
		CredentialID string `json:"credential_id"`
		GrantID      string `json:"grant_id"`
		Provider     string `json:"provider_surface"`
	} `json:"bindings"`
}

func (c *Client) VaultCatalog(ctx context.Context) (VaultCatalog, error) {
	var response struct {
		Version string       `json:"version"`
		Catalog VaultCatalog `json:"catalog"`
	}
	err := c.Call(ctx, "GET", "/v1/door/vault/runtime-catalog", nil, &response)
	if err == nil && (response.Version != "v1" || response.Catalog.Schema != 1 || len(response.Catalog.Connections) > 64) {
		err = errors.New("ipc_protocol_invalid")
	}
	return response.Catalog, err
}

func (v VaultConnection) Binding() Binding {
	return Binding{Kind: "vault", ConnectionID: v.ID, Identity: v.Certificate, Trust: v.Trust, ServerName: v.ServerName}
}

type VaultCertificate struct {
	ID                string    `json:"binding_id"`
	ConnectionID      string    `json:"connection_id"`
	RPCBaseURL        string    `json:"rpc_base_url"`
	ServerName        string    `json:"server_name"`
	Trust             string    `json:"server_trust_ref"`
	State             string    `json:"state"`
	Expires           time.Time `json:"certificate_not_after"`
	InvitationExpires time.Time `json:"invitation_expires_at"`
}

func (c *Client) VaultCertificates(ctx context.Context) ([]VaultCertificate, error) {
	var status struct {
		Version  string             `json:"version"`
		Bindings []VaultCertificate `json:"bindings"`
	}
	if err := c.Call(ctx, "GET", "/v1/door/vault/certificates/status", nil, &status); err != nil {
		return nil, err
	}
	if status.Version != "v1" || status.Bindings == nil || len(status.Bindings) > 64 {
		return nil, errors.New("ipc_protocol_invalid")
	}
	return status.Bindings, nil
}

func (v VaultCertificate) Binding() Binding {
	return Binding{Kind: "vault", ConnectionID: v.ConnectionID, Identity: v.ID, Trust: v.Trust, ServerName: v.ServerName}
}

func (v VaultCertificate) Usable() bool {
	return v.Binding().Valid() && (v.State == "ready" && v.Expires.After(time.Now()) || v.State == "submitted" && v.InvitationExpires.After(time.Now()))
}

// A Vault's RPC endpoint is part of its persisted enrollment identity. Never
// rewrite it or obtain trust/grants from Hub metadata. Revalidate every heartbeat.
// Certificate collection itself calls PairDoor over this mTLS RPC endpoint, so
// a locally submitted enrollment may open the tunnel before grants exist.
// The Vault remains the authority for pairing approval and every credential grant.
func (c *Client) ValidateVault(ctx context.Context, b Binding, address string) error {
	certificates, err := c.VaultCertificates(ctx)
	if err != nil {
		return err
	}
	for _, v := range certificates {
		if v.ID == b.Identity && v.ConnectionID == b.ConnectionID && v.RPCBaseURL == "https://"+address && v.ServerName == b.ServerName && v.Trust == b.Trust && v.Usable() {
			return nil
		}
	}
	return errors.New("pairing_required")
}
