package model

import (
	"errors"
	"math/big"
	"regexp"
	"time"
)

type User struct {
	ID          string `json:"id"`
	GitHubLogin string `json:"github_login"`
	Name        string `json:"name"`
	Admin       bool   `json:"admin"`
	SuperAdmin  bool   `json:"super_admin"`
}
type Candidate struct {
	Kind         string `json:"kind,omitempty"`
	Key          string `json:"key"`
	RouteID      string `json:"route_id"`
	Provider     string `json:"provider"`
	ServerName   string `json:"server_name"`
	Ready        bool   `json:"ready"`
	UsageEnabled bool   `json:"usage_enabled"`
}

// Preparation contains only local setup readiness. It carries no local paths,
// credentials, certificate material, invitations, or management addresses.
type Preparation struct {
	Profile string      `json:"profile"`
	Setup   *LocalSetup `json:"setup"`
}
type LocalSetup struct {
	VaultReady          *bool `json:"vault_ready,omitempty"`
	VaultConnections    *int  `json:"vault_connections,omitempty"`
	DoorRoutes          int   `json:"door_routes"`
	GateListeners       int   `json:"gate_listeners"`
	ConsumerConfigured  bool  `json:"consumer_configured"`
	BootstrapConfigured bool  `json:"bootstrap_configured"`
	PublishConfigured   int   `json:"publish_configured"`
}
type Device struct {
	ID          string       `json:"id"`
	UserID      string       `json:"user_id"`
	Name        string       `json:"name"`
	LastSeen    int64        `json:"last_seen"`
	Status      string       `json:"status"`
	Selected    string       `json:"selected_service"`
	Applied     string       `json:"applied_service"`
	Candidates  []Candidate  `json:"candidates"`
	Revoked     bool         `json:"revoked"`
	Preparation *Preparation `json:"preparation,omitempty"`
}
type Service struct {
	Kind         string    `json:"kind"`
	ID           string    `json:"id"`
	OwnerID      string    `json:"owner_id"`
	OwnerName    string    `json:"owner_name"`
	DeviceID     string    `json:"device_id"`
	Key          string    `json:"key"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	RouteID      string    `json:"route_id"`
	Provider     string    `json:"provider"`
	ServerName   string    `json:"server_name"`
	Enabled      bool      `json:"enabled"`
	Online       bool      `json:"online"`
	Access       string    `json:"access"`
	UsageEnabled bool      `json:"usage_enabled"`
	PublishedAt  time.Time `json:"published_at"`
}
type Tokens struct {
	Input        *int64 `json:"input"`
	Output       *int64 `json:"output"`
	CacheRead    *int64 `json:"cache_read"`
	CacheWrite   *int64 `json:"cache_write"`
	CacheWrite5m *int64 `json:"cache_write_5m"`
	CacheWrite1h *int64 `json:"cache_write_1h"`
	Reasoning    *int64 `json:"reasoning"`
}
type Usage struct {
	ID                  string    `json:"id"`
	StartedAt           time.Time `json:"started_at"`
	CompletedAt         time.Time `json:"completed_at"`
	RouteID             string    `json:"route_id"`
	ListenerID          string    `json:"listener_id"`
	Provider            string    `json:"provider_surface"`
	Model               string    `json:"model"`
	ModelSource         string    `json:"model_source"`
	ServiceTier         string    `json:"service_tier"`
	ActorID             string    `json:"actor_id"`
	CommercialPlan      string    `json:"commercial_plan"`
	Outcome             string    `json:"outcome"`
	Quality             string    `json:"quality"`
	MissingReason       string    `json:"missing_reason"`
	Reported            Tokens    `json:"reported"`
	Billable            Tokens    `json:"billable"`
	Amount              *string   `json:"amount_usd"`
	AmountKind          string    `json:"amount_kind"`
	PricingVersion      string    `json:"pricing_version"`
	PricingRevision     int64     `json:"pricing_revision"`
	CalculationRevision int64     `json:"calculation_revision"`
	UnpricedReason      string    `json:"unpriced_reason"`
}
type Report struct {
	ServiceID string `json:"service_id"`
	Version   int64  `json:"version"`
	Usage     Usage  `json:"usage"`
}
type Work struct {
	Ticket    string `json:"ticket"`
	Key       string `json:"key"`
	ServiceID string `json:"service_id"`
	Purpose   string `json:"purpose"`
}
type Heartbeat struct {
	Candidates  []Candidate  `json:"candidates"`
	Applied     string       `json:"applied_service"`
	Status      string       `json:"status"`
	Preparation *Preparation `json:"preparation,omitempty"`
}
type HeartbeatResponse struct {
	Selection *Service  `json:"selection,omitempty"`
	Selected  string    `json:"selected_service"`
	Services  []Service `json:"services"`
}

// Empty kind is the original Gate wire format. Unknown kinds never gain access.
func ServiceKind(kind string) string {
	if kind == "" {
		return "gate"
	}
	return kind
}

func (c Candidate) Valid() bool {
	if c.Key == "" || c.ServerName == "" || !Identifier(c.Key) || !Identifier(c.ServerName) {
		return false
	}
	switch ServiceKind(c.Kind) {
	case "gate":
		return c.RouteID != "" && c.Provider != "" && Identifier(c.RouteID) && Identifier(c.Provider)
	case "vault":
		return c.RouteID == "" && c.Provider == "" && !c.UsageEnabled
	default:
		return false
	}
}

func (c Candidate) Matches(s Service) bool {
	return ServiceKind(c.Kind) == ServiceKind(s.Kind) && c.Key == s.Key && c.RouteID == s.RouteID && c.Provider == s.Provider && c.ServerName == s.ServerName
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$`)
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$`)

func Identifier(v string) bool { return v == "" || safeID.MatchString(v) }
func Amount(v string) bool     { return decimal.MatchString(v) }
func (u Usage) Validate() error {
	if u.ID == "" || u.RouteID == "" || u.ListenerID == "" || u.Provider == "" || u.StartedAt.IsZero() || u.CompletedAt.Before(u.StartedAt) || u.CompletedAt.After(time.Now().Add(24*time.Hour)) {
		return errors.New("invalid_usage")
	}
	for _, v := range []string{u.ID, u.RouteID, u.ListenerID, u.Provider, u.Model, u.ModelSource, u.ServiceTier, u.ActorID, u.CommercialPlan, u.Outcome, u.Quality, u.MissingReason, u.AmountKind, u.PricingVersion, u.UnpricedReason} {
		if !Identifier(v) {
			return errors.New("invalid_usage")
		}
	}
	for _, t := range []Tokens{u.Reported, u.Billable} {
		for _, v := range []*int64{t.Input, t.Output, t.CacheRead, t.CacheWrite, t.CacheWrite5m, t.CacheWrite1h, t.Reasoning} {
			if v != nil && (*v < 0 || *v > 1_000_000_000_000) {
				return errors.New("invalid_usage")
			}
		}
	}
	if u.Amount != nil && !Amount(*u.Amount) {
		return errors.New("invalid_usage")
	}
	return nil
}
func Sum(amounts []string) string {
	sum := new(big.Rat)
	for _, a := range amounts {
		if n, ok := new(big.Rat).SetString(a); ok {
			sum.Add(sum, n)
		}
	}
	return sum.FloatString(18)
}
