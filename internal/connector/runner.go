package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"path/filepath"
	"tokenhub/internal/gjl"
	"tokenhub/internal/model"
	"tokenhub/internal/privatefs"
	"tokenhub/internal/transport"
)

type endpoint struct {
	address, bootstrap string
	candidate          model.Candidate
}

func (e endpoint) sameScope(other endpoint) bool {
	return e.address == other.address && e.bootstrap == other.bootstrap &&
		model.ServiceKind(e.candidate.Kind) == model.ServiceKind(other.candidate.Kind) &&
		e.candidate.Key == other.candidate.Key && e.candidate.RouteID == other.candidate.RouteID &&
		e.candidate.Provider == other.candidate.Provider && e.candidate.ServerName == other.candidate.ServerName
}

type publishedStream struct {
	key, service string
	endpoint     endpoint
	cancel       context.CancelFunc
}
type Runner struct {
	Config                                 Config
	API                                    *API
	GJL                                    *gjl.Client
	Outbox                                 *Outbox
	mu                                     sync.RWMutex
	endpoints                              map[string]endpoint
	services                               []model.Service
	selected, applied, status, usageStatus string
	selectionContext                       context.Context
	selectionCancel                        context.CancelFunc
	slots                                  chan struct{}
	connections                            sync.WaitGroup
	publications                           map[*publishedStream]struct{}
}

func (r *Runner) suspendSelection() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.selectionCancel != nil {
		r.selectionCancel()
	}
	r.selectionContext, r.selectionCancel = nil, nil
	r.selected, r.applied = "", ""
}

func New(cfg Config) (*Runner, error) {
	id, err := readIdentity(cfg.StateDir, cfg.HubURL)
	if err != nil {
		return nil, err
	}
	client, err := HTTPClient(cfg.HubURL, cfg.DevHTTP, cfg.CAFile, cfg.TLSKeyPin)
	if err != nil {
		return nil, err
	}
	ipc, err := gjl.New(cfg.IPC)
	if err != nil {
		return nil, err
	}
	outbox, err := OpenOutbox(cfg.StateDir)
	if err != nil {
		ipc.Close()
		return nil, err
	}
	return NewWithClients(cfg, &API{Base: cfg.HubURL, Token: id.Token, HTTP: client}, ipc, outbox), nil
}
func NewWithClients(cfg Config, api *API, ipc *gjl.Client, outbox *Outbox) *Runner {
	return &Runner{Config: cfg, API: api, GJL: ipc, Outbox: outbox, endpoints: map[string]endpoint{}, slots: make(chan struct{}, 32), status: "ready"}
}
func (r *Runner) Close() { r.GJL.Close(); r.API.HTTP.CloseIdleConnections(); _ = r.Outbox.Close() }
func localTarget(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("listener_address_invalid")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("listener_address_invalid")
	}
	if ip.IsUnspecified() {
		if ip.Is4() {
			ip = netip.MustParseAddr("127.0.0.1")
		} else {
			ip = netip.MustParseAddr("::1")
		}
	}
	if !ip.IsLoopback() {
		return "", errors.New("loopback_gate_required")
	}
	return net.JoinHostPort(ip.String(), port), nil
}
func (r *Runner) discover(ctx context.Context) ([]model.Candidate, map[string]endpoint, *model.Preparation, error) {
	profile := "custom"
	for _, development := range []bool{false, true} {
		if address, err := gjl.ProfileAddress(development); err == nil && address == r.Config.IPC {
			profile = "installed"
			if development {
				profile = "development"
			}
		}
	}
	preparation := &model.Preparation{Profile: profile}
	doc, err := r.GJL.Config(ctx)
	if err != nil {
		return nil, nil, preparation, err
	}
	options, err := discoverSetupDocument(doc)
	if err != nil {
		return nil, nil, preparation, err
	}
	options.discoverVault(ctx, r.GJL)
	preparation.Setup = &model.LocalSetup{DoorRoutes: len(options.Door), GateListeners: len(options.Gates), BootstrapConfigured: r.Config.BootstrapListen != ""}
	preparation.Setup.VaultReady = options.VaultReady
	if options.VaultError == nil {
		n := len(options.Vaults)
		preparation.Setup.VaultConnections = &n
	}
	for _, v := range options.Vaults {
		for _, b := range append(append([]gjl.Binding(nil), r.Config.Bindings...), consumerBindings(r.Config.Consumer)...) {
			if model.ServiceKind(b.Kind) == "vault" && b.ConnectionID == v.ConnectionID && b.Identity == v.ID && b.Trust == v.Trust && b.ServerName == v.ServerName && VaultLocalAddress(v.RPCBaseURL) == r.Config.Listen {
				preparation.Setup.ConsumerConfigured = true
			}
		}
	}
	for _, b := range options.Door {
		if c := r.Config.Consumer; c != nil && r.Config.Listen != "" && c.RouteID == b.RouteID && c.Identity == b.Identity && c.Trust == b.Trust && c.ServerName == b.ServerName {
			preparation.Setup.ConsumerConfigured = true
		}
		for _, c := range r.Config.Bindings {
			if r.Config.Listen != "" && c.RouteID == b.RouteID && c.Identity == b.Identity && c.Trust == b.Trust && c.ServerName == b.ServerName {
				preparation.Setup.ConsumerConfigured = true
			}
		}
	}
	for _, b := range options.Gates {
		for _, p := range r.Config.Publish {
			if b.ListenerID == p.ListenerID {
				preparation.Setup.PublishConfigured++
			}
		}
	}
	routes := map[string]gjl.Route{}
	for _, raw := range doc.Routes {
		var v gjl.Route
		if json.Unmarshal(raw, &v) != nil {
			return nil, nil, preparation, errors.New("ipc_protocol_invalid")
		}
		routes[v.ID] = v
	}
	result := []model.Candidate{}
	endpoints := map[string]endpoint{}
	for _, p := range r.Config.Publish {
		if model.ServiceKind(p.Kind) == "vault" {
			if !p.Valid() || options.VaultReady == nil || !*options.VaultReady {
				continue
			}
			preparation.Setup.PublishConfigured++
			c := model.Candidate{Kind: "vault", Key: p.ListenerID, ServerName: p.ServerName}
			conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", p.Address)
			if err == nil {
				c.Ready = true
				conn.Close()
			}
			result = append(result, c)
			if c.Ready {
				endpoints[c.Key] = endpoint{address: p.Address, bootstrap: p.Bootstrap, candidate: c}
			}
			continue
		}
		if model.ServiceKind(p.Kind) != "gate" {
			continue
		}
		for _, l := range doc.Listeners {
			if l.ID != p.ListenerID || l.Role != "gate" || l.Transport != "gate_paired_door_mtls" || len(l.Matchers) != 0 {
				continue
			}
			route, ok := routes[l.RouteID]
			if !ok || route.Role != "gate" || route.Target != "provider" {
				continue
			}
			address, err := localTarget(l.Address)
			if err != nil {
				continue
			}
			c := model.Candidate{Kind: "gate", Key: l.ID, RouteID: route.ID, Provider: route.Provider, ServerName: p.ServerName, UsageEnabled: route.Usage}
			conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", address)
			if err == nil {
				c.Ready = true
				conn.Close()
			}
			result = append(result, c)
			if c.Ready {
				endpoints[l.ID] = endpoint{address: address, bootstrap: p.Bootstrap, candidate: c}
			}
		}
	}
	return result, endpoints, preparation, nil
}
func (r *Runner) heartbeat(ctx context.Context) error {
	candidates, endpoints, preparation, err := r.discover(ctx)
	status := "ready"
	if err != nil {
		status = "ipc_unavailable"
		candidates = []model.Candidate{}
		endpoints = map[string]endpoint{}
	}
	r.mu.Lock()
	r.endpoints = endpoints
	r.revalidatePublicationsLocked()
	applied := r.applied
	if r.status != "ready" && status == "ready" {
		status = r.status
	}
	if r.usageStatus != "" && status == "ready" {
		status = r.usageStatus
	}
	r.mu.Unlock()
	var response model.HeartbeatResponse
	if err := r.API.Call(ctx, "POST", "/api/connector/heartbeat", model.Heartbeat{Candidates: candidates, Applied: applied, Status: status, Preparation: preparation}, &response); err != nil {
		return err
	}
	services, scopeErr := r.authorizeServices(ctx, response.Services, candidates)
	r.mu.Lock()
	r.services = services
	r.revalidatePublicationsLocked()
	if scopeErr != nil {
		r.usageStatus = "usage_delayed"
	}
	r.mu.Unlock()
	if response.Selected != "" && (response.Selection == nil || response.Selection.ID != response.Selected) {
		r.suspendSelection()
		return errors.New("hub_catalog_invalid")
	}
	if err := r.selectService(ctx, response.Selected, response.Selection); err != nil {
		return err
	}
	r.mu.RLock()
	nowApplied, nowStatus := r.applied, r.status
	r.mu.RUnlock()
	if nowApplied != applied {
		var confirmed model.HeartbeatResponse
		if err := r.API.Call(ctx, "POST", "/api/connector/heartbeat", model.Heartbeat{Candidates: candidates, Applied: nowApplied, Status: nowStatus, Preparation: preparation}, &confirmed); err != nil {
			return err
		}
		if confirmed.Selected != response.Selected {
			r.suspendSelection()
		}
	}
	return nil
}

func (r *Runner) publicationAllowedLocked(service string, ep endpoint) bool {
	for _, s := range r.services {
		if s.ID == service && ep.candidate.Matches(s) {
			return true
		}
	}
	return false
}

func (r *Runner) revalidatePublicationsLocked() {
	for active := range r.publications {
		ep, exists := r.endpoints[active.key]
		if !exists || !ep.sameScope(active.endpoint) || !r.publicationAllowedLocked(active.service, ep) {
			active.cancel()
		}
	}
}

func (r *Runner) authorizeServices(ctx context.Context, services []model.Service, candidates []model.Candidate) ([]model.Service, error) {
	accepted := []model.Service{}
	var failure error
	if len(services) > 64 {
		return accepted, errors.New("hub_catalog_invalid")
	}
	for _, s := range services {
		allowed := false
		for _, c := range candidates {
			if c.Valid() && c.Matches(s) && s.ID != "" && len(s.ID) <= 64 {
				allowed = true
				s.UsageEnabled = c.UsageEnabled
				break
			}
		}
		if !allowed {
			failure = errors.New("hub_catalog_invalid")
			continue
		}
		since, err := r.Outbox.PinPublication(ctx, s)
		if err != nil {
			failure = err
			continue
		}
		s.PublishedAt = since
		accepted = append(accepted, s)
	}
	return accepted, failure
}
func (r *Runner) selectService(ctx context.Context, selected string, selection ...*model.Service) error {
	r.mu.RLock()
	old := r.selected
	r.mu.RUnlock()
	if selected != old {
		r.suspendSelection()
	}
	if selected == "" {
		r.mu.Lock()
		r.status = "ready"
		r.mu.Unlock()
		return nil
	}
	if r.Config.Listen == "" {
		r.mu.Lock()
		r.status = "listener_unavailable"
		r.mu.Unlock()
		return nil
	}
	var binding *gjl.Binding
	for _, b := range r.Config.Bindings {
		if b.ServiceID == selected {
			copy := b
			binding = &copy
		}
	}
	if binding == nil && r.Config.Consumer != nil {
		copy := *r.Config.Consumer
		copy.ServiceID = selected
		binding = &copy
	}
	if binding != nil && len(selection) > 0 && selection[0] != nil {
		s := selection[0]
		if model.ServiceKind(binding.Kind) != model.ServiceKind(s.Kind) || binding.ServerName != s.ServerName {
			binding = nil
		}
	}
	status := "pairing_required"
	applied := ""
	if binding != nil {
		if err := r.GJL.Apply(ctx, *binding, r.Config.Listen); err != nil {
			status = "route_conflict"
			if err.Error() == "ipc_unavailable" {
				status = "ipc_unavailable"
			}
			if err.Error() == "pairing_required" {
				status = "pairing_required"
			}
		} else {
			status = "ready"
			applied = selected
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if applied == "" && r.applied != "" && r.selectionCancel != nil {
		r.selectionCancel()
		r.selectionContext, r.selectionCancel = nil, nil
	}
	r.status = status
	r.applied = applied
	// Only the separate bootstrap listener may use an unapplied selection.
	if r.selectionContext == nil {
		r.selectionContext, r.selectionCancel = context.WithCancel(ctx)
		r.selected = selected
	}
	return nil
}
func (r *Runner) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	start := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	listeners := []net.Listener{}
	defer func() {
		cancel()
		for _, l := range listeners {
			_ = l.Close()
		}
		r.mu.Lock()
		if r.selectionCancel != nil {
			r.selectionCancel()
		}
		r.mu.Unlock()
		wg.Wait()
		r.connections.Wait()
	}()
	for _, item := range []struct{ address, purpose string }{{r.Config.Listen, "data"}, {r.Config.BootstrapListen, "bootstrap"}} {
		if item.address == "" {
			continue
		}
		l, err := net.Listen("tcp", item.address)
		if err != nil {
			for _, old := range listeners {
				old.Close()
			}
			return errors.New("connector_listener_unavailable")
		}
		listeners = append(listeners, l)
		purpose := item.purpose
		start(func() { r.accept(ctx, l, purpose) })
	}
	start(func() { r.workLoop(ctx) })
	start(func() { r.usageLoop(ctx) })
	var retry backoff
	for {
		err := r.heartbeat(ctx)
		if err != nil {
			r.suspendSelection()
		}
		r.saveStatus(err)
		if err != nil && err.Error() == "device_revoked" {
			return err
		}
		if !waitRetry(ctx, retry.next(err, 5*time.Second)) {
			return nil
		}
	}
}
func (r *Runner) accept(ctx context.Context, l net.Listener, purpose string) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case r.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		r.connections.Add(1)
		go func() {
			defer r.connections.Done()
			defer func() { <-r.slots }()
			defer conn.Close()
			r.mu.RLock()
			service := r.selected
			selectedCtx := r.selectionContext
			applied := r.applied
			r.mu.RUnlock()
			if service == "" || selectedCtx == nil || purpose == "data" && applied != service {
				return
			}
			connectionCtx, cancel := context.WithCancel(selectedCtx)
			defer cancel()
			ws, err := r.API.Socket(connectionCtx, tunnelPath(service, purpose), "")
			if err != nil {
				return
			}
			defer ws.CloseNow()
			transport.Bridge(connectionCtx, conn, transport.Stream(connectionCtx, ws))
		}()
	}
}
func (r *Runner) workLoop(ctx context.Context) {
	var retry backoff
	for ctx.Err() == nil {
		var work model.Work
		err := r.API.Call(ctx, "GET", "/api/connector/work", nil, &work)
		if err != nil {
			if !waitRetry(ctx, retry.next(err, 2*time.Second)) {
				return
			}
			continue
		}
		retry.failures = 0
		if work.Ticket == "" {
			continue
		}
		select {
		case r.slots <- struct{}{}:
			r.connections.Add(1)
			go func() { defer r.connections.Done(); defer func() { <-r.slots }(); r.serve(ctx, work) }()
		default:
		}
	}
}
func (r *Runner) serve(ctx context.Context, work model.Work) {
	if work.Purpose != "data" && work.Purpose != "bootstrap" {
		return
	}
	r.mu.RLock()
	ep, ok := r.endpoints[work.Key]
	allowed := r.publicationAllowedLocked(work.ServiceID, ep)
	r.mu.RUnlock()
	if !ok || !allowed {
		return
	}
	address := ep.address
	if work.Purpose == "bootstrap" {
		address = ep.bootstrap
	}
	if address == "" {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	active := &publishedStream{key: work.Key, service: work.ServiceID, endpoint: ep, cancel: cancel}
	r.mu.Lock()
	if current, exists := r.endpoints[work.Key]; !exists || !current.sameScope(ep) || !r.publicationAllowedLocked(work.ServiceID, ep) {
		r.mu.Unlock()
		return
	}
	if r.publications == nil {
		r.publications = make(map[*publishedStream]struct{})
	}
	r.publications[active] = struct{}{}
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.publications, active); r.mu.Unlock() }()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return
	}
	defer conn.Close()
	ws, err := r.API.Socket(ctx, "/api/attach", work.Ticket)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	transport.Bridge(ctx, conn, transport.Stream(ctx, ws))
}
func (r *Runner) Scan(ctx context.Context) error {
	r.mu.RLock()
	services := append([]model.Service(nil), r.services...)
	r.mu.RUnlock()
	// Re-read the local catalog: an unrelated route cannot become reportable
	// through a remote service ID or a configuration change between heartbeats.
	candidates, _, _, err := r.discover(ctx)
	if err != nil {
		return err
	}
	services, err = r.authorizeServices(ctx, services, candidates)
	if err != nil {
		return err
	}
	for _, s := range services {
		if model.ServiceKind(s.Kind) != "gate" || !s.UsageEnabled {
			continue
		}
		cursor := ""
		seen := map[string]bool{}
		for n := 0; n < 1000; n++ {
			page, err := r.GJL.Usage(ctx, s.RouteID, s.Key, cursor, s.PublishedAt)
			if err != nil {
				return err
			}
			values := []model.Usage{}
			for _, v := range page.Records {
				if v.Role != "gate" || v.StartedAt.Before(s.PublishedAt) || v.RouteID != s.RouteID || v.ListenerID != s.Key || v.Provider != s.Provider {
					return errors.New("usage_scope_invalid")
				}
				values = append(values, v.Usage)
			}
			if err = r.Outbox.Enqueue(ctx, s.ID, values); err != nil {
				return err
			}
			if page.Cursor == "" {
				break
			}
			if seen[page.Cursor] {
				return errors.New("usage_cursor_invalid")
			}
			seen[page.Cursor] = true
			cursor = page.Cursor
			if n == 999 {
				return errors.New("scan_limit")
			}
		}
	}
	return nil
}
func (r *Runner) usageLoop(ctx context.Context) {
	var retry backoff
	delay := 10 * time.Second
	for {
		if !waitRetry(ctx, delay) {
			return
		}
		status := ""
		err := r.Scan(ctx)
		if err != nil {
			status = "usage_delayed"
			if err.Error() == "scan_limit" {
				status = "scan_limit"
			}
		}
		if deliveryErr := r.Outbox.Deliver(ctx, r.API); deliveryErr != nil {
			err = deliveryErr
			status = "usage_delayed"
		}
		r.mu.Lock()
		r.usageStatus = status
		r.mu.Unlock()
		delay = retry.next(err, 10*time.Second)
	}
}

// Snapshot has no tokens, request bodies, or provider errors.
type Snapshot struct {
	Updated  time.Time `json:"updated"`
	Selected string    `json:"selected"`
	Applied  string    `json:"applied"`
	Status   string    `json:"status"`
	Usage    string    `json:"usage"`
	Hub      string    `json:"hub"`
}

func (r *Runner) saveStatus(err error) {
	if r.Config.StateDir == "" {
		return
	}
	r.mu.RLock()
	s := Snapshot{Updated: time.Now().UTC(), Selected: r.selected, Applied: r.applied, Status: r.status, Usage: r.usageStatus, Hub: "ok"}
	r.mu.RUnlock()
	if err != nil {
		s.Hub = "unavailable"
		var e *APIError
		if errors.As(err, &e) {
			s.Hub = e.Code
		}
	}
	raw, _ := json.Marshal(s)
	_ = privatefs.Write(filepath.Join(r.Config.StateDir, "status.json"), raw)
}
