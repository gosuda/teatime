package connector

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	hubendpoint "tokenhub/internal/endpoint"
)

type API struct {
	Base, Token string
	HTTP        *http.Client
}

// APIError contains only allowlisted codes, never a server's raw error text.
type APIError struct {
	Code       string
	Status     int
	RetryAfter time.Duration
	Temporary  bool
}

func networkError(err error) error {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if strings.Contains(err.Error(), "hub_tls_pin_mismatch") {
		return &APIError{Code: "hub_certificate_invalid"}
	}
	if errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return &APIError{Code: "hub_certificate_invalid"}
	}
	return &APIError{Code: "hub_unavailable", Temporary: true}
}

func (e *APIError) Error() string { return e.Code }
func responseError(res *http.Response) error {
	code := "hub_rejected"
	switch res.StatusCode {
	case 401:
		code = "device_revoked"
	case 403:
		code = "access_denied"
	case 404:
		code = "hub_endpoint_missing"
	case 409:
		code = "selection_changed"
	case 410:
		code = "enrollment_expired"
	case 429:
		code = "hub_rate_limited"
	default:
		if res.StatusCode >= 500 {
			code = "hub_unavailable"
		}
	}
	var payload struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4097))
	if len(raw) <= 4096 && json.Unmarshal(raw, &payload) == nil {
		switch payload.Error {
		case "membership_unavailable", "membership_not_configured", "membership_rate_limited", "membership_permission_denied", "storage_unavailable", "service_offline", "selection_changed", "route_not_applied", "gosuda_membership_required", "github_identity_conflict", "access_required":
			code = payload.Error
		}
	}
	delay := time.Duration(0)
	if seconds, err := strconv.ParseInt(res.Header.Get("Retry-After"), 10, 32); err == nil && seconds > 0 {
		delay = time.Duration(seconds) * time.Second
	} else if date, err := http.ParseTime(res.Header.Get("Retry-After")); err == nil {
		delay = time.Until(date)
	}
	if delay < 0 {
		delay = 0
	}
	if delay > 15*time.Minute {
		delay = 15 * time.Minute
	}
	return &APIError{Code: code, Status: res.StatusCode, RetryAfter: delay, Temporary: res.StatusCode == 429 || res.StatusCode >= 500}
}

type backoff struct{ failures int }

func (b *backoff) next(err error, normal time.Duration) time.Duration {
	if err == nil {
		b.failures = 0
		return normal
	}
	if b.failures < 6 {
		b.failures++
	}
	delay := normal * time.Duration(1<<b.failures)
	if delay > 2*time.Minute {
		delay = 2 * time.Minute
	}
	var failure *APIError
	if errors.As(err, &failure) && failure.RetryAfter > delay {
		delay = failure.RetryAfter
	}
	return delay
}
func waitRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (a *API) Call(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return errors.New("hub_request_invalid")
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, body)
	if err != nil {
		return errors.New("hub_request_invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	res, err := a.HTTP.Do(req)
	if err != nil {
		return networkError(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return responseError(res)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, out) != nil {
		return errors.New("hub_response_invalid")
	}
	return nil
}
func (a *API) Socket(ctx context.Context, path, ticket string) (*websocket.Conn, error) {
	header := http.Header{"Authorization": []string{"Bearer " + a.Token}}
	if ticket != "" {
		header.Set("X-Tunnel-Ticket", ticket)
	}
	base := strings.Replace(a.Base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)
	ws, res, err := websocket.Dial(ctx, base+path, &websocket.DialOptions{HTTPClient: a.HTTP, HTTPHeader: header, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		if res != nil && res.Body != nil {
			defer res.Body.Close()
			return nil, responseError(res)
		}
		return nil, networkError(err)
	}
	return ws, nil
}
func Enroll(ctx context.Context, client *http.Client, base, name, state string, show func(string)) error {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := os.Lstat(filepath.Join(state, "identity.json")); err == nil {
		return errors.New("device_already_enrolled")
	} else if !os.IsNotExist(err) {
		return errors.New("identity_unavailable")
	}
	a := &API{Base: base, HTTP: client}
	var start struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
		WebURL string `json:"web_url"`
	}
	if err := a.Call(ctx, "POST", "/api/enroll/start", map[string]string{"name": name}, &start); err != nil {
		return err
	}
	if start.Secret == "" || start.Code == "" {
		return errors.New("hub_response_invalid")
	}
	show(start.Code)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	var retry backoff
	for {
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return parent.Err()
			}
			return errors.New("enrollment_expired")
		case <-timer.C:
			var result struct {
				Status   string `json:"status"`
				DeviceID string `json:"device_id"`
				Token    string `json:"token"`
			}
			if err := a.Call(ctx, "POST", "/api/enroll/claim", map[string]string{"secret": start.Secret}, &result); err != nil {
				var failure *APIError
				if errors.As(err, &failure) && failure.Temporary {
					timer.Reset(retry.next(err, 2*time.Second))
					continue
				}
				return err
			}
			if result.Status == "approved" {
				if len(result.Token) != 43 || result.DeviceID == "" {
					return errors.New("hub_response_invalid")
				}
				return SaveIdentity(state, Identity{HubURL: base, DeviceID: result.DeviceID, Token: result.Token})
			}
			if result.Status != "pending" {
				return errors.New("hub_response_invalid")
			}
			timer.Reset(retry.next(nil, 2*time.Second))
		}
	}
}

// WebOrigin returns only a validated metadata field from the verified transport.
// An explicit flag from the public website is preferred for approval navigation.
func WebOrigin(ctx context.Context, client *http.Client, base string, development bool) (string, error) {
	var metadata struct {
		WebURL string `json:"web_url"`
	}
	api := &API{Base: base, HTTP: client}
	if err := api.Call(ctx, "GET", "/api/connection-info", nil, &metadata); err != nil {
		return "", err
	}
	if _, err := hubendpoint.Parse(metadata.WebURL, development); err != nil {
		return "", errors.New("invalid_web_url")
	}
	return metadata.WebURL, nil
}
func tunnelPath(service, purpose string) string {
	return "/api/tunnel?service_id=" + url.QueryEscape(service) + "&purpose=" + url.QueryEscape(purpose)
}
