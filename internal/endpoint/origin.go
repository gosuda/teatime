// Package endpoint owns canonical origin validation shared by both binaries.
package endpoint

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func Parse(value string, development bool) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(value, "\r\n\t ") {
		return nil, errors.New("invalid_endpoint_url")
	}
	ip, _ := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(development && u.Scheme == "http" && ip.IsLoopback()) {
		return nil, errors.New("endpoint_https_required")
	}
	if u.Port() != "" {
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("invalid_endpoint_port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid_endpoint_port")
	}
	return u, nil
}
