package dataplane

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type ServiceDescriptor struct {
	ServiceName    string `json:"service_name"`
	ActorCN        string `json:"actor_cn"`
	ZprAddress     string `json:"zpr_addr"`
	DockZprAddress string `json:"dock_zpr_addr"`
	Kind           string `json:"service_kind"`
	Endpoints      string `json:"service_endpoints"`
}

// Hosts reports whether addr is one of the addresses this service answers on.
func (s ServiceDescriptor) Hosts(addr string) bool {
	return addr != "" && (addr == s.ZprAddress || addr == s.DockZprAddress)
}

type Endpoint struct {
	Proto string
	Port  string
}

// ponytail: parses the server's display string
// ("TCP/443,ICMP/128,TCP/8000-8080"). If admin_service.rs changes that format
// counts silently fall to zero — upgrade path is structured endpoints on
// ServiceDescriptor.
func (s ServiceDescriptor) ServiceEndpoints() []Endpoint {
	if s.Endpoints == "" {
		return nil
	}

	var endpoints []Endpoint
	for _, entry := range strings.Split(s.Endpoints, ",") {
		proto, port, _ := strings.Cut(strings.TrimSpace(entry), "/")
		if proto == "" {
			continue
		}

		endpoints = append(endpoints, Endpoint{Proto: proto, Port: port})
	}

	return endpoints
}

// visaProto canonicalises the protocol name a visa payload carries.
func visaProto(proto string) string {
	switch p := strings.ToUpper(strings.TrimSpace(proto)); p {
	case "PROTO_6":
		return "TCP"
	case "PROTO_17":
		return "UDP"
	case "PROTO_58":
		return "ICMP"
	default:
		return p
	}
}

// endpointProto canonicalises the protocol name a declared endpoint carries.
// An endpoint says IPV6_ICMP or PROTO_58 where a visa just says ICMP, while an
// endpoint's plain ICMP (or PROTO_1) is IPv4 and must not match those visas.
func endpointProto(proto string) string {
	switch p := strings.ToUpper(strings.TrimSpace(proto)); p {
	case "IPV6_ICMP":
		return "ICMP"
	case "ICMP", "PROTO_1":
		return "ICMPV4"
	default:
		return visaProto(p)
	}
}

// Matches reports whether proto/port fall within this declared endpoint. An
// endpoint with no port (or port zero) constrains the protocol only; malformed
// ports fail closed.
func (e Endpoint) Matches(proto string, port int) bool {
	canon := endpointProto(e.Proto)
	if canon != visaProto(proto) {
		return false
	}

	spec := strings.TrimSpace(e.Port)
	if spec == "" || spec == "0" {
		return true
	}

	lowText, highText, isRange := strings.Cut(spec, "-")
	low, err := strconv.Atoi(strings.TrimSpace(lowText))
	if err != nil {
		return false
	}
	if !isRange {
		return port == low
	}

	high, err := strconv.Atoi(strings.TrimSpace(highText))
	if err != nil || high < low {
		return false
	}
	if canon == "ICMP" {
		// An ICMPv6 range names a request/response type pair, not a span.
		return port == low || port == high
	}

	return port >= low && port <= high
}

// Targets reports whether the visa was granted for traffic to this service:
// its service-side address is one the service answers on and its protocol and
// port fall within one of the service's declared endpoints.
func (s ServiceDescriptor) Targets(v VisaDescriptor) bool {
	addr, port, ok := v.ServiceSide()
	if !ok || !s.Hosts(addr) {
		return false
	}

	for _, endpoint := range s.ServiceEndpoints() {
		if endpoint.Matches(v.Proto, port) {
			return true
		}
	}

	return false
}

// The server formats the trusted-service api name with Rust's Debug.
func (s ServiceDescriptor) KindName() string {
	if api, ok := strings.CutPrefix(s.Kind, `Trusted("`); ok {
		return "Trusted: " + strings.TrimSuffix(api, `")`)
	}

	return s.Kind
}

type ServiceIDEntry struct {
	Name string `json:"id"`
}

func (c *Client) ListServices(ctx context.Context) ([]ServiceIDEntry, error) {
	path := "/admin/services"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List services: %s", resp.Status)
	}

	var entries []ServiceIDEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Decode services: %w", err)
	}

	return entries, nil
}

func (c *Client) GetService(ctx context.Context, name string) (ServiceDescriptor, error) {
	path := "/admin/services/" + url.PathEscape(name)

	resp, err := c.Get(ctx, path)
	if err != nil {
		return ServiceDescriptor{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ServiceDescriptor{}, fmt.Errorf("Get service %s: %s", name, resp.Status)
	}

	var svc ServiceDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&svc); err != nil {
		return ServiceDescriptor{}, fmt.Errorf("Decode service: %w", err)
	}

	return svc, nil
}

func (c *Client) FetchServices(ctx context.Context) ([]ServiceDescriptor, error) {
	entries, err := c.ListServices(ctx)
	if err != nil {
		return nil, err
	}

	var services []ServiceDescriptor
	for _, entry := range entries {
		svc, err := c.GetService(ctx, entry.Name)
		if err != nil {
			continue
		}
		services = append(services, svc)
	}

	// Stable order so rows don't reshuffle between polls.
	slices.SortFunc(services, func(a, b ServiceDescriptor) int {
		return cmp.Compare(a.ServiceName, b.ServiceName)
	})

	return services, nil
}
