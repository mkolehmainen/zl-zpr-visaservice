package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

type Endpoint struct {
	Proto string
	Port  string
}

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

	return services, nil
}
