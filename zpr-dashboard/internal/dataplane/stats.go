package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type Stats struct {
	Values map[string]string `json:"stats"`
}

const (
	StatUptime           = "uptime" // seconds since the service started
	StatVisaRequests     = "visa_requests"
	StatVisasApproved    = "visa_requests_approved"
	StatVisasDenied      = "visa_requests_denied"
	StatVisaFailed       = "visa_request_failed"
	StatVisaTimeout      = "visa_request_timeout"
	StatNodeConnected    = "node_connections_success"
	StatNodeConnectFail  = "node_connections_failed"
	StatAuthorizeConnect = "authorize_connect_success"
	StatAuthorizeFail    = "authorize_connect_failed"
)

func (s Stats) Count(name string) (int, bool) {
	raw, ok := s.Values[name]
	if !ok {
		return 0, false
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}

	return value, true
}

func (s Stats) CountOr(name string, fallback int) int {
	if value, ok := s.Count(name); ok {
		return value
	}

	return fallback
}

func (c *Client) GetStats(ctx context.Context) (Stats, error) {
	resp, err := c.Get(ctx, "/admin/stats")
	if err != nil {
		return Stats{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Stats{}, fmt.Errorf("Get stats: %s", resp.Status)
	}

	var stats Stats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return Stats{}, fmt.Errorf("Decode stats: %w", err)
	}

	return stats, nil
}
