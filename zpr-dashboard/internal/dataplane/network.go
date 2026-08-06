package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type NodeConnections struct {
	Node string `json:"node"` // the node's CN

	// Unresolvable peers arrive as "cn_missing:<addr>"
	Connections []string `json:"connections"`
}

type NetworkDetails struct {
	Network []NodeConnections `json:"network"`
}

func (c *Client) GetNetwork(ctx context.Context) ([]NodeConnections, error) {
	resp, err := c.Get(ctx, "/admin/network")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Get network: %s", resp.Status)
	}

	var details NetworkDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("Decode network: %w", err)
	}

	return details.Network, nil
}
