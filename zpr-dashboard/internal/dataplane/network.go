package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// A single link between two nodes, as reported by GET /admin/network.
type NodeConnection struct {
	NodeA      string `json:"node_a_addr"`
	NodeB      string `json:"node_b_addr"`
	CType      string `json:"ctype"`            // UP | DOWN | INVALID
	SubstrateA string `json:"node_a_substrate"` // "host:port"; empty for INVALID links
	SubstrateB string `json:"node_b_substrate"`
}

type NetworkDetails struct {
	Network []NodeConnection `json:"network"`
}

func (c *Client) GetNetwork(ctx context.Context) ([]NodeConnection, error) {
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

	// Stable order so rows don't reshuffle between polls.
	slices.SortFunc(details.Network, func(a, b NodeConnection) int {
		if c := compareAddr(a.NodeA, b.NodeA); c != 0 {
			return c
		}
		return compareAddr(a.NodeB, b.NodeB)
	})

	return details.Network, nil
}

// compareAddr orders two IP address strings numerically, falling back to
// lexical order if either fails to parse.
func compareAddr(a, b string) int {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	if errX != nil || errY != nil {
		return strings.Compare(a, b)
	}
	return x.Compare(y)
}
