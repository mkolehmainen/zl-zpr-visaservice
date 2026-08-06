package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Returned result, see how we extract json values from it
type CnEntry struct {
	CName       string `json:"cn"`
	CTime       string `json:"ctime"`
	Ident       string `json:"ident"`
	Node        string `json:"node"`
	ZprAddress  string `json:"zpr_addr"`
	NodeDetails string `json:"node_details"`
}

// List all actors
func (c *Client) ListActors(ctx context.Context) ([]CnEntry, error) {
	path := "/admin/actors"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List actors: %s", resp.Status)
	}

	var entries []CnEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Decode actors: %w", err)
	}

	return entries, nil
}

func (c *Client) FetchActors(ctx context.Context) ([]ActorDescriptor, error) {
	entries, err := c.ListActors(ctx)
	if err != nil {
		return nil, err
	}

	var actors []ActorDescriptor
	for _, entry := range entries {
		actor, err := c.GetActor(ctx, entry.CName)
		if err != nil {
			// keep an actor we can name but not describe
			actors = append(actors, ActorDescriptor{CName: entry.CName})
			continue
		}

		actors = append(actors, actor)
	}

	return actors, nil
}
