package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ActorEntry is one row of the GET /admin/actors listing. The ZPR address
// identifies the actor; the CN is a display label that may be absent
// (decoded as "" when the wire carries null).
type ActorEntry struct {
	ZprAddress string `json:"zpr_addr"`
	CName      string `json:"cn"`
}

// List all actors
func (c *Client) ListActors(ctx context.Context) ([]ActorEntry, error) {
	path := "/admin/actors"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List actors: %s", resp.Status)
	}

	var entries []ActorEntry
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
		actor, err := c.GetActor(ctx, entry.ZprAddress)
		if err != nil {
			// keep an actor we can address but not describe
			actors = append(actors, ActorDescriptor{ZprAddress: entry.ZprAddress, CName: entry.CName, Undescribed: true})
			continue
		}

		actors = append(actors, actor)
	}

	return actors, nil
}
