package dataplane

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

type ActorDescriptor struct {
	CName      string      `json:"cn"`
	Created    int64       `json:"created"` // always 0: create time isn't tracked yet
	Ident      string      `json:"ident"`   // identity values joined with "|"
	Node       bool        `json:"node"`
	ZprAddress string      `json:"zpr_addr"`
	Attrs      []Attribute `json:"attrs"`

	// Null when the actor has no authentication expiry.
	AuthExp     *int64           `json:"auth_exp"`     // seconds since epoch
	NodeDetails *NodeRecordBrief `json:"node_details"` // nil for adapters
}

type Attribute struct {
	Key       string   `json:"key"`
	Values    []string `json:"value"`
	ExpiresAt int64    `json:"expires_at"` // seconds since epoch
}

func (a ActorDescriptor) Attr(key string) []string {
	for _, attr := range a.Attrs {
		if attr.Key == key {
			return attr.Values
		}
	}

	return nil
}

type NodeRecordBrief struct {
	PendingInstall int    `json:"pending_install"` // visas queued for install
	LastContact    *int64 `json:"last_contact"`    // seconds since epoch

	VisaRequests    int `json:"visa_requests"`
	ConnectRequests int `json:"connect_requests"` // always 0: not tracked yet
	ApprovedVreqs   int `json:"approved_vreqs"`
	DeniedVreqs     int `json:"denied_vreqs"`

	// Nil when the node has never asked for a visa
	LastVreq *int64 `json:"last_vreq"` // seconds since epoch

	// Set together: in sync means a VSS address is recorded
	InSync  bool `json:"in_sync"`
	VssPort *int `json:"vss_port"`

	Adapters []string `json:"adapters"` // CNs of the adapters connected via this node
	Links    []string `json:"links"`    // CNs of this node's topology peers

	Visas             []int64 `json:"visas"`          // installed on the node
	VisasEnqueued     []int64 `json:"visas_enqueued"` // queued for install
	PendingRevocation int     `json:"pending_revocation"`
}

type VisaIDEntry struct {
	ID int64 `json:"id"`
}

func (c *Client) ListNodes(ctx context.Context) ([]CnEntry, error) {
	path := "/admin/actors?" + url.Values{"role": {"node"}}.Encode()

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List nodes: %s", resp.Status)
	}

	var entries []CnEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Decode nodes: %w", err)
	}

	return entries, nil
}

func (c *Client) FetchNodes(ctx context.Context) ([]ActorDescriptor, error) {
	entries, err := c.ListNodes(ctx)
	if err != nil {
		return nil, err
	}

	var nodes []ActorDescriptor
	for _, entry := range entries {
		node, err := c.GetActor(ctx, entry.CName)
		if err != nil {
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

func (c *Client) GetActor(ctx context.Context, cn string) (ActorDescriptor, error) {
	path := "/admin/actors/" + url.PathEscape(cn)

	resp, err := c.Get(ctx, path)
	if err != nil {
		return ActorDescriptor{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ActorDescriptor{}, fmt.Errorf("Get actor %s: %s", cn, resp.Status)
	}

	var actor ActorDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&actor); err != nil {
		return ActorDescriptor{}, fmt.Errorf("Decode actor: %w", err)
	}

	// Stable order so rows don't reshuffle between polls. Every
	// ActorDescriptor comes from here, so views can assume sorted attributes.
	slices.SortFunc(actor.Attrs, func(a, b Attribute) int {
		return cmp.Compare(a.Key, b.Key)
	})

	return actor, nil
}

func (c *Client) ListActorVisas(ctx context.Context, cn string) ([]VisaIDEntry, error) {
	return c.listVisaIDs(ctx, "/admin/actors/"+url.PathEscape(cn)+"/visas", cn)
}

func (c *Client) ListNodeVisas(ctx context.Context, cn string) ([]VisaIDEntry, error) {
	return c.listVisaIDs(ctx, "/admin/nodes/"+url.PathEscape(cn)+"/visas", cn)
}

func (c *Client) listVisaIDs(ctx context.Context, path, cn string) ([]VisaIDEntry, error) {
	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List visas for %s: %s", cn, resp.Status)
	}

	var entries []VisaIDEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Decode visa ids: %w", err)
	}

	return entries, nil
}

func (c *Client) FetchActorVisas(ctx context.Context, cn string) ([]VisaDescriptor, error) {
	ids, err := c.ListActorVisas(ctx, cn)
	if err != nil {
		return nil, err
	}

	var visas []VisaDescriptor
	for _, entry := range ids {
		visa, err := c.GetVisa(ctx, entry.ID)
		if err != nil {
			continue
		}
		visas = append(visas, visa)
	}
	sortVisas(visas)

	return visas, nil
}
