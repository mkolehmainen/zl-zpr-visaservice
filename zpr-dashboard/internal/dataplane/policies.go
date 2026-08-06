package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type PolicyBundle struct {
	ConfigID  int    `json:"config_id"`
	Version   string `json:"version"`
	Format    string `json:"format"`
	Container string `json:"container"`
}

type policyList struct {
	ConfigIDs []int `json:"config_ids"`
	ID        *int  `json:"id"`
}

func (l policyList) ids() []int {
	if len(l.ConfigIDs) > 0 {
		return l.ConfigIDs
	}

	if l.ID != nil {
		return []int{*l.ID}
	}

	return nil
}

// The API only exposes the bundle base64-encoded, and DecodedLen counts the
// padding as bytes that are not there.
func (p PolicyBundle) Size() int {
	return base64.StdEncoding.DecodedLen(len(p.Container)) -
		len(p.Container) + len(strings.TrimRight(p.Container, "="))
}

func (c *Client) ListPolicies(ctx context.Context) ([]int, error) {
	path := "/admin/policies"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List policies: %s", resp.Status)
	}

	var list policyList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("Decode policies: %w", err)
	}

	return list.ids(), nil
}

func (c *Client) GetPolicy(ctx context.Context, id string) (PolicyBundle, error) {
	path := "/admin/policies/" + url.PathEscape(id)

	resp, err := c.Get(ctx, path)
	if err != nil {
		return PolicyBundle{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PolicyBundle{}, fmt.Errorf("Get policy %s: %s", id, resp.Status)
	}

	var bundle PolicyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return PolicyBundle{}, fmt.Errorf("Decode policy: %w", err)
	}

	return bundle, nil
}

func (c *Client) GetCurrentPolicy(ctx context.Context) (PolicyBundle, error) {
	path := "/admin/policies/curr"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return PolicyBundle{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PolicyBundle{}, fmt.Errorf("Get current policy: %s", resp.Status)
	}

	var bundle PolicyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return PolicyBundle{}, fmt.Errorf("Decode current policy: %w", err)
	}

	return bundle, nil
}

func (c *Client) FetchPolicies(ctx context.Context) ([]PolicyBundle, error) {
	ids, err := c.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var policies []PolicyBundle
	for _, id := range ids {
		bundle, err := c.GetPolicy(ctx, strconv.Itoa(id))
		if err != nil {
			continue
		}
		policies = append(policies, bundle)
	}

	return policies, nil
}
