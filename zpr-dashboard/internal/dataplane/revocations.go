package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

type AuthRevokeDescriptor struct {
	// ID isn't in the entry body; it comes from the list that named it
	ID int `json:"-"`

	Type string `json:"ty"`
	CN   string `json:"cn"`
}

type RevocationIDEntry struct {
	ID int `json:"id"`
}

func (c *Client) ListRevocations(ctx context.Context) ([]RevocationIDEntry, error) {
	path := "/admin/authrevoke"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List revocations: %s", resp.Status)
	}

	var entries []RevocationIDEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Decode revocations: %w", err)
	}

	return entries, nil
}

func (c *Client) GetRevocation(ctx context.Context, id string) (AuthRevokeDescriptor, error) {
	path := "/admin/authrevoke/" + url.PathEscape(id)

	resp, err := c.Get(ctx, path)
	if err != nil {
		return AuthRevokeDescriptor{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AuthRevokeDescriptor{}, fmt.Errorf("Get revocation %s: %s", id, resp.Status)
	}

	var desc AuthRevokeDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&desc); err != nil {
		return AuthRevokeDescriptor{}, fmt.Errorf("Decode revocation: %w", err)
	}

	return desc, nil
}

func (c *Client) FetchRevocations(ctx context.Context) ([]AuthRevokeDescriptor, error) {
	entries, err := c.ListRevocations(ctx)
	if err != nil {
		return nil, err
	}

	var revocations []AuthRevokeDescriptor
	for _, entry := range entries {
		desc, err := c.GetRevocation(ctx, strconv.Itoa(entry.ID))
		if err != nil {
			continue
		}

		desc.ID = entry.ID
		revocations = append(revocations, desc)
	}

	return revocations, nil
}
