package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type ListEntry struct {
	ID int64 `json:"id"`
}

type VisaDescriptor struct {
	ID      int64 `json:"id"`
	Created int64 `json:"created"` // seconds since epoch
	Expires int64 `json:"expires"` // seconds since epoch

	PolicyID       string `json:"policy_id"` // the vinst the visa was issued under
	ZPL            string `json:"zpl"`       // the rule that granted it, "" if unrecorded
	Direction      string `json:"direction"` // "forward" | "reverse"
	RequestingNode string `json:"requesting_node"`

	SourceAddr *string  `json:"source_addr"`
	DestAddr   *string  `json:"dest_addr"`
	SourcePort *int     `json:"source_port"`
	DestPort   *int     `json:"dest_port"`
	Proto      string   `json:"proto"`
	Signals    []string `json:"signals"`
}

func (v VisaDescriptor) Source() string { return derefString(v.SourceAddr) }
func (v VisaDescriptor) Dest() string   { return derefString(v.DestAddr) }

func (v VisaDescriptor) Port() (int, bool) {
	if v.Proto == "ICMP" {
		return derefInt(v.SourcePort)
	}

	return derefInt(v.DestPort)
}

func (v VisaDescriptor) ICMP() (icmpType, icmpCode int, ok bool) {
	if v.Proto != "ICMP" {
		return 0, 0, false
	}

	icmpType, _ = derefInt(v.SourcePort)
	icmpCode, _ = derefInt(v.DestPort)

	return icmpType, icmpCode, true
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func derefInt(value *int) (int, bool) {
	if value == nil {
		return 0, false
	}

	return *value, true
}

func (c *Client) ListVisas(ctx context.Context) ([]ListEntry, error) {
	path := "/admin/visas"

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("List visas: %s", resp.Status)
	}

	var entries []ListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Decode visas: %w", err)
	}

	return entries, nil
}

func (c *Client) GetVisa(ctx context.Context, id int64) (VisaDescriptor, error) {
	path := "/admin/visas/" + strconv.FormatInt(id, 10)

	resp, err := c.Get(ctx, path)
	if err != nil {
		return VisaDescriptor{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VisaDescriptor{}, fmt.Errorf("Get visa %d: %s", id, resp.Status)
	}

	var visa VisaDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&visa); err != nil {
		return VisaDescriptor{}, fmt.Errorf("Decode visa: %w", err)
	}

	return visa, nil
}
