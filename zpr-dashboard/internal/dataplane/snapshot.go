package dataplane

import (
	"context"
	"time"
)

type VisaSnapshot struct {
	ActiveCount  int
	RevokedCount int
	RecentVisas  []VisaDescriptor
	Uptime       time.Duration
	Requested    int
	Approved     int
	Denied       int
	Stats        Stats
}

func (c *Client) FetchVisaSnapshot(ctx context.Context) (VisaSnapshot, error) {
	ids, err := c.ListVisas(ctx)
	if err != nil {
		return VisaSnapshot{}, err
	}

	revocations, err := c.ListRevocations(ctx)
	if err != nil {
		return VisaSnapshot{}, err
	}

	var recent []VisaDescriptor
	for _, entry := range ids {
		visa, err := c.GetVisa(ctx, entry.ID)
		if err != nil {
			continue
		}
		recent = append(recent, visa)
	}

	snapshot := VisaSnapshot{
		ActiveCount:  len(ids),
		RevokedCount: len(revocations),
		RecentVisas:  recent,
	}

	// A service that cannot report these still yields a usable snapshot
	stats, err := c.GetStats(ctx)
	if err != nil {
		return snapshot, nil
	}

	snapshot.Stats = stats
	snapshot.Uptime = time.Duration(stats.CountOr(StatUptime, 0)) * time.Second
	snapshot.Requested = stats.CountOr(StatVisaRequests, 0)
	snapshot.Approved = stats.CountOr(StatVisasApproved, 0)
	snapshot.Denied = stats.CountOr(StatVisasDenied, 0)

	return snapshot, nil
}
