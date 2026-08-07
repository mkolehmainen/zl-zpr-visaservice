package dataplane

import (
	"context"
	"errors"
	"fmt"
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

	// A visa can expire or be revoked between the list and its detail fetch, so
	// that loss is expected and simply drops out of the set. Any other failure
	// would undercount silently, so the whole refresh fails instead.
	var recent []VisaDescriptor
	for _, entry := range ids {
		visa, err := c.GetVisa(ctx, entry.ID)
		if errors.Is(err, ErrVisaGone) {
			continue
		}
		if err != nil {
			return VisaSnapshot{}, fmt.Errorf("fetch active visa %d: %w", entry.ID, err)
		}
		recent = append(recent, visa)
	}
	sortVisas(recent)

	snapshot := VisaSnapshot{
		ActiveCount:  len(recent),
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
