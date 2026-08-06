package app

import (
	"time"

	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

type state struct {
	header struct {
		hoverTab int
		tabStart int
		tabRect  []int
	}

	actor struct {
		selectedIndex int

		// Admin API cannot currently revoke an actor
		revokeOpen  bool
		revokeVisas bool

		actors   []dataplane.ActorDescriptor
		network  []dataplane.NodeConnections
		fetchErr error

		visas            []dataplane.VisaDescriptor
		visasFetchErr    error
		visaCountHistory []int
	}

	visa struct {
		selectedIndex int
		view          components.VisaView

		activeCount  int
		revokedCount int

		// Reported by the service itself, via GET /admin/stats.
		uptime    time.Duration
		requested int
		approved  int
		denied    int

		recentVisas    []dataplane.VisaDescriptor
		activeHistory  []int
		revokedHistory []int
		fetchErr       error
	}

	service struct {
		selectedIndex int

		services []dataplane.ServiceDescriptor
		fetchErr error
	}

	policy struct {
		selectedIndex int

		// Admin API cannot roll a policy back
		rollbackOpen bool

		policies []dataplane.PolicyBundle
		applied  *dataplane.PolicyBundle
		fetchErr error
	}

	revocation struct {
		revocations []dataplane.AuthRevokeDescriptor
		fetchErr    error
	}

	dismissedAlerts map[string]bool
}
