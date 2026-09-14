package components

import "neboagency.com/zpr-dashborad/internal/dataplane"

// actorLabel is the display label for an actor: the CN when present, the ZPR
// address otherwise — the same fallback endpointLabel established. A CN is
// only a label and may be absent (e.g. an OIDC-only connect); the address is
// always present on a described actor.
func actorLabel(actor dataplane.ActorDescriptor) string {
	if actor.CName != "" {
		return actor.CName
	}

	return actor.ZprAddress
}

// serviceActorLabel labels the actor owning a service: its CN when the
// registration carries one, the service's actor-side address otherwise.
func serviceActorLabel(svc dataplane.ServiceDescriptor) string {
	if svc.ActorCN != "" {
		return svc.ActorCN
	}

	return svc.ZprAddress
}
