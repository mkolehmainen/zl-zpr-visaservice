package components

import (
	"strings"
	"time"

	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

// actorDock resolves the CN of the dock an actor connects through, from its
// zpr.connect_via address. Falls back to the raw address when no actor matches
// it, and to "" when the attribute (or its value) is absent.
// ponytail: linear scan, build an addr→CN map if the actor count gets large.
func actorDock(actors []dataplane.ActorDescriptor, actor dataplane.ActorDescriptor) string {
	via := actor.Attr("zpr.connect_via")
	if len(via) == 0 || via[0] == "" {
		return ""
	}

	for _, candidate := range actors {
		if candidate.ZprAddress == via[0] && candidate.CName != "" {
			return candidate.CName
		}
	}

	return via[0]
}

// formatTTL renders how long until expiresAt as a duration, eg "4h23m7s".
// Returns "" when there is no expiry and "expired" once the time has passed.
func formatTTL(expiresAt int64, now time.Time) string {
	if expiresAt == 0 {
		return ""
	}

	remaining := time.Unix(expiresAt, 0).Sub(now)
	if remaining <= 0 {
		return "expired"
	}

	if years, ok := timefmt.FarFuture(expiresAt, now); ok {
		return years
	}

	return remaining.String()
}

// displayAttrs returns the actor's non-zpr. attributes, leaving the actor's own
// slice order untouched. GetActor already sorts Attrs by key, so the filtered
// copy stays sorted.
func displayAttrs(actor dataplane.ActorDescriptor) []dataplane.Attribute {
	var attrs []dataplane.Attribute
	for _, attr := range actor.Attrs {
		if !strings.HasPrefix(attr.Key, "zpr.") {
			attrs = append(attrs, attr)
		}
	}

	return attrs
}

// formatAttr renders one attribute as "key value(s) (ttl)", dropping the TTL
// suffix when the attribute never expires.
func formatAttr(attr dataplane.Attribute, now time.Time) string {
	line := label(attr.Key) + " " + strings.Join(attr.Values, ",")

	if ttl := formatTTL(attr.ExpiresAt, now); ttl != "" {
		line += " (" + ttl + ")"
	}

	return line
}
