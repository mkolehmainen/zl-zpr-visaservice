package components

import (
	"image/color"
	"time"

	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

type AuthState int

const (
	AuthUnknown AuthState = iota
	AuthValid
	AuthExpired
)

// A null auth_exp means no expiry, not passed
func ActorAuthState(actor dataplane.ActorDescriptor) AuthState {
	if actor.AuthExp == nil {
		return AuthUnknown
	}

	if time.Unix(*actor.AuthExp, 0).Before(time.Now()) {
		return AuthExpired
	}

	return AuthValid
}

func authStateName(s AuthState) string {
	switch s {
	case AuthValid:
		return "Valid"
	case AuthExpired:
		return "Expired"
	default:
		return "Unknown"
	}
}

func authStateColor(s AuthState) color.Color {
	switch s {
	case AuthValid:
		return styles.ColorGreen
	case AuthExpired:
		return styles.ColorRed
	default:
		return styles.ColorDimmed
	}
}

// Nodes are flagged explicitly
func actorRole(actor dataplane.ActorDescriptor) string {
	if actor.Node {
		return "node"
	}

	if roles := actor.Attr("zpr.role"); len(roles) > 0 {
		return roles[0]
	}

	return "actor"
}

func actorCounts(actors []dataplane.ActorDescriptor) (valid int, expired int) {
	for _, actor := range actors {
		switch ActorAuthState(actor) {
		case AuthValid:
			valid++
		case AuthExpired:
			expired++
		}
	}

	return valid, expired
}
