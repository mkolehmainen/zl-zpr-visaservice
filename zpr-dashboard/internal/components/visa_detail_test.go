package components

import (
	"testing"

	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// TestVisaIssuer checks that the "Issued by" value is read from the
// per-namespace authority attributes (device.zpr.authority /
// user.zpr.authority), combining both when present, and falls back to a dash
// when the actor is unknown or carries no authority.
func TestVisaIssuer(t *testing.T) {
	actorWith := func(attrs ...dataplane.Attribute) []dataplane.ActorDescriptor {
		return []dataplane.ActorDescriptor{{ZprAddress: "fd5a:5052::1", Attrs: attrs}}
	}
	visa := dataplane.VisaDescriptor{RequestingNode: "fd5a:5052::1"}

	cases := []struct {
		name   string
		actors []dataplane.ActorDescriptor
		want   string
	}{
		{
			name:   "device authority only",
			actors: actorWith(dataplane.Attribute{Key: "device.zpr.authority", Values: []string{"zpr-bootstrap"}}),
			want:   "zpr-bootstrap",
		},
		{
			name:   "user authority only",
			actors: actorWith(dataplane.Attribute{Key: "user.zpr.authority", Values: []string{"https://idp.example"}}),
			want:   "https://idp.example",
		},
		{
			name: "both namespaces present",
			actors: actorWith(
				dataplane.Attribute{Key: "device.zpr.authority", Values: []string{"zpr-bootstrap"}},
				dataplane.Attribute{Key: "user.zpr.authority", Values: []string{"https://idp.example"}},
			),
			want: "zpr-bootstrap, https://idp.example",
		},
		{
			name:   "legacy un-namespaced key is ignored",
			actors: actorWith(dataplane.Attribute{Key: "zpr.authority", Values: []string{"stale"}}),
			want:   "—",
		},
		{
			name:   "no authority attributes",
			actors: actorWith(),
			want:   "—",
		},
		{
			name:   "unknown actor",
			actors: nil,
			want:   "—",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := visaIssuer(visa, tc.actors); got != tc.want {
				t.Errorf("visaIssuer() = %q, want %q", got, tc.want)
			}
		})
	}
}
