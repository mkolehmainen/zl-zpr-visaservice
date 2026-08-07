package components

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// TestVisaTableUsesActorCNs checks the visa table labels source and destination
// with actor CNs when known, and keeps the raw address otherwise.
func TestVisaTableUsesActorCNs(t *testing.T) {
	actors := []dataplane.ActorDescriptor{
		{CName: "node-nyc", ZprAddress: "fd5a:5052:90de::1"},
	}

	visas := []dataplane.VisaDescriptor{
		{
			ID:         1,
			SourceAddr: strPtr("fd5a:5052:90de::1"),
			DestAddr:   strPtr("fd5a:5052:90de::99"),
			Proto:      "TCP",
		},
	}

	out := ansi.Strip(activeVisaTable(120, visas, actors, -1))

	if !strings.Contains(out, "node-nyc") {
		t.Errorf("expected source CN in output:\n%s", out)
	}

	if !strings.Contains(out, "fd5a:5052:90de::99") {
		t.Errorf("expected unknown destination address to survive:\n%s", out)
	}

	if strings.Contains(out, "fd5a:5052:90de::1 ") {
		t.Errorf("expected source address to be replaced by its CN:\n%s", out)
	}
}

// TestFormatRemaining checks the near-term duration forms, the expired case, and
// that a far-future expiry collapses to a rounded year count.
func TestFormatRemaining(t *testing.T) {
	cases := []struct {
		offset time.Duration
		want   string
	}{
		{-time.Second, "expired"},
		// A second of slack: Expires is whole seconds, so the remaining interval
		// lands just under each offset and the minute forms truncate.
		{30*time.Minute + time.Second, "30m"},
		{2*time.Hour + 15*time.Minute + time.Second, "2h 15m"},
		{50*time.Hour + time.Second, "2d 2h"},
		{100 * 365 * 24 * time.Hour, "100y"},
	}

	for _, c := range cases {
		visa := dataplane.VisaDescriptor{Expires: time.Now().Add(c.offset).Unix()}
		if got := formatRemaining(visa); got != c.want {
			t.Errorf("formatRemaining(+%s) = %q, want %q", c.offset, got, c.want)
		}
	}
}
