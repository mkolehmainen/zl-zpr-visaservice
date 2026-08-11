package components

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// serviceVisaFixture returns one service plus a forward visa towards it, its
// reverse half, and an unrelated visa on the same address but another port.
func serviceVisaFixture() ([]dataplane.ServiceDescriptor, []dataplane.VisaDescriptor, []dataplane.ActorDescriptor) {
	const svc, peer = "fd5a:5052:90de::30", "fd5a:5052:90de::40"

	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ActorCN: "alpha-cn", ZprAddress: svc, Endpoints: "TCP/443"},
	}
	visas := []dataplane.VisaDescriptor{
		{ID: 1, Direction: "forward", Proto: "TCP", SourceAddr: strPtr(peer), DestAddr: strPtr(svc), SourcePort: intPtr(0), DestPort: intPtr(443)},
		{ID: 2, Direction: "reverse", Proto: "TCP", SourceAddr: strPtr(svc), DestAddr: strPtr(peer), SourcePort: intPtr(443), DestPort: intPtr(0)},
		{ID: 3, Direction: "forward", Proto: "TCP", SourceAddr: strPtr(peer), DestAddr: strPtr(svc), SourcePort: intPtr(0), DestPort: intPtr(9000)},
	}
	actors := []dataplane.ActorDescriptor{{CName: "peer-cn", ZprAddress: peer}}

	return services, visas, actors
}

// TestServiceVisasBothDirections checks both halves of a flow are listed with
// their direction, the peer is the far end in either direction, and a visa on
// another port of the same address is excluded.
func TestServiceVisasBothDirections(t *testing.T) {
	services, visas, actors := serviceVisaFixture()

	out := ansi.Strip(ServiceVisas(80, 20, services, 0, visas, actors, nil))

	for _, want := range []string{"forward", "reverse", "peer-cn"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the table:\n%s", want, out)
		}
	}
	// The peer resolves to a CN in both rows, so the raw address never shows.
	if strings.Contains(out, "fd5a:5052:90de::40") {
		t.Errorf("expected the peer address to be replaced by its CN:\n%s", out)
	}
	// Visa 3 shares the service address but not its declared port.
	if rows := strings.Count(out, "peer-cn"); rows != 2 {
		t.Errorf("expected 2 matching rows, got %d:\n%s", rows, out)
	}
}

// TestServiceVisasFitsBudget checks the pane stays inside its width and height.
func TestServiceVisasFitsBudget(t *testing.T) {
	services, visas, actors := serviceVisaFixture()

	const width, height = 60, 8
	out := ServiceVisas(width, height, services, 0, visas, actors, nil)

	if w := lipgloss.Width(out); w > width {
		t.Errorf("pane width = %d, want <= %d:\n%s", w, width, ansi.Strip(out))
	}
	if h := lipgloss.Height(out); h > height {
		t.Errorf("pane height = %d, want <= %d:\n%s", h, height, ansi.Strip(out))
	}
}
