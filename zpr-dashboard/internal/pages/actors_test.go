package pages

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// TestActorsPageFitsViewport checks the three-column layout stays inside the
// viewport at a narrow and a wide terminal, and that the narrow rendering still
// shows an unbroken Visas header on Services Offered.
func TestActorsPageFitsViewport(t *testing.T) {
	actors := []dataplane.ActorDescriptor{{CName: "alpha-cn"}}
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ActorCN: "alpha-cn", ZprAddress: "fd5a:5052:90de::30", Endpoints: "TCP/80"},
	}

	for _, width := range []int{100, 160} {
		vp := viewport.New()
		vp.SetWidth(width)
		vp.SetHeight(30)

		out := ActorsPage(vp, actors, 0, nil, nil, nil, nil, nil, nil, services, nil, false)

		if w := lipgloss.Width(out); w > vp.Width() {
			t.Errorf("width %d: rendered %d columns, viewport is %d", width, w, vp.Width())
		}
		if h := lipgloss.Height(out); h > vp.Height() {
			t.Errorf("width %d: rendered %d rows, viewport is %d", width, h, vp.Height())
		}
		if !strings.Contains(out, "Visas") {
			t.Errorf("width %d: expected an unbroken Visas header:\n%s", width, out)
		}
	}
}
