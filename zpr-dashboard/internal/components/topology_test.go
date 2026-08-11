package components

import (
	"errors"
	"image/color"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

var testActors = []dataplane.ActorDescriptor{
	{CName: "node-nyc", ZprAddress: "fd5a:5052:90de::1"},
	{CName: "node-lon", ZprAddress: "fd5a:5052:90de::2"},
}

var testNetwork = []dataplane.NodeConnection{
	{NodeA: "fd5a:5052:90de::1", NodeB: "fd5a:5052:90de::2", CType: "DOWN",
		SubstrateA: "129.22.31.2:5000", SubstrateB: "[fd5a:5052:90de::2]:5000"},
	{NodeA: "fd5a:5052:90de::1", NodeB: "fd5a:5052:90de::9", CType: "UP",
		SubstrateA: "129.22.31.2:5000", SubstrateB: "10.8.22.1:5000"},
	{NodeA: "fd5a:5052:90de::8", NodeB: "fd5a:5052:90de::9", CType: "INVALID"},
}

// renderTopology renders the pane roomy enough that nothing is clipped.
func renderTopology(t *testing.T, network []dataplane.NodeConnection, fetchErr error) string {
	t.Helper()
	return NetworkTopology(160, 30, network, testActors, true, 0, fetchErr)
}

// TestTopologyLinkCellsPairEndpoints checks each endpoint of a link gets its own
// line, that endpoint B is marked with the ↳ indent, that both CNs are looked
// up, and that an endpoint no actor claims shows a dash.
func TestTopologyLinkCellsPairEndpoints(t *testing.T) {
	out := renderTopology(t, testNetwork, nil)
	for _, cn := range []string{"node-nyc", "node-lon"} {
		if !strings.Contains(out, cn) {
			t.Errorf("expected CN %q in output", cn)
		}
	}

	// Endpoints ::1 and ::2 are both known actors.
	node, actor, substrate := topologyLinkCells(testNetwork[0], testActors, 22, 13, 27)
	for name, cell := range map[string]string{"node": node, "actor": actor, "substrate": substrate} {
		if lines := strings.Count(cell, "\n") + 1; lines != topologyRowLines {
			t.Errorf("%s cell has %d lines, want %d: %q", name, lines, topologyRowLines, cell)
		}
	}

	nodeLines := strings.Split(node, "\n")
	if strings.Contains(nodeLines[0], "↳") {
		t.Errorf("endpoint A should not carry the peer marker, got %q", nodeLines[0])
	}
	if !strings.Contains(nodeLines[1], "↳") {
		t.Errorf("endpoint B should carry the peer marker, got %q", nodeLines[1])
	}

	if !strings.Contains(actor, "node-nyc") || !strings.Contains(actor, "node-lon") {
		t.Errorf("expected both endpoints' CNs in the actor cell, got %q", actor)
	}

	// ::9 belongs to no actor, so its half of the cell is a dash.
	_, actor, _ = topologyLinkCells(testNetwork[1], testActors, 22, 13, 27)
	if !strings.Contains(strings.Split(actor, "\n")[1], "—") {
		t.Errorf("expected a dash for the unknown endpoint's actor, got %q", actor)
	}
}

// TestTopologyEmptySubstrateIsDash checks an INVALID link, which carries neither
// substrate, degrades to a dash on both of its lines.
func TestTopologyEmptySubstrateIsDash(t *testing.T) {
	out := renderTopology(t, testNetwork[2:], nil)
	if !strings.Contains(out, "—") {
		t.Error("expected a dash for the missing substrate")
	}

	_, _, substrate := topologyLinkCells(testNetwork[2], testActors, 22, 13, 27)
	if got := strings.Count(substrate, "—"); got != 2 {
		t.Errorf("got %d dashes in the substrate cell, want 2: %q", got, substrate)
	}
}

// TestTopologySubstrateFitsBracketedIPv6 checks a bracketed IPv6 substrate
// survives whole at the half-pane width of a 160-column terminal, the narrowest
// real case the Substrate column has to hold.
func TestTopologySubstrateFitsBracketedIPv6(t *testing.T) {
	const substrate = "[fd5a:5052:90de::2]:5000"

	out := NetworkTopology(80, 30, testNetwork, testActors, true, 0, nil)
	if !strings.Contains(out, substrate) {
		t.Errorf("substrate %q was truncated at an 80-column pane:\n%s", substrate, out)
	}
}

// TestLinkStatusColors checks each ctype gets its intended colour and that
// unrecognised values fall back to yellow.
func TestLinkStatusColors(t *testing.T) {
	cases := map[string]color.Color{
		"UP":      styles.ColorGreen,
		"DOWN":    styles.ColorRed,
		"INVALID": styles.ColorYellow,
		"weird":   styles.ColorYellow,
	}

	for ctype, colour := range cases {
		want := lipgloss.NewStyle().Foreground(colour).Render(ctype)
		if got := linkStatus(ctype); got != want {
			t.Errorf("linkStatus(%q) = %q, want %q", ctype, got, want)
		}
	}
}

// TestTopologyStaleWarning checks a failed refresh with rows retained shows the
// warning, and that a failure with no rows shows the error panel instead.
func TestTopologyStaleWarning(t *testing.T) {
	out := renderTopology(t, testNetwork, errors.New("boom"))
	if !strings.Contains(out, "last refresh failed") {
		t.Error("expected stale-data warning when rows are retained")
	}

	out = renderTopology(t, nil, errors.New("boom"))
	if !strings.Contains(out, "could not reach") {
		t.Error("expected the error panel when no rows are available")
	}
}

// TestTopologyEmptyState checks the pane says links, not nodes, when empty.
func TestTopologyEmptyState(t *testing.T) {
	if out := renderTopology(t, nil, nil); !strings.Contains(out, "No links declared") {
		t.Error("expected the empty-links note")
	}
}

// TestTableRowsThatFitHeights covers all-one-line, mixed heights, an exact
// fit, and an overflow that must reserve the "+N more" line.
func TestTableRowsThatFitHeights(t *testing.T) {
	cases := []struct {
		name          string
		heights       []int
		budget, extra int
		shown, hidden int
	}{
		// budget - 3 - extra lines are available for rows.
		{"all fit, one line each", []int{1, 1, 1}, 10, 0, 3, 0},
		{"exact fit", []int{1, 1, 1}, 6, 0, 3, 0},
		{"mixed heights fit", []int{2, 1, 2}, 8, 0, 3, 0},
		{"mixed heights overflow", []int{2, 2, 2}, 8, 0, 2, 1},
		{"overflow reserves the note", []int{1, 1, 1, 1}, 6, 0, 2, 2},
		{"extra line eats a row", []int{1, 1, 1}, 6, 1, 1, 2},
		{"nothing fits", []int{2, 2}, 4, 0, 0, 2},
	}

	for _, c := range cases {
		shown, hidden := tableRowsThatFitHeights(c.heights, c.budget, c.extra)
		if shown != c.shown || hidden != c.hidden {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", c.name, shown, hidden, c.shown, c.hidden)
		}
	}
}
