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
	{NodeA: "fd5a:5052:90de::1", NodeB: "fd5a:5052:90de::2", CType: "DOWN", Substrate: "129.22.31.2:5000"},
	{NodeA: "fd5a:5052:90de::1", NodeB: "fd5a:5052:90de::9", CType: "UP", Substrate: "10.8.22.1:5000"},
	{NodeA: "fd5a:5052:90de::8", NodeB: "fd5a:5052:90de::9", CType: "INVALID"},
}

// renderTopology renders the pane roomy enough that nothing is clipped.
func renderTopology(t *testing.T, network []dataplane.NodeConnection, fetchErr error) string {
	t.Helper()
	return NetworkTopology(160, 30, network, testActors, true, 0, fetchErr)
}

// TestTopologyShowsCNUnderKnownAddress checks a matching actor's CN appears
// beneath its address and unknown endpoints stay one line.
func TestTopologyShowsCNUnderKnownAddress(t *testing.T) {
	out := renderTopology(t, testNetwork, nil)

	for _, cn := range []string{"node-nyc", "node-lon"} {
		if !strings.Contains(out, cn) {
			t.Errorf("expected CN %q in output", cn)
		}
	}

	cell := topologyNodeCell("fd5a:5052:90de::9", testActors, 30)
	if strings.Contains(cell, "\n") {
		t.Errorf("unknown endpoint should render one line, got %q", cell)
	}
}

// TestTopologyEmptySubstrateIsDash checks an INVALID link's blank substrate
// degrades to a dash rather than an empty cell.
func TestTopologyEmptySubstrateIsDash(t *testing.T) {
	out := renderTopology(t, testNetwork[2:], nil)
	if !strings.Contains(out, "—") {
		t.Error("expected a dash for the missing substrate")
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
