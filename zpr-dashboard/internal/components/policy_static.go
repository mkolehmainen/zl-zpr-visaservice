package components

import (
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/styles"
)

var policyVersions = []struct {
	version string
	date    string
	notes   string
	active  bool
}{
	{"v3", "2026-07-21", "tightened egress rules", true},
	{"v2", "2026-06-02", "added mesh-control bindings", false},
	{"v1", "2026-03-01", "initial import", false},
}

// Not implemented:
//
//	GET /admin/policies/{id}/versions
//
//	Request Parameters:
//	  (none)
//
//	Response:
//	  PolicyVersion[]:
//	    version string
//	    applied_at number|null
//	    compiler string
//	    size number
//	    active boolean
//	    notes string
func PolicyVersionHistory(width, height int) string {
	const title, subtitle = "Version History", "Static sample data"

	tableWidth := width - 5
	versionSize := int(float32(tableWidth) * 0.15)
	dateSize := int(float32(tableWidth) * 0.28)
	notesSize := int(float32(tableWidth) * 0.57)

	t := panelTable(tableWidth,
		[]string{"Ver", "Date", "Notes"},
		[]int{versionSize, dateSize, notesSize},
	)

	for _, version := range policyVersions {
		marker := styles.ValueStyle.Foreground(styles.ColorDimmed).Render("○ ")
		if version.active {
			marker = lipgloss.NewStyle().Foreground(styles.ColorGreen).Render("● ")
		}

		t.Row(
			marker+ansi.Truncate(version.version, versionSize-2, "..."),
			ansi.Truncate(version.date, dateSize, "..."),
			ansi.Truncate(version.notes, notesSize, "..."),
		)
	}

	return placeholderPanel(width, height, title, subtitle, t.Render())
}
