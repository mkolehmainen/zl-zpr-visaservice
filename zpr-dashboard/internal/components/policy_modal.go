package components

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// Not implemented:
//
//	POST /admin/policies/{id}/activate
//
//	Request Parameters:
//	  (none)
//
//	Response:
//	  ListEntry:
//	    id number (the config_id now applied)
//
//	  404 unknown id, 409 already applied
func PolicyRollbackModal(width, height int, policy dataplane.PolicyBundle, applied *dataplane.PolicyBundle) string {
	dim := styles.SubtitleStyle
	value := lipgloss.NewStyle().Foreground(styles.ColorFg)

	field := func(label, val string) string {
		return dim.Render(fmt.Sprintf("  %-10s", label)) + val
	}

	from := "—"
	if applied != nil {
		from = fmt.Sprintf("config %d", applied.ConfigID)
	}

	confirm := lipgloss.NewStyle().
		Background(styles.ColorGreen).
		Foreground(styles.ColorBg).
		Bold(true).
		Padding(0, 2).
		Render("✓  Confirm")

	cancel := lipgloss.NewStyle().
		Background(styles.ColorBorder).
		Foreground(styles.ColorFg).
		Padding(0, 2).
		Render("✕  Cancel")

	content := strings.Join([]string{
		lipgloss.NewStyle().Foreground(styles.ColorYellow).Bold(true).Render("  ⚠  Roll Back Policy Version"),
		dim.Render("     Revert to a previously installed bundle"),
		dim.Render(strings.Repeat("─", 54)),
		field("Policy", value.Render(fmt.Sprintf("config %d", policy.ConfigID))),
		field("From", lipgloss.NewStyle().Foreground(styles.ColorBlue).Bold(true).Render(from)),
		field("To", lipgloss.NewStyle().Foreground(styles.ColorGreen).Bold(true).
			Render(fmt.Sprintf("config %d · %s", policy.ConfigID, orDash(policy.Version)))),
		"",
		dim.Render("  The admin API has no rollback endpoint, so this"),
		dim.Render("  dialog confirms nothing" + placeholderMark),
		"",
		"  " + confirm + "      " + cancel,
		"  " + dim.Render("   y / enter") + "              " + dim.Render("   n / esc"),
	}, "\n")

	box := lipgloss.NewStyle().
		Width(56).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorYellow).
		Padding(1, 0).
		Render(content)

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
