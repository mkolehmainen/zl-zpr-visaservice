package components

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func PolicyActiveVersion(
	width, height int,
	policies []dataplane.PolicyBundle,
	selectedIndex int,
	applied *dataplane.PolicyBundle,
	fetchErr error,
) string {
	const title, subtitle = "Active Version", "Bundle currently selected"

	if fetchErr != nil && len(policies) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(policies) {
		return detailPanel(width, height, title, subtitle, panelNote("Select a policy"))
	}

	policy := policies[selectedIndex]

	state := styles.ValueStyle.Foreground(styles.ColorDimmed).Render("installed, not applied")
	if isApplied(policy, applied) {
		state = lipgloss.NewStyle().Foreground(styles.ColorGreen).Bold(true).Render("● applied by the visa service")
	}

	body := "\n"
	body += fmt.Sprintf("%s %d\n", label("Config ID"), policy.ConfigID)
	body += fmt.Sprintf("%s %s\n", label("Version"), orDash(policy.Version))
	body += fmt.Sprintf("%s %s\n", label("Format"), orDash(policy.Format))
	body += fmt.Sprintf("%s %s\n", label("Bundle"), formatBytes(policy.Size()))
	body += state

	return detailPanel(width, height, title, subtitle, body)
}
