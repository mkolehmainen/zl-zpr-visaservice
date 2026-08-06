package components

import (
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func VisaDenialRateChart(width, height int, revokedHistory []int, fetchErr error) string {
	content :=
		styles.TitleStyle.Render("Visa Revocations") + "  " +
			lipgloss.NewStyle().Foreground(styles.ColorRed).Render("━") + " " +
			lipgloss.NewStyle().Foreground(styles.ColorDimmed).Render("Revoked (live)") + "\n"

	content += styles.Separator(width - 4)

	switch {
	case fetchErr != nil && len(revokedHistory) == 0:
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

	case len(revokedHistory) < 2:
		content += panelNote("No samples collected yet")

	case width-9 < 10 || height-7 < 2:
		content += panelNote("Panel too small for the chart")

	default:
		content += "\n" + charts.DotChart(width, height, styles.ColorRed, revokedHistory)
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
