package components

import (
	"image/color"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func VisaBarChart(width, height int, activeHistory []int, fetchErr error) string {
	title := lipgloss.NewStyle().Foreground(styles.ColorCyan).Bold(true).Render("Visa Activity")
	legend := lipgloss.NewStyle().Foreground(styles.ColorBlue).Render("█") + " " +
		styles.ValueStyle.Foreground(styles.ColorDimmed).Render("Active")

	content := title + "  " + legend + "\n"
	content += styles.Separator(width-4) + "\n"

	switch {
	case fetchErr != nil && len(activeHistory) == 0:
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())
	case len(activeHistory) == 0:
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render("Collecting data...")
	default:
		data := make([][]int, len(activeHistory))
		for i, v := range activeHistory {
			data[i] = []int{v}
		}
		content += charts.BarChart(width, height, data, []color.Color{styles.ColorBlue}, []string{"Active"})
		if fetchErr != nil {
			content += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
		}
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
