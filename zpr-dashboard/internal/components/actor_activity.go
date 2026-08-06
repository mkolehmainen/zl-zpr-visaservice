package components

import (
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// Not implemented:
//
//	GET /admin/actors/{cn}/visas/history
//
//	Request Parameters:
//	  window number (optional, seconds)
//	  buckets number (optional)
//
//	Response:
//	  VisaCountHistory:
//	    bucket_seconds number
//	    samples number[] (visas held per bucket, oldest first)
func ActorActivityChart(width, height int, visaCountHistory []int, fetchErr error) string {
	content := styles.TitleStyle.Render("Visa Activities") + "\n"

	if fetchErr != nil && len(visaCountHistory) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	chartHeight := height + 2

	if len(visaCountHistory) < 2 || width-9 < 10 || chartHeight-7 < 2 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + panelNote("No activity recorded yet"))
	}

	content += charts.DotChart(width, chartHeight, styles.ColorCyan, visaCountHistory)

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
