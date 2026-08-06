package components

import (
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// Not implemented:
//
//	GET /admin/stats/history
//
//	Request Parameters:
//	  counter string (a name from GET /admin/stats)
//	  window number (optional, seconds)
//	  buckets number (optional)
//
//	Response:
//	  StatHistory:
//	    counter string
//	    bucket_seconds number
//	    samples number[] (per-bucket deltas, oldest first)
func ThroughputChartPanel(width, height int) string {
	content :=
		placeholderTitle("Network Throughout") + "  " +
			lipgloss.NewStyle().Foreground(styles.ColorBlue).Render("━") + " " +
			lipgloss.NewStyle().Foreground(styles.ColorDimmed).Render("Throughput/minute") + "\n"

	content += styles.Separator(width - 4)

	if width-9 < 10 || height-7 < 2 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + panelNote("Panel too small for the chart"))
	}

	content += "\n" + charts.DotChart(width, height, styles.ColorBlue, []int{15, 15, 4, 8, 10, 12, 15, 12, 15, 9, 9, 3}[:])

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
