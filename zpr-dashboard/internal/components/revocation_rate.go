package components

import (
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func RevocationRateChart(width, height int, revokedHistory []int, fetchErr error) string {
	content := styles.TitleStyle.Render("Revocation Rate") + "\n"
	content += styles.SubtitleStyle.Render("Table size per refresh") + "\n"

	if fetchErr != nil && len(revokedHistory) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	chartHeight := height + 1
	if len(revokedHistory) < 2 || width-9 < 10 || chartHeight-7 < 2 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + panelNote("No samples collected yet"))
	}

	content += charts.DotChart(width, chartHeight, styles.ColorRed, revokedHistory)

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
