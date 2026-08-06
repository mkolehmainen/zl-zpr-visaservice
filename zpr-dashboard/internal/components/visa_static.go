package components

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// Invented data: the API knows a visa was issued, not that anything used it
var visaUsageSamples = []int{4, 6, 5, 9, 12, 10, 14, 11, 15, 13, 18, 16, 12, 9, 11, 8}

// Not implemented:
//
//	GET /admin/visas/{id}/usage
//
//	Request Parameters:
//	  (none)
//
//	Response:
//	  VisaUsage:
//	    requests number
//	    active_connections number
//	    bytes number
//	    errors number
//	    last_used number|null
func VisaUsage(width, height int, visa *dataplane.VisaDescriptor) string {
	const title = "Live Usage"

	if visa == nil {
		return placeholderPanel(width, height, title, "Traffic under this visa", panelNote("Select an active visa"))
	}

	value := lipgloss.NewStyle().Foreground(styles.ColorFg)

	requests := 40 + int(visa.ID*37)%1200
	errors := int(visa.ID) % 4

	errStyle := lipgloss.NewStyle().Foreground(styles.ColorGreen)
	if errors > 0 {
		errStyle = lipgloss.NewStyle().Foreground(styles.ColorRed).Bold(true)
	}

	body := "\n" + strings.Join([]string{
		visaField("Requests", value.Render(fmt.Sprintf("%d", requests))),
		visaField("Active", value.Render(fmt.Sprintf("%d now", int(visa.ID)%6))),
		visaField("Transfer", value.Render(formatBytes(requests*(512+int(visa.ID*128)%8192)))),
		visaField("Errors", errStyle.Render(fmt.Sprintf("%d", errors))),
		visaField("Last used", value.Render(fmt.Sprintf("%ds ago", int(visa.ID*13)%300))),
	}, "\n")

	return placeholderPanel(width, height, title, "Traffic under this visa", body)
}

// Not implemented:
//
//	GET /admin/visas/{id}/usage/history
//
//	Request Parameters:
//	  window number (optional, seconds)
//	  buckets number (optional)
//
//	Response:
//	  VisaUsageHistory:
//	    bucket_seconds number
//	    samples number[] (requests per bucket, oldest first)
func VisaActivities(width, height int, visa *dataplane.VisaDescriptor) string {
	const title = "Visa Activities"
	const subtitle = "Requests per interval"

	if visa == nil {
		return placeholderPanel(width, height, title, subtitle, panelNote("Select an active visa"))
	}

	chartHeight := height + 1
	if width-9 < 10 || chartHeight-7 < 2 {
		return placeholderPanel(width, height, title, subtitle, panelNote("Panel too small for the chart"))
	}

	return placeholderPanel(width, height, title, subtitle,
		charts.DotChart(width, chartHeight, styles.ColorCyan, visaUsageSamples))
}
