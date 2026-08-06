package components

import (
	"fmt"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/charts"
	"neboagency.com/zpr-dashborad/internal/styles"
)

var serviceAlerts = []struct {
	agoSeconds int
	message    string
	tag        string
	risk       RiskLevel
}{
	{35, "connection timeout from upstream peer", "conn", RiskMedium},
	{330, "certificate expiring soon — renewal required", "cert", RiskHigh},
	{576, "elevated latency detected — p99 > 500 ms", "health", RiskLow},
	{722, "certificate expiring soon — renewal required", "cert", RiskHigh},
	{865, "connection timeout from upstream peer", "conn", RiskMedium},
}

var serviceErrorSamples = []int{4, 6, 3, 7, 5, 9, 6, 4, 8, 12, 9, 14}

// Not implemented:
//
//	GET /admin/services/{name}/alerts
//
//	Request Parameters:
//	  since number (optional, epoch seconds)
//	  limit number (optional)
//
//	Response:
//	  ServiceAlert[]:
//	    at number
//	    message string
//	    tag string
//	    risk low|medium|high
func ServiceAlerts(width, height int) string {
	const title, subtitle = "Service Alerts", "Static sample data"

	budget := height - 4
	if budget < 1 {
		return placeholderPanel(width, height, title, subtitle, panelNote("Panel too small for alerts"))
	}

	shown := serviceAlerts
	if len(shown) > budget {
		shown = shown[:budget]
	}

	var lines []string
	for _, alert := range shown {
		lines = append(lines, alertLine(width-4, alert.agoSeconds, alert.message, alert.tag, alert.risk))
	}

	if hidden := len(serviceAlerts) - len(shown); hidden > 0 {
		lines[len(lines)-1] = styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fmt.Sprintf("+%d more", hidden+1))
	}

	return placeholderPanel(width, height, title, subtitle, lipgloss.JoinVertical(lipgloss.Top, lines...))
}

func alertLine(width, agoSeconds int, message, tag string, risk RiskLevel) string {
	stamp := time.Now().Add(-time.Duration(agoSeconds) * time.Second).Format("15:04:05")
	dim := styles.ValueStyle.Foreground(styles.ColorDimmed)

	body := ansi.Truncate(message, max(4, width-len(stamp)-len(tag)-6), "...")

	return riskColor(risk).Render("●") + " " +
		dim.Render(stamp) + " " +
		lipgloss.NewStyle().Foreground(styles.ColorFg).Render(body) + " " +
		dim.Render("["+tag+"]")
}

// Not implemented:
//
//	GET /admin/services/{name}/errors
//
//	Request Parameters:
//	  window number (optional, seconds)
//	  buckets number (optional)
//
//	Response:
//	  ErrorRate:
//	    bucket_seconds number
//	    samples number[] (refusals per bucket, oldest first)
func ServiceErrorRate(width, height int) string {
	const title = "Error Rate"

	current := serviceErrorSamples[len(serviceErrorSamples)-1]
	subtitle := fmt.Sprintf("%d%% now · static sample data", current)

	chartHeight := height + 1
	if width-9 < 10 || chartHeight-7 < 2 {
		return placeholderPanel(width, height, title, subtitle, panelNote("Panel too small for the chart"))
	}

	return placeholderPanel(width, height, title, subtitle, charts.DotChart(width, chartHeight, styles.ColorRed, serviceErrorSamples))
}
