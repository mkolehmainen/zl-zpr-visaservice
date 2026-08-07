package components

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

func ServiceCertificate(
	width, height int,
	services []dataplane.ServiceDescriptor,
	selectedIndex int,
	actors []dataplane.ActorDescriptor,
	fetchErr error,
) string {
	const title, subtitle = "Certificate", "Authorization of the owning actor"

	if fetchErr != nil && len(services) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(services) {
		return detailPanel(width, height, title, subtitle, panelNote("Select a service"))
	}

	svc := services[selectedIndex]

	owner, ok := actorByCN(actors, svc.ActorCN)
	if !ok {
		return detailPanel(width, height, title, subtitle, panelNote("Owning actor not connected"))
	}

	if owner.AuthExp == nil {
		return detailPanel(width, height, title, subtitle, panelNote("No expiry tracked for this actor"))
	}

	now := time.Now()
	days := int(time.Unix(*owner.AuthExp, 0).Sub(now).Hours() / 24)

	stateColor, icon, status := certState(days)

	body := "\n"
	body += styles.ValueStyle.Foreground(styles.ColorDimmed).Render("Expires  ") +
		lipgloss.NewStyle().Foreground(styles.ColorFg).Render(timefmt.Expiry(*owner.AuthExp)) + "\n\n"
	body += certBar(width-6, days, formatCertRemaining(*owner.AuthExp, now, days), stateColor) + "\n"
	body += lipgloss.NewStyle().Foreground(stateColor).Bold(true).Render(icon + " " + status)

	return detailPanel(width, height, title, subtitle, body)
}

func certState(days int) (color.Color, string, string) {
	switch {
	case days > 90:
		return styles.ColorGreen, "✓", "Valid"
	case days > 30:
		return styles.ColorYellow, "!", "Expiring Soon"
	case days > 0:
		return styles.ColorOrange, "!", "Expiring"
	default:
		return styles.ColorRed, "✗", "Expired"
	}
}

// formatCertRemaining labels the bar with the time left on the certificate,
// using the same rounded-year rule as the Expires row once it is far out.
func formatCertRemaining(expiresAt int64, now time.Time, days int) string {
	if years, ok := timefmt.FarFuture(expiresAt, now); ok {
		return years
	}

	return fmt.Sprintf("%4d days", days)
}

func certBar(width, days int, remaining string, barColor color.Color) string {
	barWidth := width - len(remaining) - 1
	if barWidth < 6 {
		barWidth = 6
	}

	filled := max(0, min(days*barWidth/365, barWidth))

	bar := lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("█", filled)) +
		styles.ValueStyle.Foreground(styles.ColorDimmed).Render(strings.Repeat("░", barWidth-filled))

	return bar + styles.ValueStyle.Foreground(styles.ColorDimmed).Render(" "+remaining)
}

func actorByCN(actors []dataplane.ActorDescriptor, cn string) (dataplane.ActorDescriptor, bool) {
	for _, actor := range actors {
		if actor.CName == cn {
			return actor, true
		}
	}

	return dataplane.ActorDescriptor{}, false
}
