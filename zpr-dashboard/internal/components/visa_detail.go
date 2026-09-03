package components

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

func visaField(label, value string) string {
	return styles.SubtitleStyle.Render(fmt.Sprintf("%-*s", 14, label)) + value
}

func VisaAuthScope(width, height int, visa *dataplane.VisaDescriptor, actors []dataplane.ActorDescriptor) string {
	if visa == nil {
		return detailPanel(width, height, "Authorization Scope", "What the visa grants",
			panelNote("Select an active visa"))
	}

	value := lipgloss.NewStyle().Foreground(styles.ColorFg)
	remaining := time.Until(visaExpiry(*visa))

	body := "\n" + strings.Join([]string{
		visaField("Destination", value.Render(endpointLabel(visa.Dest(), actors))),
		visaField("Source", value.Render(endpointLabel(visa.Source(), actors))),
		visaField("Port / Proto", value.Render(visaPort(*visa))+
			styles.SubtitleStyle.Render("  /  ")+value.Render(orDash(visa.Proto))),
		visaField("Direction", value.Render(orDash(visa.Direction))),
		"",
		visaField("Issued", styles.SubtitleStyle.Render(timefmt.DateTime(visa.Created))),
		visaField("Expires in", lipgloss.NewStyle().Foreground(remainingColor(remaining)).Bold(true).
			Render(formatRemaining(*visa))),
	}, "\n")

	return detailPanel(width, height, "Authorization Scope", "What the visa grants", body)
}

func VisaAuthorizedBy(width, height int, visa *dataplane.VisaDescriptor, actors []dataplane.ActorDescriptor) string {
	if visa == nil {
		return detailPanel(width, height, "Authorized By", "Why the visa exists",
			panelNote("Select an active visa"))
	}

	value := lipgloss.NewStyle().Foreground(styles.ColorFg)

	rule := ansi.Truncate(orDash(visa.ZPL), max(4, width-6), "...")

	body := "\n" + strings.Join([]string{
		visaField("Policy", value.Render("version "+orDash(visa.PolicyID))),
		visaField("Effect", lipgloss.NewStyle().Foreground(styles.ColorGreen).Bold(true).Render("Allow")),
		visaField("Subject", value.Render(visaSubject(*visa, actors))),
		visaField("Issued by", value.Render(visaIssuer(*visa, actors))),
		visaSignalLine(*visa, width),
		styles.SubtitleStyle.Render("Matched rule"),
		value.Render(rule),
	}, "\n")

	return detailPanel(width, height, "Authorized By", "Why the visa exists", body)
}

// visaIssuer names the authority that authenticated the requesting actor.
// Authorities are per identity namespace (device.zpr.authority /
// user.zpr.authority); when both are present, both are shown.
func visaIssuer(visa dataplane.VisaDescriptor, actors []dataplane.ActorDescriptor) string {
	actor, ok := actorByAddr(actors, visa.RequestingNode)
	if !ok {
		return "—"
	}

	var authorities []string
	for _, key := range []string{"device.zpr.authority", "user.zpr.authority"} {
		authorities = append(authorities, actor.Attr(key)...)
	}

	if len(authorities) == 0 {
		return "—"
	}

	return strings.Join(authorities, ", ")
}

func visaSignalLine(visa dataplane.VisaDescriptor, width int) string {
	var signals []string
	for _, signal := range visa.Signals {
		if signal != "" {
			signals = append(signals, signal)
		}
	}

	if len(signals) == 0 {
		return ""
	}

	return visaField("Signals", lipgloss.NewStyle().Foreground(styles.ColorOrange).
		Render(ansi.Truncate(strings.Join(signals, ", "), max(4, width-14-6), "...")))
}

func remainingColor(remaining time.Duration) color.Color {
	switch {
	case remaining < time.Hour:
		return styles.ColorRed
	case remaining < 6*time.Hour:
		return styles.ColorYellow
	default:
		return styles.ColorGreen
	}
}
