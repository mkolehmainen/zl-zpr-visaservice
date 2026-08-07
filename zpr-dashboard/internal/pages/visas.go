package pages

import (
	"fmt"

	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

const visaDetailHeight = 12
const visaTableMinHeight = 11

type VisaCounts struct {
	Active    int
	Requested int
	Approved  int
	Denied    int
}

func VisaTab(
	vp viewport.Model,
	view components.VisaView,
	counts VisaCounts,
	activeHistory []int,
	revokedHistory []int,
	visas []dataplane.VisaDescriptor,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	fetchErr error,
	showStatic bool,
) string {
	// The rounding leftover goes to the last box, so the row spans the page.
	boxWidth := vp.Width() / 4
	summary := lipgloss.JoinHorizontal(
		lipgloss.Left,
		components.DataContainerWidth(boxWidth, "Total Active Visas", visaTrend(activeHistory), fmt.Sprintf("%d", counts.Active), "#7aa2f7"),
		components.DataContainerWidth(boxWidth, "Visas Requested", "Since service start", fmt.Sprintf("%d", counts.Requested), "#e0af68"),
		components.DataContainerWidth(boxWidth, "Visas Approved", "Since service start", fmt.Sprintf("%d", counts.Approved), "#9ece6a"),
		components.DataContainerWidth(vp.Width()-3*boxWidth, "Visas Denied", "Since service start", fmt.Sprintf("%d", counts.Denied), "#f7768e"),
	)

	rest := vp.Height() - summaryHeight

	rows := visaDetailRows(rest, view, showStatic)
	panel := components.VisaPanel(vp.Width(), rest-rows*visaDetailHeight, view, visas, actors, selectedIndex, fetchErr)

	parts := []string{summary, panel}

	colWidth := vp.Width() / 2
	restWidth := vp.Width() - colWidth
	selected := components.SelectedVisa(visas, selectedIndex)

	if rows > 0 {
		parts = append(parts, visaDetailRow(view, colWidth, restWidth, selected, actors, activeHistory, revokedHistory, fetchErr))
	}

	if rows > 1 {
		parts = append(parts, lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.VisaUsage(colWidth, visaDetailHeight, selected),
			components.VisaActivities(restWidth, visaDetailHeight, selected),
		))
	}

	return lipgloss.JoinVertical(lipgloss.Top, parts...)
}

func visaDetailRows(rest int, view components.VisaView, showStatic bool) int {
	if rest < visaTableMinHeight+visaDetailHeight {
		return 0
	}

	if view != components.VisaViewActive || !showStatic {
		return 1
	}

	if rest < visaTableMinHeight+2*visaDetailHeight {
		return 1
	}

	return 2
}

func visaDetailRow(
	view components.VisaView,
	colWidth, restWidth int,
	selected *dataplane.VisaDescriptor,
	actors []dataplane.ActorDescriptor,
	activeHistory, revokedHistory []int,
	fetchErr error,
) string {
	if view != components.VisaViewActive {
		return lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.VisaBarChart(colWidth, visaDetailHeight, activeHistory, fetchErr),
			components.VisaDenialRateChart(restWidth, visaDetailHeight, revokedHistory, fetchErr),
		)
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		components.VisaAuthScope(colWidth, visaDetailHeight, selected, actors),
		components.VisaAuthorizedBy(restWidth, visaDetailHeight, selected, actors),
	)
}

func visaTrend(activeHistory []int) string {
	if len(activeHistory) < 2 {
		return "Collecting"
	}

	first := activeHistory[0]
	last := activeHistory[len(activeHistory)-1]

	switch {
	case last > first:
		return "Rising"
	case last < first:
		return "Falling"
	default:
		return "Stable"
	}
}
