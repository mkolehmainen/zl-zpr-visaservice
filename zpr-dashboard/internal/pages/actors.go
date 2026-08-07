package pages

import (
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func ActorsPage(
	vp viewport.Model,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	fetchErr error,
	visas []dataplane.VisaDescriptor,
	visasFetchErr error,
	activeVisas []dataplane.VisaDescriptor,
	activeVisasFetchErr error,
	visaCountHistory []int,
	services []dataplane.ServiceDescriptor,
	servicesFetchErr error,
	showStatic bool,
) string {
	colWidth := vp.Width() / 3
	rosterWidth := vp.Width() - 2*colWidth

	rowHeight := vp.Height() / 3
	chartHeight := vp.Height() - 2*rowHeight

	roster := components.ActorList(rosterWidth, vp.Height(), actors, selectedIndex, showStatic, fetchErr)

	// Everything on the right is scoped to the actor selected on the left. The
	// grid is not rectangular, so it is assembled column by column.
	detail := lipgloss.JoinVertical(
		lipgloss.Top,
		components.ActorDetails(colWidth, 2*rowHeight, actors, selectedIndex, fetchErr),
		components.ActorVisas(colWidth, chartHeight, visas, actors, visasFetchErr),
	)

	context := lipgloss.JoinVertical(
		lipgloss.Top,
		components.ActorIdentity(colWidth, rowHeight, actors, selectedIndex, fetchErr),
		components.ActorActivityChart(colWidth, chartHeight, visaCountHistory, visasFetchErr),
		components.ActorServicesOffered(colWidth, rowHeight, actors, selectedIndex, services, activeVisas, servicesFetchErr, activeVisasFetchErr),
	)

	return lipgloss.JoinHorizontal(lipgloss.Left, roster, detail, context)
}
