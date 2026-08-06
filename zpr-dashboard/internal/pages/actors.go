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

	// Everything on the right is scoped to the actor selected on the left.
	details := lipgloss.JoinVertical(
		lipgloss.Top,
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.ActorDetails(colWidth, rowHeight, actors, selectedIndex, fetchErr),
			components.ActorIdentity(colWidth, rowHeight, actors, selectedIndex, fetchErr),
		),
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.ActorVisas(colWidth, chartHeight, visas, visasFetchErr),
			components.ActorActivityChart(colWidth, chartHeight, visaCountHistory, visasFetchErr),
		),
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.ActorServicesOffered(colWidth, rowHeight, actors, selectedIndex, services, servicesFetchErr),
			components.ActorServicesUsed(colWidth, rowHeight, visas, services, servicesFetchErr),
		),
	)

	return lipgloss.JoinHorizontal(lipgloss.Left, roster, details)
}
