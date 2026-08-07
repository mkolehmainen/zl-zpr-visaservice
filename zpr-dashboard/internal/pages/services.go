package pages

import (
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func ServicesPage(
	vp viewport.Model,
	services []dataplane.ServiceDescriptor,
	selectedIndex int,
	fetchErr error,
	actors []dataplane.ActorDescriptor,
	actorsFetchErr error,
	visas []dataplane.VisaDescriptor,
	visasFetchErr error,
	showStatic bool,
) string {
	colWidth := vp.Width() / 3
	listWidth := vp.Width() - 2*colWidth
	rows := 3
	if !showStatic {
		rows = 2
	}
	rowHeight := vp.Height() / rows
	lastHeight := vp.Height() - (rows-1)*rowHeight

	list := components.ServiceList(listWidth, vp.Height(), services, selectedIndex, fetchErr)

	grid := []string{
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.ServiceDetails(colWidth, rowHeight, services, selectedIndex, fetchErr),
			components.ServiceCertificate(colWidth, rowHeight, services, selectedIndex, actors, actorsFetchErr),
		),
	}

	visasHeight := rowHeight
	if !showStatic {
		visasHeight = lastHeight
	}

	grid = append(grid, lipgloss.JoinHorizontal(
		lipgloss.Left,
		components.ServiceVisas(colWidth, visasHeight, services, selectedIndex, visas, actors, visasFetchErr),
		components.ServiceEndpoints(colWidth, visasHeight, services, selectedIndex, fetchErr),
	))

	if showStatic {
		grid = append(grid, lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.ServiceAlerts(colWidth, lastHeight),
			components.ServiceErrorRate(colWidth, lastHeight),
		))
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, list, lipgloss.JoinVertical(lipgloss.Top, grid...))
}
