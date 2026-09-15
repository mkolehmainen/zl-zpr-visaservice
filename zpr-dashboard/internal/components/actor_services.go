package components

import (
	"strconv"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func ActorServicesOffered(
	width, height int,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	services []dataplane.ServiceDescriptor,
	activeVisas []dataplane.VisaDescriptor,
	servicesFetchErr error,
	activeVisasFetchErr error,
) string {
	const title, subtitle = "Services Offered", "Registered to this actor"

	if servicesFetchErr != nil && len(services) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(servicesFetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(actors) {
		return detailPanel(width, height, title, subtitle, panelNote("Select an actor"))
	}

	actor := actors[selectedIndex]

	// FetchServices sorts by ServiceName, so the filtered copy stays sorted.
	// The join keys on the ZPR address: a CN may be absent, and matching on it
	// would hand every CN-less actor every CN-less registration.
	var offered []dataplane.ServiceDescriptor
	for _, svc := range services {
		if svc.ZprAddress != "" && svc.ZprAddress == actor.ZprAddress {
			offered = append(offered, svc)
		}
	}

	if len(offered) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No services registered to this actor"))
	}

	tableWidth := width - 5
	visaSize := 6
	textWidth := tableWidth - visaSize
	nameSize := int(float32(textWidth) * 0.53)
	endpointSize := textWidth - nameSize

	t := panelTable(tableWidth,
		[]string{"Service", "Endpoints", "Visas"},
		[]int{nameSize, endpointSize, visaSize},
	)

	for _, svc := range offered {
		// A failed visa refresh must not read as a current count of zero.
		count := "ERR"
		if activeVisasFetchErr == nil {
			count = strconv.Itoa(len(visasForService(activeVisas, svc)))
		}

		t.Row(
			ansi.Truncate(svc.ServiceName, nameSize, "..."),
			ansi.Truncate(orDash(svc.Endpoints), endpointSize, "..."),
			ansi.Truncate(count, visaSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}

	return value
}
