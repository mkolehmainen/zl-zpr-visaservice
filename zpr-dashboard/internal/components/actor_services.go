package components

import (
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func ActorServicesOffered(
	width, height int,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	services []dataplane.ServiceDescriptor,
	fetchErr error,
) string {
	const title, subtitle = "Services Offered", "Registered to this actor"

	if fetchErr != nil && len(services) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(actors) {
		return detailPanel(width, height, title, subtitle, panelNote("Select an actor"))
	}

	actor := actors[selectedIndex]

	var offered []dataplane.ServiceDescriptor
	for _, svc := range services {
		if svc.ActorCN == actor.CName {
			offered = append(offered, svc)
		}
	}

	if len(offered) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No services registered to this actor"))
	}

	tableWidth := width - 5
	nameSize := int(float32(tableWidth) * 0.45)
	addressSize := int(float32(tableWidth) * 0.3)
	dockSize := int(float32(tableWidth) * 0.25)

	t := panelTable(tableWidth,
		[]string{"Service", "Address", "Dock"},
		[]int{nameSize, addressSize, dockSize},
	)

	for _, svc := range offered {
		t.Row(
			ansi.Truncate(svc.ServiceName, nameSize, "..."),
			ansi.Truncate(svc.ZprAddress, addressSize, "..."),
			ansi.Truncate(orDash(svc.DockZprAddress), dockSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}

func ActorServicesUsed(
	width, height int,
	visas []dataplane.VisaDescriptor,
	services []dataplane.ServiceDescriptor,
	fetchErr error,
) string {
	const title, subtitle = "Services Used", "Reachable through active visas"

	if fetchErr != nil && len(visas) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if len(visas) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No visas assigned to this actor"))
	}

	tableWidth := width - 5
	nameSize := int(float32(tableWidth) * 0.4)
	destSize := int(float32(tableWidth) * 0.4)
	protoSize := int(float32(tableWidth) * 0.2)

	t := panelTable(tableWidth,
		[]string{"Service", "Destination", "Proto"},
		[]int{nameSize, destSize, protoSize},
	)

	for _, visa := range visas {
		t.Row(
			ansi.Truncate(serviceAt(services, visa.Dest()), nameSize, "..."),
			ansi.Truncate(orDash(visa.Dest()), destSize, "..."),
			ansi.Truncate(visa.Proto, protoSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}

func serviceAt(services []dataplane.ServiceDescriptor, addr string) string {
	if addr == "" {
		return "unknown"
	}

	for _, svc := range services {
		if svc.ZprAddress == addr || svc.DockZprAddress == addr {
			return svc.ServiceName
		}
	}

	return "unregistered"
}

func orDash(value string) string {
	if value == "" {
		return "—"
	}

	return value
}
