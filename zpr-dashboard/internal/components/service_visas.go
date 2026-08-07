package components

import (
	"strconv"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

// inboundVisas returns the visas granted towards svc, i.e. those whose
// destination is an address the service answers on. Input order is preserved.
func inboundVisas(visas []dataplane.VisaDescriptor, svc dataplane.ServiceDescriptor) []dataplane.VisaDescriptor {
	var inbound []dataplane.VisaDescriptor
	for _, visa := range visas {
		if svc.Hosts(visa.Dest()) {
			inbound = append(inbound, visa)
		}
	}

	return inbound
}

func ServiceVisas(
	width, height int,
	services []dataplane.ServiceDescriptor,
	selectedIndex int,
	visas []dataplane.VisaDescriptor,
	actors []dataplane.ActorDescriptor,
	fetchErr error,
) string {
	const title, subtitle = "Assigned Visas", "Granted towards this service"

	if fetchErr != nil && len(visas) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(services) {
		return detailPanel(width, height, title, subtitle, panelNote("Select a service"))
	}

	svc := services[selectedIndex]

	inbound := inboundVisas(visas, svc)

	if len(inbound) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No visas towards this service"))
	}

	tableWidth := width - 5
	idSize := int(float32(tableWidth) * 0.14)
	sourceSize := int(float32(tableWidth) * 0.38)
	protoSize := int(float32(tableWidth) * 0.16)
	expireSize := int(float32(tableWidth) * 0.32)

	t := panelTable(tableWidth,
		[]string{"ID", "Source", "Proto", "Expires"},
		[]int{idSize, sourceSize, protoSize, expireSize},
	)

	for _, visa := range inbound {
		t.Row(
			ansi.Truncate(strconv.FormatInt(visa.ID, 10), idSize, "..."),
			ansi.Truncate(endpointLabel(visa.Source(), actors), sourceSize, "..."),
			ansi.Truncate(visa.Proto, protoSize, "..."),
			ansi.Truncate(timefmt.Expiry(visa.Expires), expireSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}
