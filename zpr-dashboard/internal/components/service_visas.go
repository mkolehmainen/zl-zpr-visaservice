package components

import (
	"strconv"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

// visasForService returns the visas granted for traffic to svc's endpoints,
// forward and reverse. Input order is preserved.
func visasForService(visas []dataplane.VisaDescriptor, svc dataplane.ServiceDescriptor) []dataplane.VisaDescriptor {
	var matched []dataplane.VisaDescriptor
	for _, visa := range visas {
		if svc.Targets(visa) {
			matched = append(matched, visa)
		}
	}

	return matched
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

	matched := visasForService(visas, svc)

	if len(matched) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No visas towards this service"))
	}

	tableWidth := width - 5
	idSize := int(float32(tableWidth) * 0.12)
	peerSize := int(float32(tableWidth) * 0.32)
	dirSize := int(float32(tableWidth) * 0.14)
	protoSize := int(float32(tableWidth) * 0.14)
	expireSize := tableWidth - idSize - peerSize - dirSize - protoSize

	t := panelTable(tableWidth,
		[]string{"ID", "Peer", "Dir", "Proto", "Expires"},
		[]int{idSize, peerSize, dirSize, protoSize, expireSize},
	)

	for _, visa := range matched {
		t.Row(
			ansi.Truncate(strconv.FormatInt(visa.ID, 10), idSize, "..."),
			ansi.Truncate(endpointLabel(visa.Peer(), actors), peerSize, "..."),
			ansi.Truncate(visa.Direction, dirSize, "..."),
			ansi.Truncate(visa.Proto, protoSize, "..."),
			ansi.Truncate(timefmt.Expiry(visa.Expires), expireSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, t.Render())
}
