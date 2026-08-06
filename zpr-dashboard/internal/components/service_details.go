package components

import (
	"fmt"
	"strings"

	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func ServiceDetails(width, height int, services []dataplane.ServiceDescriptor, selectedIndex int, fetchErr error) string {
	const title, subtitle = "Service Details", "Registration record"

	if fetchErr != nil && len(services) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(services) {
		return detailPanel(width, height, title, subtitle, panelNote("Select a service"))
	}

	svc := services[selectedIndex]

	body := "\n"
	body += fmt.Sprintf("%s %s\n", label("Name"), svc.ServiceName)
	body += fmt.Sprintf("%s %s\n", label("Actor"), svc.ActorCN)
	body += fmt.Sprintf("%s %s\n", label("Address"), orDash(svc.ZprAddress))
	body += fmt.Sprintf("%s %s\n", label("Dock"), orDash(svc.DockZprAddress))
	body += fmt.Sprintf("%s %s\n", label("Kind"), orDash(svc.KindName()))
	body += fmt.Sprintf("%s %s", label("Endpoints"), serviceEndpointList(svc))

	return detailPanel(width, height, title, subtitle, body)
}

func serviceEndpointList(svc dataplane.ServiceDescriptor) string {
	endpoints := svc.ServiceEndpoints()
	if len(endpoints) == 0 {
		return "—"
	}

	rendered := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Port == "" {
			rendered = append(rendered, endpoint.Proto)
			continue
		}

		rendered = append(rendered, endpoint.Proto+"/"+endpoint.Port)
	}

	return strings.Join(rendered, ", ")
}
