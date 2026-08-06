package components

import (
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func ServiceEndpoints(width, height int, services []dataplane.ServiceDescriptor, selectedIndex int, fetchErr error) string {
	const title = "Policy Endpoints"

	if fetchErr != nil && len(services) == 0 {
		return detailPanel(width, height, title, "From the running policy", panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(services) {
		return detailPanel(width, height, title, "From the running policy", panelNote("Select a service"))
	}

	svc := services[selectedIndex]
	subtitle := "From the running policy"
	if kind := svc.KindName(); kind != "" {
		subtitle = kind
	}

	endpoints := svc.ServiceEndpoints()
	if len(endpoints) == 0 {
		return detailPanel(width, height, title, subtitle,
			panelNote("The running policy defines no endpoints for this service"))
	}

	tableWidth := width - 5
	protoSize := int(float32(tableWidth) * 0.4)
	portSize := tableWidth - protoSize

	t := panelTable(tableWidth, []string{"Protocol", "Port"}, []int{protoSize, portSize})

	for _, endpoint := range endpoints {
		port := endpoint.Port
		if port == "" {
			port = "any"
		}

		t.Row(
			lipgloss.NewStyle().Foreground(styles.ColorCyan).Render(ansi.Truncate(endpoint.Proto, protoSize, "...")),
			ansi.Truncate(port, portSize, "..."),
		)
	}

	return detailPanel(width, height, title, subtitle, "\n"+t.Render())
}
