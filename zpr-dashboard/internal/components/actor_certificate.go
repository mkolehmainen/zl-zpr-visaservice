package components

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// No API endpoint exposed for this type of histortical data yet
func ActorIdentity(width, height int, actors []dataplane.ActorDescriptor, selectedIndex int, fetchErr error) string {
	content := styles.TitleStyle.Render("Identity") + "\n\n"

	if fetchErr != nil && len(actors) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	if selectedIndex < 0 || selectedIndex >= len(actors) {
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render("Collecting data...")

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	actor := actors[selectedIndex]

	ident := actor.Ident
	if ident == "" {
		ident = "not tracked yet"
	}

	content += fmt.Sprintf("%s %s\n", label("Identity"), ident)
	content += fmt.Sprintf("%s %s", label("Common Name"), actor.CName)

	if fetchErr != nil {
		content += "\n\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
