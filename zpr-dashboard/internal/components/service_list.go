package components

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func ServiceList(width, height int, services []dataplane.ServiceDescriptor, selectedIndex int, fetchErr error) string {
	content := styles.TitleStyle.Render("Service List") + "\n"
	actors := distinctActors(services)
	content += styles.SubtitleStyle.Render(fmt.Sprintf("%d %s · %d %s", len(services), plural(len(services), "service"), actors, plural(actors, "actor"))) + "\n\n"

	if fetchErr != nil && len(services) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	size := width - 4
	nameSize := int(float32(size) * 0.6)
	actorSize := int(float32(size) * 0.4)

	t := table.New().
		Width(size).
		Border(lipgloss.HiddenBorder()).
		Headers("Service", "Actor").
		BorderHeader(false).
		BorderTop(false).
		BorderBottom(false).
		BorderLeft(false).
		BorderColumn(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			s := lipgloss.NewStyle()

			if row == table.HeaderRow {
				s = s.
					Foreground(styles.ColorBlue).
					Bold(true).
					Border(lipgloss.RoundedBorder(), false, false, true, false).
					BorderForeground(styles.ColorDimmed)
			} else {
				s = s.Foreground(styles.ColorFg)
			}

			if row == selectedIndex && selectedIndex > -1 {
				s = s.Background(styles.ColorTableSelBg)
			}

			switch col {
			case 0:
				return s.Width(nameSize).MaxWidth(nameSize)
			case 1:
				return s.Width(actorSize).MaxWidth(actorSize)
			default:
				return s
			}
		})

	for _, svc := range services {
		t.Row(
			ansi.Truncate(svc.ServiceName, nameSize, "..."),
			ansi.Truncate(svc.ActorCN, actorSize, "..."),
		)
	}

	content += t.Render()
	if len(services) == 0 {
		content += panelNote("No services registered")
	}

	if fetchErr != nil {
		content += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}

func distinctActors(services []dataplane.ServiceDescriptor) int {
	seen := make(map[string]struct{}, len(services))
	for _, svc := range services {
		seen[svc.ActorCN] = struct{}{}
	}

	return len(seen)
}
