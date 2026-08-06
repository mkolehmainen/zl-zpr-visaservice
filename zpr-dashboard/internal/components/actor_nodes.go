package components

import (
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// ActorNodes shows the selected actor's own node status. The API has no
// endpoint linking an actor to a set of "its" nodes — an actor either is a
// node (Node == true) or isn't, so this shows that single fact rather than
// a fabricated list.
func ActorNodes(vp viewport.Model, actors []dataplane.ActorDescriptor, selectedIndex int, fetchErr error) string {
	content := styles.TitleStyle.Render("Connected Nodes") + "\n\n"

	containerSize := vp.Width() / 3
	boxHeight := vp.Height() / 3
	size := containerSize - 3

	nodeSize := int(float32(size) * 0.4)
	addressSize := int(float32(size) * 0.4)
	statusSize := int(float32(size) * 0.2)

	if fetchErr != nil && len(actors) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(boxHeight).Width(containerSize).Render(content)
	}

	if selectedIndex < 0 || selectedIndex >= len(actors) {
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render("Collecting data...")

		return styles.ContainerStyle.Height(boxHeight).Width(containerSize).Render(content)
	}

	actor := actors[selectedIndex]

	t := table.New().
		Width(size).
		Border(lipgloss.HiddenBorder()).
		Headers("Node", "Address", "Status").
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

			switch col {
			case 0:
				return s.Width(nodeSize).MaxWidth(nodeSize)
			case 1:
				return s.Width(addressSize).MaxWidth(addressSize)
			case 2:
				return s.Width(statusSize).MaxWidth(statusSize)
			default:
				return s
			}
		})

	switch {
	case !actor.Node:
		t.Row("not a node", "", "")
	case actor.NodeDetails == nil:
		t.Row(actor.CName, actor.ZprAddress, "not tracked yet")
	case actor.NodeDetails.InSync:
		t.Row(actor.CName, actor.ZprAddress, "in sync")
	default:
		t.Row(actor.CName, actor.ZprAddress, "out of sync")
	}

	content += lipgloss.NewStyle().PaddingTop(1).Render(t.Render())
	if fetchErr != nil {
		content += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(boxHeight).Width(containerSize).Render(content)
}
