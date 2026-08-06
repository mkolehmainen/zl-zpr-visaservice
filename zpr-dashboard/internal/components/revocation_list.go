package components

import (
	"fmt"
	"strconv"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func RevocationList(width, height int, revocations []dataplane.AuthRevokeDescriptor, actors []dataplane.ActorDescriptor, fetchErr error) string {
	content := styles.TitleStyle.Render("Revocation Feed") + "\n"
	content += styles.SubtitleStyle.Render(fmt.Sprintf("%d %s in the revocation table", len(revocations), plural(len(revocations), "entry"))) + "\n\n"

	if fetchErr != nil && len(revocations) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	size := width - 5

	idSize := int(float32(size) * 0.15)
	typeSize := int(float32(size) * 0.2)
	cnSize := int(float32(size) * 0.4)
	actorSize := int(float32(size) * 0.25)

	columnWidth := func(col int) int {
		switch col {
		case 0:
			return idSize
		case 1:
			return typeSize
		case 2:
			return cnSize
		default:
			return actorSize
		}
	}

	t := table.New().
		Width(size).
		Border(lipgloss.HiddenBorder()).
		Headers("Rev ID", "Type", "CN", "Actor").
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

				if col == 3 && row < len(revocations) {
					if _, connected := actorByCN(actors, revocations[row].CN); connected {
						s = s.Foreground(styles.ColorYellow)
					} else {
						s = s.Foreground(styles.ColorDimmed)
					}
				}
			}

			return s.Width(columnWidth(col)).MaxWidth(columnWidth(col))
		})

	for _, revocation := range revocations {
		t.Row(
			ansi.Truncate(strconv.Itoa(revocation.ID), idSize, "..."),
			ansi.Truncate(orDash(revocation.Type), typeSize, "..."),
			ansi.Truncate(orDash(revocation.CN), cnSize, "..."),
			ansi.Truncate(revocationActor(revocation, actors), actorSize, "..."),
		)
	}

	content += t.Render()
	if len(revocations) == 0 {
		content += panelNote("No revocations recorded")
	}

	if fetchErr != nil {
		content += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}

func revocationActor(revocation dataplane.AuthRevokeDescriptor, actors []dataplane.ActorDescriptor) string {
	if _, ok := actorByCN(actors, revocation.CN); ok {
		return "still connected"
	}

	return "not connected"
}
