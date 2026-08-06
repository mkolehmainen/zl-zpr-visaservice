package components

import (
	"strconv"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func ActorVisas(width, height int, visas []dataplane.VisaDescriptor, fetchErr error) string {
	content := styles.TitleStyle.Render("Assigned Visas") + "\n"
	content += styles.SubtitleStyle.Render("Visas granted to this actor") + "\n"

	tableSize := width - 5

	idSize := int(float32(tableSize) * 0.14)
	destinationSize := int(float32(tableSize) * 0.38)
	protoSize := int(float32(tableSize) * 0.16)
	expireSize := int(float32(tableSize) * 0.32)

	if fetchErr != nil && len(visas) == 0 {
		content += lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa admin service") + "\n"
		content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())

		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	// A note, not a row: the ID column is too narrow to hold a sentence
	if len(visas) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + panelNote("No visas assigned to this actor"))
	}

	t := table.New().
		Width(tableSize).
		Border(lipgloss.HiddenBorder()).
		Headers("ID", "Destination", "Proto", "Expires").
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
				return s.Width(idSize).MaxWidth(idSize)
			case 1:
				return s.Width(destinationSize).MaxWidth(destinationSize)
			case 2:
				return s.Width(protoSize).MaxWidth(protoSize)
			case 3:
				return s.Width(expireSize).MaxWidth(expireSize)
			default:
				return s
			}
		})

	for _, v := range visas {
		expires := visaExpiry(v).Format("01-02 15:04")

		t.Row(
			ansi.Truncate(strconv.FormatInt(v.ID, 10), idSize, "..."),
			ansi.Truncate(orDash(v.Dest()), destinationSize, "..."),
			ansi.Truncate(v.Proto, protoSize, "..."),
			ansi.Truncate(expires, expireSize, "..."),
		)
	}

	content += t.Render()
	if fetchErr != nil {
		content += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
