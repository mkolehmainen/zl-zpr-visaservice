package components

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func ActorList(
	width, height int,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	showActions bool,
	fetchErr error,
) string {
	valid, expired := actorCounts(actors)

	content := styles.TitleStyle.Render("Actor List") + "\n"
	content += styles.SubtitleStyle.Render(fmt.Sprintf("%d %s · %d valid · %d expired", len(actors), plural(len(actors), "actor"), valid, expired))

	budget := height - panelChrome
	size := width - 4

	if fetchErr != nil && len(actors) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelError(fetchErr), budget, panelBodyWidth(width)))
	}

	if len(actors) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelNote("No actors connected"), budget, panelBodyWidth(width)))
	}

	headers := []string{"Actor", "Dock"}
	shares := []float32{0.5, 0.5}

	showActions = showActions && int(float32(size)*0.25) >= lipgloss.Width(revokeLabel)
	if showActions {
		headers = append(headers, "Actions")
		shares = []float32{0.375, 0.375, 0.25}
	}

	widths := make([]int, len(shares))
	for i, share := range shares {
		widths[i] = int(float32(size) * share)
	}

	t := table.New().
		Width(size).
		Border(lipgloss.HiddenBorder()).
		Headers(headers...).
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

			if col < len(widths) {
				return s.Width(widths[col]).MaxWidth(widths[col])
			}

			return s
		})

	extra := 0
	if fetchErr != nil {
		extra = 1
	}

	fits, hidden := tableRowsThatFit(len(actors), budget, extra)

	for i, a := range actors[:fits] {
		cells := []string{
			ansi.Truncate(a.CName, widths[0], "..."),
			ansi.Truncate(orDash(actorDock(actors, a)), widths[1], "..."),
		}

		if showActions {
			cells = append(cells, revokeButton(i == selectedIndex))
		}

		t.Row(cells...)
	}

	body := "\n" + t.Render()

	if hidden > 0 {
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("+%d more", hidden))
	}

	if fetchErr != nil {
		body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(body, budget, panelBodyWidth(width)))
}

const revokeLabel = "[ Revoke ]"

func revokeButton(selected bool) string {
	if selected {
		return lipgloss.NewStyle().Foreground(styles.ColorRed).Bold(true).Render(revokeLabel)
	}

	return styles.SubtitleStyle.Render(revokeLabel)
}
