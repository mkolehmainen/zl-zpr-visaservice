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

func PolicyList(
	width, height int,
	policies []dataplane.PolicyBundle,
	applied *dataplane.PolicyBundle,
	selectedIndex int,
	showActions bool,
	fetchErr error,
) string {
	content := styles.TitleStyle.Render("Policies") + "\n"
	content += styles.SubtitleStyle.Render(fmt.Sprintf("%d installed %s", len(policies), plural(len(policies), "bundle")))

	budget := height - panelChrome

	if fetchErr != nil && len(policies) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelError(fetchErr), budget, panelBodyWidth(width)))
	}

	size := width - 5

	headers := []string{"Config ID", "Version", "Format", "Bundle", "Status"}
	shares := []float32{0.14, 0.18, 0.3, 0.18, 0.2}

	// Without a whole column the button wraps every row
	showActions = showActions && int(float32(size)*0.16) >= lipgloss.Width(rollbackLabel)
	if showActions {
		headers = append(headers, "Actions")
		shares = []float32{0.12, 0.15, 0.25, 0.15, 0.17, 0.16}
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

				if col == 4 && row < len(policies) && isApplied(policies[row], applied) {
					s = s.Foreground(styles.ColorGreen)
				}
			}

			if row == selectedIndex && selectedIndex > -1 {
				s = s.Background(styles.ColorTableSelBg)
			}

			if col < len(widths) {
				return s.Width(widths[col]).MaxWidth(widths[col])
			}

			return s
		})

	if len(policies) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelNote("No policies installed"), budget, panelBodyWidth(width)))
	}

	extra := 0
	if fetchErr != nil {
		extra = 1
	}

	fits, hidden := tableRowsThatFit(len(policies), budget, extra)

	for i, policy := range policies[:fits] {
		cells := []string{
			ansi.Truncate(strconv.Itoa(policy.ConfigID), widths[0], "..."),
			ansi.Truncate(orDash(policy.Version), widths[1], "..."),
			ansi.Truncate(orDash(policy.Format), widths[2], "..."),
			ansi.Truncate(formatBytes(policy.Size()), widths[3], "..."),
			ansi.Truncate(policyStatus(policy, applied), widths[4], "..."),
		}

		if showActions {
			cells = append(cells, rollbackButton(i == selectedIndex))
		}

		t.Row(cells...)
	}

	body := "\n" + t.Render()

	// Say so rather than silently showing part of the list.
	if hidden > 0 {
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("+%d more", hidden))
	}

	if fetchErr != nil {
		body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(body, budget, panelBodyWidth(width)))
}

const rollbackLabel = "[ Rollback ]"

func rollbackButton(selected bool) string {
	if selected {
		return lipgloss.NewStyle().Foreground(styles.ColorYellow).Bold(true).Render(rollbackLabel)
	}

	return styles.SubtitleStyle.Render(rollbackLabel)
}

func isApplied(policy dataplane.PolicyBundle, applied *dataplane.PolicyBundle) bool {
	return applied != nil && applied.ConfigID == policy.ConfigID
}

func policyStatus(policy dataplane.PolicyBundle, applied *dataplane.PolicyBundle) string {
	if isApplied(policy, applied) {
		return "Applied"
	}

	return "Installed"
}

func formatBytes(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}

	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}
