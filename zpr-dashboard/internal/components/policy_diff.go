package components

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func PolicyVersionDiff(
	width, height int,
	policies []dataplane.PolicyBundle,
	selectedIndex int,
	applied *dataplane.PolicyBundle,
	fetchErr error,
) string {
	const title = "Version Diff"

	if fetchErr != nil && len(policies) == 0 {
		return detailPanel(width, height, title, "Selected against applied", panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(policies) {
		return detailPanel(width, height, title, "Selected against applied", panelNote("Select a policy"))
	}

	selected := policies[selectedIndex]

	if applied == nil {
		return detailPanel(width, height, title, "Selected against applied",
			panelNote("No applied policy to compare against"))
	}

	if isApplied(selected, applied) {
		return detailPanel(width, height, title,
			fmt.Sprintf("config %d is the applied one", selected.ConfigID),
			panelNote("Selected bundle is the one in force — nothing to compare"))
	}

	subtitle := fmt.Sprintf("config %d → config %d", selected.ConfigID, applied.ConfigID)

	var body string
	for _, row := range diffLines(bundleLines(selected), bundleLines(*applied)) {
		text := ansi.Truncate(row.text, max(4, width-8), "...")

		switch row.kind {
		case diffAdded:
			body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorGreen).Render("+ "+text)
		case diffRemoved:
			body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("- "+text)
		default:
			body += "\n" + styles.SubtitleStyle.Render("  "+text)
		}
	}

	return detailPanel(width, height, title, subtitle, body)
}

func bundleLines(policy dataplane.PolicyBundle) []string {
	return []string{
		fmt.Sprintf("config_id  %d", policy.ConfigID),
		fmt.Sprintf("version    %s", orDash(policy.Version)),
		fmt.Sprintf("format     %s", orDash(policy.Format)),
		fmt.Sprintf("bundle     %s", formatBytes(policy.Size())),
	}
}

type diffKind int

const (
	diffSame diffKind = iota
	diffAdded
	diffRemoved
)

type diffRow struct {
	kind diffKind
	text string
}

// Longest common subsequence, so unchanged lines stays
func diffLines(old, new []string) []diffRow {
	lcs := make([][]int, len(old)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(new)+1)
	}

	for i := len(old) - 1; i >= 0; i-- {
		for j := len(new) - 1; j >= 0; j-- {
			if old[i] == new[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}

			lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
		}
	}

	var rows []diffRow
	i, j := 0, 0
	for i < len(old) && j < len(new) {
		switch {
		case old[i] == new[j]:
			rows = append(rows, diffRow{diffSame, new[j]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			rows = append(rows, diffRow{diffRemoved, old[i]})
			i++
		default:
			rows = append(rows, diffRow{diffAdded, new[j]})
			j++
		}
	}

	for ; i < len(old); i++ {
		rows = append(rows, diffRow{diffRemoved, old[i]})
	}

	for ; j < len(new); j++ {
		rows = append(rows, diffRow{diffAdded, new[j]})
	}

	return rows
}
