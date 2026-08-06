package charts

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"

	"neboagency.com/zpr-dashborad/internal/styles"
)

func BarChart(width int, height int, data [][]int, colors []color.Color, labels []string) string {
	barCount := len(data[0])
	groupCount := len(data)

	iw := width - 4
	ih := height - 4

	var yLabelW = 7
	var barsPerGrp = barCount
	var grpGap = 5
	var grpW = barsPerGrp + grpGap

	chartW := iw - yLabelW
	chartH := ih - 3 // title + x-axis rule + x-axis labels

	if chartW < grpW || chartH < 3 {
		return "Terminal window size is too narrow..."
	}

	// Show at most 12 hours; fewer if the panel is too narrow or there
	// isn't that much data yet.
	numGroups := min(chartW/grpW, 12, groupCount)

	// Show the most recent numGroups hours (right-edge = current hour).
	startHour := max(0, groupCount-numGroups)

	// ── Shared Y-axis max across all metrics and all hours ────────────────────
	globalMax := 1
	for h := range groupCount {
		for k := range barCount {
			if data[h][k] > globalMax {
				globalMax = data[h][k]
			}
		}
	}

	// ── Build the character grid ──────────────────────────────────────────────
	fracBlocks := []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	gridW := numGroups * grpW
	grid := make([][]string, chartH)
	for y := range chartH {
		grid[y] = make([]string, gridW)
		for x := range gridW {
			grid[y][x] = " "
		}
	}

	for g := range numGroups {
		h := startHour + g
		baseX := g * grpW

		for k := range barCount {
			barH8 := data[h][k] * chartH * 8 / globalMax
			fullRows := barH8 / 8
			frac := barH8 % 8
			col := colors[k]
			x := baseX + k

			for row := 0; row < fullRows && row < chartH; row++ {
				grid[chartH-1-row][x] = lipgloss.NewStyle().Foreground(col).Render("█")
			}
			if frac > 0 && fullRows < chartH {
				grid[chartH-1-fullRows][x] = lipgloss.NewStyle().
					Foreground(col).Render(string(fracBlocks[frac]))
			}
		}
	}

	// ── Assemble rows ─────────────────────────────────────────────────────────
	var rows []string
	for y := range chartH {
		var label string
		switch y {
		case 0:
			label = fmt.Sprintf("%4d │ ", globalMax)
		case chartH / 2:
			label = fmt.Sprintf("%4d │ ", globalMax/2)
		case chartH - 1:
			label = "   0 │ "
		default:
			label = "     │ "
		}

		var sb strings.Builder
		for _, cell := range grid[y] {
			sb.WriteString(cell)
		}
		rows = append(rows, styles.ValueStyle.Foreground(styles.ColorDimmed).Render(label)+sb.String())
	}

	// x-axis rule
	rows = append(rows, styles.ValueStyle.Foreground(styles.ColorDimmed).Render(strings.Repeat(" ", yLabelW-2)+"└"+strings.Repeat("─", chartW)))

	pad := chartW - 7
	rows = append(rows, styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fmt.Sprintf("    %dh ago", numGroups)+strings.Repeat(" ", pad)+"Now"))

	return strings.Join(rows, "\n")
}
