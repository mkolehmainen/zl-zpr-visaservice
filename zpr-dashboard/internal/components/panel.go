package components

import (
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/styles"
)

const panelChrome = 4

func detailPanel(width, height int, title, subtitle string, body string) string {
	content := styles.TitleStyle.Render(title) + "\n"
	content += styles.SubtitleStyle.Render(subtitle) + "\n"
	content += clampLines(body, height-panelChrome, panelBodyWidth(width))

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}

func tableRowsThatFit(total, budget, extra int) (shown, hidden int) {
	rows := budget - 3 - extra
	if rows >= total {
		return total, 0
	}

	// The note needs a row of its own
	rows--
	if rows < 0 {
		rows = 0
	}

	return rows, total - rows
}

// tableRowsThatFitHeights is tableRowsThatFit for tables whose rows are not
// all one line high. heights[i] is the rendered line count of row i.
func tableRowsThatFitHeights(heights []int, budget, extra int) (shown, hidden int) {
	lines := budget - 3 - extra

	used := 0
	for i, h := range heights {
		if used+h > lines {
			// The note needs a line of its own
			for i > 0 && used+1 > lines {
				i--
				used -= heights[i]
			}
			return i, len(heights) - i
		}
		used += h
	}

	return len(heights), 0
}

// A panel that overflows pushes its neighbour out of line.
func clampLines(body string, rows, width int) string {
	if rows <= 0 {
		return ""
	}

	lines := strings.Split(body, "\n")
	if len(lines) > rows {
		lines = lines[:rows]
	}

	for i, line := range lines {
		if lipgloss.Width(line) > width {
			lines[i] = ansi.Truncate(line, max(1, width), "...")
		}
	}

	return strings.Join(lines, "\n")
}

func panelBodyWidth(width int) int {
	return max(1, width-4)
}

func panelTable(width int, headers []string, widths []int) *table.Table {
	return table.New().
		Width(width).
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

			if col < len(widths) {
				return s.Width(widths[col]).MaxWidth(widths[col])
			}

			return s
		})
}

func panelNote(text string) string {
	return "\n" + styles.ValueStyle.Foreground(styles.ColorDimmed).Render(text)
}

func panelError(fetchErr error) string {
	return "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("Error: could not reach visa admin service") + "\n" +
		styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fetchErr.Error())
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}

	if strings.HasSuffix(word, "y") {
		return strings.TrimSuffix(word, "y") + "ies"
	}

	return word + "s"
}

// placeholderTitle marks a panel whose data is invented rather than fetched.
func placeholderTitle(title string) string {
	return styles.TitleStyle.Render(title) + styles.SubtitleStyle.Render(" (Placeholder)")
}

func placeholderPanel(width, height int, title, subtitle, body string) string {
	content := placeholderTitle(title) + "\n"
	content += styles.SubtitleStyle.Render(subtitle) + "\n"
	content += clampLines(body, height-panelChrome, panelBodyWidth(width))

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}

var placeholderMark = styles.SubtitleStyle.Render(" (Placeholder)")
