package components

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/styles"
)

const alertBlockHeight = 4
const alertVerboseMin = alertBlockHeight * 3

// Full blocks when there is room, one line per alert when there is not
func AlertPanel(width, height int, alerts []Alert) string {
	count := lipgloss.NewStyle().Foreground(styles.ColorRed).Bold(true).
		Render(fmt.Sprintf("%d Live!", len(alerts)))

	content := styles.TitleStyle.Render("Alerts & Warnings:") + " " + count + "\n"
	content += styles.Separator(width - 4)

	budget := height - panelChrome
	rows := budget - 1
	if rows < 1 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content)
	}

	inner := panelBodyWidth(width)

	var lines []string
	switch {
	case len(alerts) == 0:
	case rows < alertVerboseMin:
		lines = alertCompactLines(alerts, rows, inner)
	default:
		lines = alertVerboseLines(alerts, rows, inner)
	}

	for len(lines) < rows {
		lines = append(lines, "")
	}

	lines = append(lines, alertClearButton())

	return styles.ContainerStyle.Height(height).Width(width).
		Render(content + clampLines(strings.Join(lines, "\n"), budget, inner))
}

func alertClearButton() string {
	return " " + lipgloss.NewStyle().Foreground(styles.ColorBlue).Bold(true).Render("[c]") +
		styles.SubtitleStyle.Render(" Clear All")
}

const alertClearMark = "[x]"

func alertRow(body string, width int) string {
	gap := width - lipgloss.Width(body) - len(alertClearMark)
	if gap < 1 {
		gap = 1
	}

	return body + strings.Repeat(" ", gap) + styles.SubtitleStyle.Render(alertClearMark)
}

func alertVerboseLines(alerts []Alert, rows, width int) []string {
	var lines []string

	for i, alert := range alerts {
		if len(lines)+alertBlockHeight > rows {
			lines = append(lines, styles.SubtitleStyle.Render(fmt.Sprintf("  ... and %d more", len(alerts)-i)))
			break
		}

		heading := " " + alertIcon(alert) + " " +
			styles.SubtitleStyle.Render(alertTypeName(alert.Type)+": ") +
			lipgloss.NewStyle().Foreground(styles.ColorFg).Render(ansi.Truncate(alert.Title, max(6, width-17), "..."))

		lines = append(lines,
			heading,
			"   "+styles.SubtitleStyle.Render(ansi.Truncate(alert.Detail, max(6, width-7), "...")),
			alertRow("   Risk Level: "+riskColor(alert.Risk).Render(riskText(alert.Risk)), width),
			"",
		)
	}

	return lines
}

func alertCompactLines(alerts []Alert, rows, width int) []string {
	var lines []string

	for i, alert := range alerts {
		if len(lines) == rows-1 && len(alerts) > rows {
			lines = append(lines, styles.SubtitleStyle.Render(fmt.Sprintf("  ... and %d more", len(alerts)-i)))
			break
		}

		if len(lines) >= rows {
			break
		}

		risk := riskText(alert.Risk)
		title := ansi.Truncate(alert.Title, max(6, width-len(risk)-11), "...")

		lines = append(lines, alertRow("  "+alertIcon(alert)+" "+
			lipgloss.NewStyle().Foreground(styles.ColorFg).Render(title)+
			styles.SubtitleStyle.Render(" — ")+riskColor(alert.Risk).Render(risk), width))
	}

	return lines
}

func alertIcon(alert Alert) string {
	switch {
	case alert.Risk == RiskHigh:
		return lipgloss.NewStyle().Foreground(styles.ColorRed).Bold(true).Render("!")
	case alert.Type == AlertTypeAlert:
		return lipgloss.NewStyle().Foreground(styles.ColorOrange).Render("!")
	default:
		return lipgloss.NewStyle().Foreground(styles.ColorYellow).Render("!")
	}
}

func alertTypeName(t AlertType) string {
	if t == AlertTypeAlert {
		return "Alert"
	}

	return "Warning"
}

type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
)

func riskColor(level RiskLevel) lipgloss.Style {
	switch level {
	case RiskLow:
		return lipgloss.NewStyle().Foreground(styles.ColorGreen)
	case RiskMedium:
		return lipgloss.NewStyle().Foreground(styles.ColorOrange)
	case RiskHigh:
		return lipgloss.NewStyle().Foreground(styles.ColorRed).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(styles.ColorFg)
	}
}

func riskText(level RiskLevel) string {
	switch level {
	case RiskLow:
		return "Low"
	case RiskMedium:
		return "Medium"
	case RiskHigh:
		return "High"
	default:
		return "None"
	}
}
