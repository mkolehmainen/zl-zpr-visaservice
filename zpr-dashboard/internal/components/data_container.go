package components

import (
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func DataContainer(vp viewport.Model, size float32, title string, subtitle string, value string, color string) string {
	return DataContainerWidth(int(float32(vp.Width())*size), title, subtitle, value, color)
}

func DataContainerWidth(width int, title string, subtitle string, value string, color string) string {
	return dataBox(width, lipgloss.NewStyle().Foreground(styles.ColorFg).Render(title), subtitle, value, color)
}

func PlaceholderContainer(vp viewport.Model, size float32, title string, subtitle string, value string, color string) string {
	return PlaceholderContainerWidth(int(float32(vp.Width())*size), title, subtitle, value, color)
}

func PlaceholderContainerWidth(width int, title string, subtitle string, value string, color string) string {
	marked := lipgloss.NewStyle().Foreground(styles.ColorFg).Render(title) + styles.SubtitleStyle.Render(" (Placeholder)")

	return dataBox(width, marked, subtitle, value, color)
}

func dataBox(width int, title string, subtitle string, value string, color string) string {
	inner := max(1, width-4)

	return styles.ContainerStyle.Width(width).Render(
		lipgloss.JoinVertical(
			lipgloss.Top,
			ansi.Truncate(title, inner, "..."),
			ansi.Truncate(lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(value), inner, "..."),
			ansi.Truncate(lipgloss.NewStyle().Foreground(styles.ColorDimmed).Render(subtitle), inner, "..."),
		),
	)
}
