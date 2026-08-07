package styles

import (
	"os"
	"strings"

	"charm.land/lipgloss/v2"
)

// HeaderTitleWidth is the width of the "ZPR Dashboard HH:MM:SS ZONE" title
// block. The tab strip is padded to the remaining width, so both must use it.
const HeaderTitleWidth = 28

var hasDarkBG = lipgloss.HasDarkBackground(os.Stdin, os.Stdout)
var lightDark = lipgloss.LightDark(hasDarkBG)

var (
	ColorBg          = lipgloss.Color("#1a1b26")
	ColorFg          = lipgloss.Color("#c0caf5")
	ColorDimmed      = lipgloss.Color("#6c78ad")
	ColorGreen       = lipgloss.Color("#9ece6a")
	ColorRed         = lipgloss.Color("#f7768e")
	ColorYellow      = lipgloss.Color("#e0af68")
	ColorCyan        = lipgloss.Color("#7dcfff")
	ColorBlue        = lipgloss.Color("#7aa2f7")
	ColorOrange      = lipgloss.Color("#ff9e64")
	ColorPurple      = lipgloss.Color("#bb9af7")
	ColorBorder      = lipgloss.Color("#3b4261")
	ColorTabActive   = lipgloss.Color("#7aa2f7")
	ColorTabInactive = lipgloss.Color("#24283b")
	ColorPanelBg     = lipgloss.Color("#1f2335")
	ColorTableHeader = lipgloss.Color("#292e42")
	ColorTableSelBg  = lipgloss.Color("#292e42")
)

var (

	// Colors
	normal  = ColorFg
	special = ColorFg
	muted   = ColorFg

	TabsWrapper = lipgloss.NewStyle().AlignHorizontal(lipgloss.Right)

	HeaderWrapper = lipgloss.NewStyle().
			BorderBottom(true).
			Border(lipgloss.RoundedBorder(), false, false, true, false).
			BorderForeground(ColorBorder)

	// Tab styles
	ActiveTab = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorTabInactive).
			Background(ColorTabActive).
			Padding(0, 2)

	InactiveTab = lipgloss.NewStyle().
			Foreground(muted).
			Background(ColorTabInactive).
			Padding(0, 2)

	HoverTab = lipgloss.NewStyle().
			Background(ColorDimmed).
			Padding(0, 2)

	// Container styles
	ContainerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1).
			MarginBottom(-1)

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorDimmed)

	ValueStyle = lipgloss.NewStyle().
			Foreground(ColorYellow)

	HelpStyle = lipgloss.NewStyle().
			Foreground(muted).
			MarginTop(1)

	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(special).
			BorderForeground(normal).
			Width(HeaderTitleWidth)

	dimStyle = lipgloss.NewStyle().Foreground(ColorBorder).AlignHorizontal(lipgloss.Center)
)

func Separator(size int) string {
	return dimStyle.Width(size).Render(strings.Repeat("─", size)) + "\n"
}
