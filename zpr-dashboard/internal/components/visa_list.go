package components

import (
	"fmt"
	"strconv"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

type VisaView int

const (
	VisaViewActive VisaView = iota
	VisaViewRequests
)

const (
	visaSegActive   = "Active Visas"
	visaSegRequests = "Visa Requests"
	visaSegDivider  = " · "
)

func (v VisaView) Toggled() VisaView {
	if v == VisaViewActive {
		return VisaViewRequests
	}

	return VisaViewActive
}

func VisaPanel(
	width, height int,
	view VisaView,
	visas []dataplane.VisaDescriptor,
	actors []dataplane.ActorDescriptor,
	selectedIndex int,
	fetchErr error,
) string {
	content := visaSegments(width, view, len(visas)) + "\n"
	content += styles.Separator(width - 4)
	budget := height - panelChrome

	if fetchErr != nil && len(visas) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelError(fetchErr), budget, panelBodyWidth(width)))
	}

	if len(visas) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelNote(visaEmptyNote(view)), budget, panelBodyWidth(width)))
	}

	var body string
	extra := 0
	if fetchErr != nil {
		extra = 1
	}

	fits, hidden := tableRowsThatFit(len(visas), budget, extra)
	shown := visas[:fits]

	if view == VisaViewActive {
		body = "\n" + activeVisaTable(width, shown, actors, selectedIndex)
	} else {
		body = "\n" + visaRequestTable(width, shown, actors)
	}

	if hidden > 0 {
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("+%d more", hidden))
	}

	if fetchErr != nil {
		body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(clampLines(body, budget, panelBodyWidth(width)))
}

func visaSegments(width int, view VisaView, count int) string {
	segment := func(label string, on bool) string {
		if on {
			return lipgloss.NewStyle().Foreground(styles.ColorCyan).Bold(true).Underline(true).Render(label)
		}

		return styles.SubtitleStyle.Render(label)
	}

	control := segment(visaSegActive, view == VisaViewActive) +
		styles.SubtitleStyle.Render(visaSegDivider) +
		segment(visaSegRequests, view == VisaViewRequests)

	status := styles.SubtitleStyle.Render(fmt.Sprintf("%d active", count))

	gap := width - 4 - lipgloss.Width(control) - lipgloss.Width(status)

	if gap < 1 {
		return ansi.Truncate(control, width-4, "...")
	}

	return control + lipgloss.NewStyle().Width(gap).Render("") + status
}

func visaEmptyNote(view VisaView) string {
	if view == VisaViewActive {
		return "No active visas — granted requests appear here"
	}

	return "No visa requests granted yet"
}

func activeVisaTable(width int, visas []dataplane.VisaDescriptor, actors []dataplane.ActorDescriptor, selectedIndex int) string {
	size := width - 5

	// ponytail: time-only on the Visas tables -- the date does not fit a 10% column.
	// Widen issuedSize to 0.14 (from cnSize) and switch to timefmt.DateTime if
	// day-old visas confuse people.
	issuedSize := int(float32(size) * 0.12)
	idSize := int(float32(size) * 0.1)
	cnSize := int(float32(size) * 0.24)
	sourceSize := int(float32(size) * 0.2)
	destSize := int(float32(size) * 0.2)
	expiresSize := size - issuedSize - idSize - cnSize - sourceSize - destSize

	widths := []int{issuedSize, idSize, cnSize, sourceSize, destSize, expiresSize}

	t := panelTable(size, []string{"Issued", "ID", "Requesting Node", "Source", "Destination", "Expires in"}, widths).
		StyleFunc(visaRowStyle(widths, selectedIndex, len(visas), 5, func(row int) bool {
			return expiringSoon(visas[row])
		}))

	for _, visa := range visas {
		t.Row(
			ansi.Truncate(timefmt.TimeOfDay(visa.Created), issuedSize, "..."),
			ansi.Truncate(strconv.FormatInt(visa.ID, 10), idSize, "..."),
			ansi.Truncate(visaSubject(visa, actors), cnSize, "..."),
			ansi.Truncate(endpointLabel(visa.Source(), actors), sourceSize, "..."),
			ansi.Truncate(endpointLabel(visa.Dest(), actors), destSize, "..."),
			ansi.Truncate(formatRemaining(visa), expiresSize, "..."),
		)
	}

	return t.Render()
}

func visaRequestTable(width int, visas []dataplane.VisaDescriptor, actors []dataplane.ActorDescriptor) string {
	size := width - 5

	timeSize := int(float32(size) * 0.1)
	statusSize := int(float32(size) * 0.11)
	idSize := int(float32(size) * 0.08)
	cnSize := int(float32(size) * 0.21)
	portSize := int(float32(size) * 0.08)
	sourceSize := int(float32(size) * 0.18)
	destSize := int(float32(size) * 0.18)
	expiresSize := size - timeSize - statusSize - idSize - cnSize - portSize - sourceSize - destSize

	widths := []int{timeSize, statusSize, idSize, cnSize, portSize, sourceSize, destSize, expiresSize}

	t := panelTable(size, []string{"Time", "Status", "ID", "Requesting Node", "Port", "Source", "Destination", "Expires"}, widths).
		StyleFunc(visaRowStyle(widths, -1, len(visas), 7, func(row int) bool {
			return expiringSoon(visas[row])
		}))

	for _, visa := range visas {
		t.Row(
			ansi.Truncate(timefmt.TimeOfDay(visa.Created), timeSize, "..."),
			ansi.Truncate("Granted", statusSize, "..."),
			ansi.Truncate(strconv.FormatInt(visa.ID, 10), idSize, "..."),
			ansi.Truncate(visaSubject(visa, actors), cnSize, "..."),
			ansi.Truncate(visaPort(visa), portSize, "..."),
			ansi.Truncate(endpointLabel(visa.Source(), actors), sourceSize, "..."),
			ansi.Truncate(endpointLabel(visa.Dest(), actors), destSize, "..."),
			ansi.Truncate(formatRemaining(visa), expiresSize, "..."),
		)
	}

	return t.Render()
}

func visaRowStyle(widths []int, selectedIndex, rows, warnCol int, warn func(row int) bool) func(row, col int) lipgloss.Style {
	return func(row, col int) lipgloss.Style {
		s := lipgloss.NewStyle()

		if row == table.HeaderRow {
			s = s.
				Foreground(styles.ColorBlue).
				Bold(true).
				Border(lipgloss.RoundedBorder(), false, false, true, false).
				BorderForeground(styles.ColorDimmed)
		} else {
			s = s.Foreground(styles.ColorFg)

			// Visas on their way out are worth spotting.
			if col == warnCol && row < rows && warn(row) {
				s = s.Foreground(styles.ColorYellow)
			}

			if row == selectedIndex {
				s = s.Background(styles.ColorTableSelBg)
			}
		}

		if col < len(widths) {
			return s.Width(widths[col]).MaxWidth(widths[col])
		}

		return s
	}
}
func visaSubject(visa dataplane.VisaDescriptor, actors []dataplane.ActorDescriptor) string {
	if actor, ok := actorByAddr(actors, visa.RequestingNode); ok {
		return actor.CName
	}

	return orDash(visa.RequestingNode)
}

func actorByAddr(actors []dataplane.ActorDescriptor, addr string) (dataplane.ActorDescriptor, bool) {
	if addr == "" {
		return dataplane.ActorDescriptor{}, false
	}

	for _, actor := range actors {
		if actor.ZprAddress == addr {
			return actor, true
		}
	}

	return dataplane.ActorDescriptor{}, false
}

func visaPort(visa dataplane.VisaDescriptor) string {
	if icmpType, icmpCode, ok := visa.ICMP(); ok {
		return fmt.Sprintf("%d/%d", icmpType, icmpCode)
	}

	port, ok := visa.Port()
	if !ok {
		return "—"
	}

	if port == 0 {
		return "any"
	}

	return strconv.Itoa(port)
}

func SelectedVisa(visas []dataplane.VisaDescriptor, selectedIndex int) *dataplane.VisaDescriptor {
	if selectedIndex < 0 || selectedIndex >= len(visas) {
		return nil
	}

	return &visas[selectedIndex]
}

const expiringSoonWindow = time.Hour

func visaExpiry(visa dataplane.VisaDescriptor) time.Time {
	return time.Unix(visa.Expires, 0)
}

func expiringSoon(visa dataplane.VisaDescriptor) bool {
	remaining := time.Until(visaExpiry(visa))

	return remaining > 0 && remaining < expiringSoonWindow
}

func ExpiringVisas(visas []dataplane.VisaDescriptor) int {
	count := 0
	for _, visa := range visas {
		if expiringSoon(visa) {
			count++
		}
	}

	return count
}

func formatRemaining(visa dataplane.VisaDescriptor) string {
	now := time.Now()

	remaining := visaExpiry(visa).Sub(now)
	if remaining <= 0 {
		return "expired"
	}

	if years, ok := timefmt.FarFuture(visa.Expires, now); ok {
		return years
	}

	hours := int(remaining.Hours())
	if hours >= 24 {
		return fmt.Sprintf("%dd %dh", hours/24, hours%24)
	}

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, int(remaining.Minutes())%60)
	}

	return fmt.Sprintf("%dm", int(remaining.Minutes()))
}
