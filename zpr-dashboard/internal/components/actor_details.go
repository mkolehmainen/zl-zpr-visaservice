package components

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

func label(text string) string {
	return styles.ValueStyle.Foreground(styles.ColorDimmed).Render(text)
}

// The server always returns 0 here, which would render as 1970.
func formatCreated(seconds int64) string {
	if seconds == 0 {
		return "not tracked yet"
	}
	return timefmt.DateTime(seconds)
}

func nodeSyncState(node *dataplane.NodeRecordBrief) string {
	if !node.InSync {
		return lipgloss.NewStyle().Foreground(styles.ColorYellow).Render("not connected")
	}

	state := lipgloss.NewStyle().Foreground(styles.ColorGreen).Render("in sync")
	if node.VssPort != nil {
		state += styles.SubtitleStyle.Render(fmt.Sprintf(" · port %d", *node.VssPort))
	}

	return state
}

func nodeRequestSummary(node *dataplane.NodeRecordBrief) string {
	summary := fmt.Sprintf("%d asked", node.VisaRequests)
	if node.VisaRequests == 0 {
		return summary
	}

	return summary + styles.SubtitleStyle.Render(fmt.Sprintf(" · %d approved · %d denied",
		node.ApprovedVreqs, node.DeniedVreqs))
}

func nodeVisaSummary(node *dataplane.NodeRecordBrief) string {
	summary := fmt.Sprintf("%d installed", len(node.Visas))

	var pending []string
	if node.PendingInstall > 0 {
		pending = append(pending, fmt.Sprintf("%d queued", node.PendingInstall))
	}

	if node.PendingRevocation > 0 {
		pending = append(pending, fmt.Sprintf("%d revoking", node.PendingRevocation))
	}

	if len(pending) == 0 {
		return summary
	}

	return summary + styles.SubtitleStyle.Render(" · "+strings.Join(pending, " · "))
}

func ActorDetails(width, height int, actors []dataplane.ActorDescriptor, selectedIndex int, fetchErr error) string {
	title := styles.TitleStyle.Render("Actor Details")
	budget := height - 3
	inner := panelBodyWidth(width)

	render := func(body string) string {
		return styles.ContainerStyle.Height(height).Width(width).
			Render(title + clampLines(body, budget, inner))
	}

	if fetchErr != nil && len(actors) == 0 {
		return render(panelError(fetchErr))
	}

	if selectedIndex < 0 || selectedIndex >= len(actors) {
		return render(panelNote("Collecting data..."))
	}

	actor := actors[selectedIndex]

	auth := ActorAuthState(actor)
	now := time.Now().Truncate(time.Second)

	// The leading blank spacer counts against the budget, and a failed refresh
	// needs its own line at the end.
	lines := []string{""}
	room := budget - 1
	if fetchErr != nil {
		room--
	}

	fields := []string{
		fmt.Sprintf("%s %s", label("Name"), actor.CName),
		fmt.Sprintf("%s %s", label("Address"), orDash(actor.ZprAddress)),
		fmt.Sprintf("%s %s", label("Created"), formatCreated(actor.Created)),
		fmt.Sprintf("%s %s", label("Role"), actorRole(actor)),
		fmt.Sprintf("%s %s", label("Auth"), lipgloss.NewStyle().Foreground(authStateColor(auth)).Render(authStateName(auth))),
		fmt.Sprintf("%s %s", label("Dock"), orUnknown(actorDock(actors, actor))),
	}

	if addr := actor.Attr("zpr.substrate_addr"); len(addr) > 0 && addr[0] != "" {
		fields = append(fields, fmt.Sprintf("%s %s", label("Substrate Address"), addr[0]))
	}

	if actor.Node {
		adapters := "unknown"
		if actor.NodeDetails != nil {
			adapters = strconv.Itoa(len(actor.NodeDetails.Adapters))
		}
		fields = append(fields, fmt.Sprintf("%s %s", label("Connected Adapters"), adapters))
	}

	if node := actor.NodeDetails; node != nil {
		fields = append(fields,
			fmt.Sprintf("%s %s", label("VSS"), nodeSyncState(node)),
			fmt.Sprintf("%s %s", label("Requests"), nodeRequestSummary(node)),
			fmt.Sprintf("%s %s", label("Visas"), nodeVisaSummary(node)),
		)
	}

	// Core and node fields outrank arbitrary attributes for the space left.
	for _, field := range fields {
		if len(lines) >= room {
			break
		}
		lines = append(lines, field)
	}

	attrs := displayAttrs(actor)
	if len(attrs) > 0 {
		shown := 0
		// One line goes to the "+N more" footer unless everything fits.
		if len(lines)+len(attrs) > room {
			shown = max(0, room-len(lines)-1)
		} else {
			shown = len(attrs)
		}

		for _, attr := range attrs[:shown] {
			lines = append(lines, formatAttr(attr, now))
		}

		if hidden := len(attrs) - shown; hidden > 0 && len(lines) < room {
			lines = append(lines, styles.SubtitleStyle.Render(fmt.Sprintf("+%d more %s", hidden, plural(hidden, "attribute"))))
		}
	}

	if fetchErr != nil {
		lines = append(lines, lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error()))
	}

	return render(strings.Join(lines, "\n"))
}

// orUnknown renders a missing value as the literal "unknown".
func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}

	return value
}
