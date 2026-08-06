package components

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func label(text string) string {
	return styles.ValueStyle.Foreground(styles.ColorDimmed).Render(text)
}

// The server always returns 0 here, which would render as 1970.
func formatCreated(seconds int64) string {
	if seconds == 0 {
		return "not tracked yet"
	}
	return time.Unix(seconds, 0).Format("2006-01-02 15:04:05")
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

	content := "\n"
	content += fmt.Sprintf("%s %s\n", label("Name"), actor.CName)
	content += fmt.Sprintf("%s %s\n", label("Address"), orDash(actor.ZprAddress))
	content += fmt.Sprintf("%s %s\n", label("Created"), formatCreated(actor.Created))
	content += fmt.Sprintf("%s %s\n", label("Role"), actorRole(actor))
	content += fmt.Sprintf("%s %s", label("Auth"), lipgloss.NewStyle().Foreground(authStateColor(auth)).Render(authStateName(auth)))

	if node := actor.NodeDetails; node != nil {
		content += "\n" + fmt.Sprintf("%s %s\n", label("VSS"), nodeSyncState(node))
		content += fmt.Sprintf("%s %s\n", label("Requests"), nodeRequestSummary(node))
		content += fmt.Sprintf("%s %s", label("Visas"), nodeVisaSummary(node))
	}

	if fetchErr != nil {
		content += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return render(content)
}
