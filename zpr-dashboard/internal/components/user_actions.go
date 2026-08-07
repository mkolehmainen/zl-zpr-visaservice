package components

import (
	"fmt"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/styles"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

// agoSeconds is how far back this sample action happened, so the rendered
// stamp is in the viewer's timezone instead of a hard-coded clock string.
type UserAction struct {
	source     string
	action     string
	attention  bool
	agoSeconds int
}

var actions = [5]UserAction{
	{
		source:     "deploy-agent",
		action:     "Firewall rule #991 updated",
		attention:  false,
		agoSeconds: 146,
	},
	{
		source:     "root@zpr.net",
		action:     "Certificate Rotation: Rotated certificate for kms.zpr.com",
		attention:  false,
		agoSeconds: 142,
	},
	{
		source:     "ops-bot-8",
		action:     "Permission Updated: Granted access to vault.svc.org to zpr service",
		attention:  true,
		agoSeconds: 71,
	},
	{
		source:     "manager-bot-2",
		action:     "Actor Disconneced: Actor #23 disconnected",
		attention:  true,
		agoSeconds: 37,
	},
	{
		source:     "manager-bot-1",
		action:     "Actor Disconneced: Actor #24 disconnected",
		attention:  true,
		agoSeconds: 0,
	},
}

// Not implemented:
//
//	GET /admin/audit
//
//	Request Parameters:
//	  since number (optional, epoch seconds)
//	  limit number (optional)
//
//	Response:
//	  AuditEntry[]:
//	    at number
//	    actor string
//	    action string
//	    target string
//	    risk low|medium|high
//	    outcome string
func UserActionsPanel(width, height int) string {
	// Captured once so every row in a single render shares one reference point.
	now := time.Now()

	content := placeholderTitle("User Action Overview") + "\n"
	content += styles.SubtitleStyle.Render("User actions across the network") + "\n"

	size := width - 5

	if height < 7 {
		return styles.ContainerStyle.Height(height).Width(width).Render(
			content + styles.ValueStyle.Foreground(styles.ColorDimmed).Render(fmt.Sprintf("%d actions", len(actions))),
		)
	}

	sourceSize := int(float32(size) * 0.2)
	actionSize := int(float32(size) * 0.4)
	attentionSize := int(float32(size) * 0.2)
	timeSize := int(float32(size) * 0.2)

	t := table.New().
		Width(size).
		Border(lipgloss.HiddenBorder()).
		Headers("Source", "Action", "Needs Attention?", "Time").
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

			switch col {
			case 0:
				return s.Width(sourceSize).MaxWidth(sourceSize)
			case 1:
				return s.Width(actionSize).MaxWidth(actionSize)
			case 2:
				return s.Width(attentionSize).MaxWidth(attentionSize)
			case 3:
				return s.Width(timeSize).MaxWidth(timeSize)
			default:
				return s
			}
		})

	values := actions[:]
	if budget := max(0, height-7); budget < len(values) {
		values = values[:budget]
	}

	for _, m := range values {
		attention := "No"
		if m.attention {
			attention = "Yes"
		}

		t.Row(
			ansi.Truncate(m.source, sourceSize, "..."),
			ansi.Truncate(m.action, actionSize, "..."),
			ansi.Truncate(attention, attentionSize, "..."),
			ansi.Truncate(now.Add(-time.Duration(m.agoSeconds)*time.Second).Format(timefmt.LayoutTimeOfDay), timeSize, "..."),
		)
	}

	content += lipgloss.NewStyle().PaddingTop(1).Render(t.Render())

	return styles.ContainerStyle.Height(height).Width(width).Render(content)
}
