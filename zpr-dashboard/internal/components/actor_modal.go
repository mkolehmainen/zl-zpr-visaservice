package components

import (
	"fmt"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// Not implemented (DELETE /admin/actors/{cn} exists but revokes nothing):
//
//	DELETE /admin/actors/{cn}
//
//	Request Parameters:
//	  revoke_visas boolean (optional, default false)
//
//	Response:
//	  Revokes:
//	    id string
//	    revoked number[] (the visas withdrawn)
func ActorRevokeModal(width, height int, actor dataplane.ActorDescriptor, visas []dataplane.VisaDescriptor, alsoVisas bool) string {
	dim := styles.SubtitleStyle
	value := lipgloss.NewStyle().Foreground(styles.ColorFg)

	field := func(label, val string) string {
		return dim.Render(fmt.Sprintf("  %-10s", label)) + val
	}

	state := ActorAuthState(actor)

	confirm := lipgloss.NewStyle().
		Background(styles.ColorRed).
		Foreground(styles.ColorBg).
		Bold(true).
		Padding(0, 2).
		Render("✓  Confirm")

	cancel := lipgloss.NewStyle().
		Background(styles.ColorBorder).
		Foreground(styles.ColorFg).
		Padding(0, 2).
		Render("✕  Cancel")

	content := strings.Join([]string{
		lipgloss.NewStyle().Foreground(styles.ColorRed).Bold(true).Render("  ⚠  Revoke Actor Authorization"),
		dim.Render("     Immediately invalidate this actor's trust"),
		dim.Render(strings.Repeat("─", 56-2)),
		field("Actor", value.Render(orDash(actor.CName))),
		field("Address", value.Render(orDash(actor.ZprAddress))),
		field("Trust", lipgloss.NewStyle().Foreground(authStateColor(state)).Render(authStateName(state))),
		field("Visas", actorModalVisas(visas)),
		"",
		actorModalToggle(len(visas), alsoVisas),
		"",
		dim.Render("  The admin API revokes nothing, so this dialog"),
		dim.Render("  confirms nothing" + placeholderMark),
		"",
		"  " + confirm + "      " + cancel,
		"  " + dim.Render("   y / enter") + "              " + dim.Render("   n / esc"),
	}, "\n")

	box := lipgloss.NewStyle().
		Width(56).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ColorRed).
		Padding(1, 0).
		Render(content)

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func actorModalVisas(visas []dataplane.VisaDescriptor) string {
	if len(visas) == 0 {
		return styles.SubtitleStyle.Render("none")
	}

	ids := make([]string, 0, 3)
	for i, visa := range visas {
		if i == 3 {
			break
		}

		ids = append(ids, strconv.FormatInt(visa.ID, 10))
	}

	preview := strings.Join(ids, ", ")
	if len(visas) > 3 {
		preview += fmt.Sprintf(", +%d more", len(visas)-3)
	}

	return lipgloss.NewStyle().Foreground(styles.ColorFg).
		Render(fmt.Sprintf("%d attached", len(visas))) +
		styles.SubtitleStyle.Render("  ("+preview+")")
}

func actorModalToggle(count int, on bool) string {
	if count == 0 {
		return styles.SubtitleStyle.Render("  No attached visas to revoke")
	}

	box := styles.SubtitleStyle.Render("[ ]")
	if on {
		box = lipgloss.NewStyle().Foreground(styles.ColorGreen).Render("[✓]")
	}

	return "  " + box + " " + lipgloss.NewStyle().Foreground(styles.ColorFg).
		Render(fmt.Sprintf("Also revoke %d attached %s", count, plural(count, "visa")))
}
