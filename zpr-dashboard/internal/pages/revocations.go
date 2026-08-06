package pages

import (
	"fmt"
	"time"

	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

type revocationBox struct {
	title       string
	subtitle    string
	value       string
	color       string
	placeholder bool
}

func revocationRate(history []int, sample time.Duration) int {
	if len(history) < 2 || sample <= 0 {
		return 0
	}

	delta := history[len(history)-1] - history[0]
	if delta < 0 {
		delta = 0
	}

	window := time.Duration(len(history)-1) * sample

	return int(float64(delta) / window.Minutes())
}

func RevocationsPage(
	vp viewport.Model,
	revocations []dataplane.AuthRevokeDescriptor,
	fetchErr error,
	actors []dataplane.ActorDescriptor,
	revokedHistory []int,
	sample time.Duration,
	showStatic bool,
) string {
	boxes := []revocationBox{
		{"Total Revocations", "In the table", fmt.Sprintf("%d", len(revocations)), "#f7768e", false},
	}

	// Invented: the API does not record auto versus manual.
	if showStatic {
		auto, manual := components.RevocationOrigins()

		boxes = append(boxes,
			revocationBox{"Auto-Triggered", "Policy + expired", fmt.Sprintf("%d", auto), "#ff9e64", true},
			revocationBox{"Manual", "Operator action", fmt.Sprintf("%d", manual), "#e0af68", true},
		)
	}

	boxes = append(boxes, revocationBox{"Rate", "Added per minute", fmt.Sprintf("%d/min", revocationRate(revokedHistory, sample)), "#7dcfff", false})

	boxWidth := vp.Width() / len(boxes)
	rendered := make([]string, 0, len(boxes))
	for i, box := range boxes {
		width := boxWidth
		if i == len(boxes)-1 {
			width = vp.Width() - i*boxWidth
		}

		if box.placeholder {
			rendered = append(rendered, components.PlaceholderContainerWidth(width, box.title, box.subtitle, box.value, box.color))
			continue
		}

		rendered = append(rendered, components.DataContainerWidth(width, box.title, box.subtitle, box.value, box.color))
	}

	rest := vp.Height() - summaryHeight
	feedHeight := rest / 2
	detailHeight := rest - feedHeight

	feed := components.RevocationList(vp.Width(), feedHeight, revocations, actors, fetchErr)

	colWidth := vp.Width() / 2
	rateWidth := vp.Width()

	var detail []string
	if showStatic {
		rateWidth = vp.Width() - colWidth
		detail = append(detail, components.RevocationBlacklist(colWidth, detailHeight))
	}

	detail = append(detail, components.RevocationRateChart(rateWidth, detailHeight, revokedHistory, fetchErr))

	return lipgloss.JoinVertical(
		lipgloss.Top,
		lipgloss.JoinHorizontal(lipgloss.Left, rendered...),
		feed,
		lipgloss.JoinHorizontal(lipgloss.Left, detail...),
	)
}
