package pages

import (
	"fmt"
	"time"

	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// Below these heights the lower sections are dropped rather than overflow
const (
	chartsMinHeight      = 37
	userActionsMinHeight = 25
)

type container struct {
	title       string
	subtitle    string
	value       string
	color       string
	placeholder bool
}

func HomePage(
	vp viewport.Model,
	revocationCount int,
	actorCount int,
	visaRequestsCount int,
	online bool,
	uptime time.Duration,
	services []dataplane.ServiceDescriptor,
	actors []dataplane.ActorDescriptor,
	network []dataplane.NodeConnection,
	denies []dataplane.DenyRecord,
	alerts []components.Alert,
	networkErr error,
	denyFetchErr error,
	showStatic bool,
) string {
	containers := []container{
		{"Revocations", "Since start", fmt.Sprintf("%d", revocationCount), "#7aa2f7", false},
		{"Total Visa Requests", "Since start", fmt.Sprintf("%d", visaRequestsCount), "#9ece6a", false},
		{"Total Actors Conneceted", "Currently", fmt.Sprintf("%d", actorCount), "#f7768e", false},
		{"Alerts Reported", "Currently live", fmt.Sprintf("%d", len(alerts)), "#e0af68", false},
	}

	boxWidth := vp.Width() / len(containers)
	boxes := make([]string, 0, len(containers))
	for i, c := range containers {
		width := boxWidth
		if i == len(containers)-1 {
			width = vp.Width() - i*boxWidth
		}

		if c.placeholder {
			boxes = append(boxes, components.PlaceholderContainerWidth(width, c.title, c.subtitle, c.value, c.color))
			continue
		}

		boxes = append(boxes, components.DataContainerWidth(width, c.title, c.subtitle, c.value, c.color))
	}

	showCharts := vp.Height() >= chartsMinHeight
	showActions := showStatic && vp.Height() >= userActionsMinHeight

	rowCount := 1
	if showCharts {
		rowCount++
	}
	if showActions {
		rowCount++
	}

	rest := vp.Height() - summaryHeight
	rowHeight := rest / rowCount
	lastHeight := rest - (rowCount-1)*rowHeight

	colWidth := vp.Width() / 2
	trendWidth := vp.Width() - colWidth
	chartHeight := rowHeight
	if !showStatic {
		trendWidth = vp.Width()
		chartHeight = lastHeight
	}

	topologyHeight := rowHeight
	if rowCount == 1 {
		topologyHeight = lastHeight
	}

	topology := lipgloss.JoinHorizontal(
		lipgloss.Left,
		components.NetworkTopology(colWidth, topologyHeight, network, actors, online, uptime, networkErr),
		components.AlertPanel(vp.Width()-colWidth, topologyHeight, alerts),
	)

	rows := []string{
		lipgloss.JoinHorizontal(lipgloss.Left, boxes...),
		topology,
	}

	if showCharts {
		height := chartHeight
		if !showActions {
			height = lastHeight
		}

		trend := components.DenyList(trendWidth, height, denies, actors, denyFetchErr)
		if showStatic {
			trend = lipgloss.JoinHorizontal(
				lipgloss.Left,
				components.ThroughputChartPanel(colWidth, height),
				trend,
			)
		}

		rows = append(rows, trend)
	}

	if showActions {
		rows = append(rows, components.UserActionsPanel(vp.Width(), lastHeight))
	}

	return lipgloss.JoinVertical(lipgloss.Top, rows...)
}
