package components

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func NetworkTopology(
	width, height int,
	network []dataplane.NodeConnection,
	actors []dataplane.ActorDescriptor,
	online bool,
	uptime time.Duration,
	fetchErr error,
) string {
	const title = "Network Topology"
	subtitle := topologyStatus(online, uptime)

	if fetchErr != nil && len(network) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	if len(network) == 0 {
		return detailPanel(width, height, title, subtitle, panelNote("No links declared"))
	}

	budget := height - panelChrome
	size := width - 5

	nodeSize := int(float32(size) * 0.30)
	peerSize := int(float32(size) * 0.30)
	substrateSize := int(float32(size) * 0.27)
	statusSize := size - nodeSize - peerSize - substrateSize

	// The stale-data warning below takes a line away from the table.
	extra := 0
	if fetchErr != nil {
		extra = 1
	}

	// Rows with a known CN are two lines high, so fit them by rendered height.
	cells := make([][2]string, len(network))
	heights := make([]int, len(network))
	for i, link := range network {
		cells[i] = [2]string{
			topologyNodeCell(link.NodeA, actors, nodeSize),
			topologyNodeCell(link.NodeB, actors, peerSize),
		}
		heights[i] = max(cellLines(cells[i][0]), cellLines(cells[i][1]))
	}

	fits, hidden := tableRowsThatFitHeights(heights, budget, extra)

	t := panelTable(size, []string{"Node", "Link To", "Substrate", "Status"},
		[]int{nodeSize, peerSize, substrateSize, statusSize})

	for i, link := range network[:fits] {
		t.Row(
			cells[i][0],
			cells[i][1],
			ansi.Truncate(orDash(link.Substrate), substrateSize, "..."),
			linkStatus(link.CType),
		)
	}

	body := "\n" + t.Render()

	// Say so rather than silently showing part of the network
	if hidden > 0 {
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("+%d more", hidden))
	}

	if fetchErr != nil {
		body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return detailPanel(width, height, title, subtitle, body)
}

// topologyNodeCell shows a node address and, when known, its actor CN below it.
func topologyNodeCell(addr string, actors []dataplane.ActorDescriptor, width int) string {
	cell := ansi.Truncate(orDash(addr), width, "...")
	actor, ok := actorByAddr(actors, addr)
	if !ok || actor.CName == "" {
		return cell
	}

	cn := ansi.Truncate(actor.CName, width, "...")
	return cell + "\n" + styles.SubtitleStyle.Render(cn)
}

// cellLines counts the terminal lines a rendered table cell occupies.
func cellLines(cell string) int {
	return strings.Count(cell, "\n") + 1
}

// linkStatus renders a ctype with the colour the CLI uses: up green,
// down red, undeclared-but-live yellow.
func linkStatus(ctype string) string {
	colour := styles.ColorYellow // INVALID, and anything unrecognised
	switch ctype {
	case "UP":
		colour = styles.ColorGreen
	case "DOWN":
		colour = styles.ColorRed
	}
	return lipgloss.NewStyle().Foreground(colour).Render(orDash(ctype))
}

func topologyStatus(online bool, uptime time.Duration) string {
	if !online {
		return "Admin service unreachable"
	}

	total := int(uptime.Seconds())

	return fmt.Sprintf("Online · up %02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}
