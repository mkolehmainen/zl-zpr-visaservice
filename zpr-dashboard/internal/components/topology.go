package components

import (
	"fmt"
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
	actorSize := int(float32(size) * 0.18)
	substrateSize := int(float32(size) * 0.37)
	statusSize := size - nodeSize - actorSize - substrateSize

	// The stale-data warning below takes a line away from the table.
	extra := 0
	if fetchErr != nil {
		extra = 1
	}

	// Every link renders both its endpoints, so every row is two lines high.
	heights := make([]int, len(network))
	for i := range heights {
		heights[i] = topologyRowLines
	}

	fits, hidden := tableRowsThatFitHeights(heights, budget, extra)

	t := panelTable(size, []string{"Node", "Actor", "Substrate", "Status"},
		[]int{nodeSize, actorSize, substrateSize, statusSize})

	for _, link := range network[:fits] {
		node, actor, substrate := topologyLinkCells(link, actors, nodeSize, actorSize, substrateSize)
		t.Row(node, actor, substrate, linkStatus(link.CType))
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

// topologyRowLines is the height of one link's row: a line per endpoint.
const topologyRowLines = 2

// peerMarker indents endpoint B's line beneath endpoint A's.
const peerMarker = " ↳ "

// topologyLinkCells renders one link as two-line cells: endpoint A on the
// first line, endpoint B indented beneath it under a ↳ marker.
func topologyLinkCells(link dataplane.NodeConnection, actors []dataplane.ActorDescriptor,
	nodeSize, actorSize, substrateSize int) (node, actor, substrate string) {
	node = ansi.Truncate(orDash(link.NodeA), nodeSize, "...") + "\n" +
		peerMarker + ansi.Truncate(orDash(link.NodeB), max(1, nodeSize-lipgloss.Width(peerMarker)), "...")

	actor = styles.SubtitleStyle.Render(topologyActorName(link.NodeA, actors, actorSize)) + "\n" +
		styles.SubtitleStyle.Render(topologyActorName(link.NodeB, actors, actorSize))

	substrate = ansi.Truncate(orDash(link.SubstrateA), substrateSize, "...") + "\n" +
		ansi.Truncate(orDash(link.SubstrateB), substrateSize, "...")

	return node, actor, substrate
}

// topologyActorName is the CN of the actor at addr, or a dash when no actor
// claims that address.
func topologyActorName(addr string, actors []dataplane.ActorDescriptor, width int) string {
	// A miss yields the zero descriptor, whose empty CN becomes the dash.
	actor, _ := actorByAddr(actors, addr)
	return ansi.Truncate(orDash(actor.CName), width, "...")
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
