package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func NetworkTopology(
	width, height int,
	network []dataplane.NodeConnections,
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
		return detailPanel(width, height, title, subtitle, panelNote("No nodes connected"))
	}

	budget := height - panelChrome
	size := width - 5

	nodeSize := int(float32(size) * 0.26)
	sourceSize := int(float32(size) * 0.27)
	destSize := int(float32(size) * 0.27)
	adapterSize := size - nodeSize - sourceSize - destSize

	widths := []int{nodeSize, sourceSize, destSize, adapterSize}

	t := panelTable(size, []string{"Node", "Source Nodes", "Destination Nodes", "Adapters"}, widths)

	fits, hidden := tableRowsThatFit(len(network), budget, 0)

	for _, node := range network[:fits] {
		sources, destinations := nodeLinks(node, network)

		t.Row(
			ansi.Truncate(orDash(node.Node), nodeSize, "..."),
			ansi.Truncate(peerList(sources), sourceSize, "..."),
			ansi.Truncate(peerList(destinations), destSize, "..."),
			ansi.Truncate(adapterList(node.Node, actors), adapterSize, "..."),
		)
	}

	body := "\n" + t.Render()

	// Say so rather than silently showing part of the network
	if hidden > 0 {
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("+%d more", hidden))
	}

	return detailPanel(width, height, title, subtitle, body)
}

func nodeLinks(node dataplane.NodeConnections, network []dataplane.NodeConnections) (sources, destinations []string) {
	for _, link := range node.Connections {
		peer, _ := dataplane.PeerName(link)

		if linksBack(network, peer, node.Node) {
			sources = append(sources, peer)
			continue
		}

		destinations = append(destinations, peer)
	}

	return sources, destinations
}

func linksBack(network []dataplane.NodeConnections, peer, cn string) bool {
	for _, node := range network {
		if node.Node != peer {
			continue
		}

		for _, link := range node.Connections {
			if name, _ := dataplane.PeerName(link); name == cn {
				return true
			}
		}
	}

	return false
}

func peerList(peers []string) string {
	if len(peers) == 0 {
		return "—"
	}

	return strings.Join(peers, ", ")
}

func adapterList(cn string, actors []dataplane.ActorDescriptor) string {
	actor, ok := actorByCN(actors, cn)
	if !ok || actor.NodeDetails == nil || len(actor.NodeDetails.Adapters) == 0 {
		return "—"
	}

	adapters := actor.NodeDetails.Adapters
	if len(adapters) > 2 {
		return fmt.Sprintf("%s, +%d", strings.Join(adapters[:2], ", "), len(adapters)-2)
	}

	return strings.Join(adapters, ", ")
}

func topologyStatus(online bool, uptime time.Duration) string {
	if !online {
		return "Admin service unreachable"
	}

	total := int(uptime.Seconds())

	return fmt.Sprintf("Online · up %02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}
