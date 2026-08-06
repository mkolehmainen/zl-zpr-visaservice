// Invented data: a revocation records only a type and a CN.
package components

import (
	"github.com/charmbracelet/x/ansi"
)

var blacklistEntries = []struct {
	id     string
	reason string
	added  string
}{
	{"rogue-node-07", "Security Breach", "2026-07-28 14:02"},
	{"ext-node-12", "Policy Violation", "2026-07-28 11:47"},
	{"corp-device-04", "Manual Block", "2026-07-27 19:15"},
	{"svc-account-03", "Revocation Cascade", "2026-07-27 08:31"},
}

// Box at the top of th revocation page, auto and manual revocations
// Not implemented (GET /admin/authrevoke/{id} exists but records no origin):
//
//	GET /admin/authrevoke/{id}
//
//	Request Parameters:
//	  (none)
//
//	Response:
//	  AuthRevoke:
//	    origin auto|manual (policy or an operator withdrew it)
//	    at number (epoch seconds)
func RevocationOrigins() (auto, manual int) {
	return 17, 4
}

// Not implemented:
//
//	GET /admin/authrevoke/blacklist
//
//	Request Parameters:
//	  (none)
//
//	Response:
//	  BlacklistEntry[]:
//	    id string
//	    kind actor|visa|node
//	    reason string
//	    author string
//	    at number
//	    expires number|null
func RevocationBlacklist(width, height int) string {
	const title, subtitle = "Blacklisted IDs", "Static sample data"

	tableWidth := width - 5
	idSize := int(float32(tableWidth) * 0.35)
	reasonSize := int(float32(tableWidth) * 0.35)
	addedSize := int(float32(tableWidth) * 0.3)

	t := panelTable(tableWidth,
		[]string{"ID", "Reason", "Added"},
		[]int{idSize, reasonSize, addedSize},
	)

	for _, entry := range blacklistEntries {
		t.Row(
			ansi.Truncate(entry.id, idSize, "..."),
			ansi.Truncate(entry.reason, reasonSize, "..."),
			ansi.Truncate(entry.added, addedSize, "..."),
		)
	}

	return placeholderPanel(width, height, title, subtitle, t.Render())
}
