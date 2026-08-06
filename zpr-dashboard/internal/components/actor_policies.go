package components

import (
	"charm.land/bubbles/v2/viewport"
	"neboagency.com/zpr-dashborad/internal/styles"
)

// ActorPolicies states plainly that policy bindings aren't available here:
// the API exposes policies as a global list (GET /admin/policies), with no
// endpoint linking a specific actor to a set of bound policies.
func ActorPolicies(vp viewport.Model) string {
	content := styles.TitleStyle.Render("Policy Bindings") + "\n\n"
	content += styles.ValueStyle.Foreground(styles.ColorDimmed).Render("Not available — policies aren't scoped per actor by the API")

	containerSize := vp.Width() / 3

	return styles.ContainerStyle.Height(vp.Height() / 3).Width(containerSize).Render(content)
}
