package pages

import (
	"fmt"

	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// Sizes
const summaryHeight = 5
const policyDetailHeight = 12
const policyTableMinHeight = 9

func PoliciesPage(
	vp viewport.Model,
	policies []dataplane.PolicyBundle,
	selectedIndex int,
	applied *dataplane.PolicyBundle,
	visas []dataplane.VisaDescriptor,
	fetchErr error,
	showStatic bool,
) string {
	appliedCount := 0
	format, bundle := "—", "—"
	if applied != nil {
		appliedCount = 1
		format = applied.Format
		bundle = fmt.Sprintf("%.1f KB", float64(applied.Size())/1024)
	}

	boxWidth := vp.Width() / 4

	summary := lipgloss.JoinHorizontal(
		lipgloss.Left,
		components.DataContainerWidth(boxWidth, "Total Policies", "Installed", fmt.Sprintf("%d", len(policies)), "#7aa2f7"),
		components.DataContainerWidth(boxWidth, "Applied", "Running now", fmt.Sprintf("%d", appliedCount), "#9ece6a"),
		components.DataContainerWidth(boxWidth, "Bundle Size", "Applied policy", bundle, "#7dcfff"),
		components.DataContainerWidth(vp.Width()-3*boxWidth, "Encoding", "Applied policy", format, "#bb9af7"),
	)

	rest := vp.Height() - summaryHeight
	rows := policyDetailRows(rest)

	list := components.PolicyList(vp.Width(), rest-rows*policyDetailHeight, policies, applied, selectedIndex, showStatic, fetchErr)
	parts := []string{summary, list}

	colWidth := vp.Width() / 2
	restWidth := vp.Width() - colWidth

	if rows > 0 {
		active := components.PolicyActiveVersion(colWidth, policyDetailHeight, policies, selectedIndex, applied, fetchErr)
		if !showStatic {
			active = components.PolicyActiveVersion(vp.Width(), policyDetailHeight, policies, selectedIndex, applied, fetchErr)
			parts = append(parts, active)
		} else {
			parts = append(parts, lipgloss.JoinHorizontal(
				lipgloss.Left,
				active,
				components.PolicyVersionHistory(restWidth, policyDetailHeight),
			))
		}
	}

	if rows > 1 {
		parts = append(parts, lipgloss.JoinHorizontal(
			lipgloss.Left,
			components.PolicyActivePolicy(colWidth, policyDetailHeight, applied, visas, fetchErr),
			components.PolicyVersionDiff(restWidth, policyDetailHeight, policies, selectedIndex, applied, fetchErr),
		))
	}

	return lipgloss.JoinVertical(lipgloss.Top, parts...)
}

func policyDetailRows(rest int) int {
	switch {
	case rest < policyTableMinHeight+policyDetailHeight:
		return 0
	case rest < policyTableMinHeight+2*policyDetailHeight:
		return 1
	default:
		return 2
	}
}
