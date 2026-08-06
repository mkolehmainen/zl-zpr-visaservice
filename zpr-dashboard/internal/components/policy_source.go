package components

import (
	"fmt"
	"image/color"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
)

func PolicyActivePolicy(width, height int, applied *dataplane.PolicyBundle, visas []dataplane.VisaDescriptor, fetchErr error) string {
	const title = "Active Policy"

	subtitle := "Rules granting the visas in force"
	if applied != nil {
		subtitle = fmt.Sprintf("config %d · %s", applied.ConfigID, orDash(applied.Version))
	}

	if fetchErr != nil && len(visas) == 0 {
		return detailPanel(width, height, title, subtitle, panelError(fetchErr))
	}

	rules := policyRules(visas)
	if len(rules) == 0 {
		return detailPanel(width, height, title, subtitle,
			panelNote(ansi.Truncate("No rules in force", max(4, width-4), "...")))
	}

	codeWidth := max(8, width-10)

	var body string
	for i, rule := range rules {
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("%3d ", i+1)) +
			highlightZPL(ansi.Truncate(rule, codeWidth, "..."))
	}

	return detailPanel(width, height, title, subtitle, body)
}

// Stop reshuffling on each request
func policyRules(visas []dataplane.VisaDescriptor) []string {
	seen := make(map[string]bool, len(visas))
	var rules []string

	for _, visa := range visas {
		rule := strings.TrimSpace(visa.ZPL)
		if rule == "" || seen[rule] {
			continue
		}

		seen[rule] = true
		rules = append(rules, rule)
	}

	sort.Strings(rules)

	return rules
}

// Coloring keywords (cannot be in the name)
var zplKeywords = map[string]color.Color{
	"allow":  styles.ColorGreen,
	"never":  styles.ColorRed,
	"deny":   styles.ColorRed,
	"define": styles.ColorBlue,
	"to":     styles.ColorBlue,
	"access": styles.ColorBlue,
	"on":     styles.ColorBlue,
	"as":     styles.ColorBlue,
	"a":      styles.ColorBlue,
	"an":     styles.ColorBlue,
	"and":    styles.ColorBlue,
	"signal": styles.ColorBlue,
	"with":   styles.ColorBlue,
}

func highlightZPL(line string) string {
	if strings.HasPrefix(strings.TrimLeft(line, " "), "#") {
		return styles.SubtitleStyle.Render(line)
	}

	indent := len(line) - len(strings.TrimLeft(line, " "))

	var out strings.Builder
	out.WriteString(line[:indent])

	for i, token := range strings.Split(line[indent:], " ") {
		if i > 0 {
			out.WriteByte(' ')
		}

		out.WriteString(highlightZPLToken(token))
	}

	return out.String()
}

func highlightZPLToken(token string) string {
	suffix := ""
	if len(token) > 1 && strings.HasSuffix(token, ".") {
		suffix = styles.SubtitleStyle.Render(".")
		token = strings.TrimSuffix(token, ".")
	}

	if token == "" {
		return suffix
	}

	if strings.HasPrefix(token, "'") || strings.HasPrefix(token, "\"") {
		return lipgloss.NewStyle().Foreground(styles.ColorGreen).Render(token) + suffix
	}

	if keyword, ok := zplKeywords[strings.ToLower(token)]; ok {
		return lipgloss.NewStyle().Foreground(keyword).Bold(true).Render(token) + suffix
	}

	if key, value, found := strings.Cut(token, ":"); found {
		out := lipgloss.NewStyle().Foreground(styles.ColorFg).Render(key) + styles.SubtitleStyle.Render(":")
		if value != "" {
			out += lipgloss.NewStyle().Foreground(styles.ColorGreen).Render(value)
		}

		return out + suffix
	}

	return lipgloss.NewStyle().Foreground(styles.ColorFg).Render(token) + suffix
}
