package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"neboagency.com/zpr-dashborad/internal/components"
	"neboagency.com/zpr-dashborad/internal/config"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/pages"
	"neboagency.com/zpr-dashborad/internal/styles"

	"charm.land/bubbles/v2/viewport"
)

const (
	tabDashboard = iota
	tabVisas
	tabActors
	tabServices
	tabPolicies
	tabRevocations
)

const dataRefreshInterval = 5 * time.Second
const visaHistoryLimit = 12

type visaTickMsg struct{}

type visaSnapshotMsg struct {
	snapshot dataplane.VisaSnapshot
	err      error
}

func tickVisaRefresh() tea.Cmd {
	return tea.Tick(dataRefreshInterval, func(time.Time) tea.Msg {
		return visaTickMsg{}
	})
}

func fetchVisaSnapshotCmd() tea.Cmd {
	return func() tea.Msg {
		client, err := dataplane.NewDefault()
		if err != nil {
			return visaSnapshotMsg{err: err}
		}

		snapshot, err := client.FetchVisaSnapshot(context.Background())
		return visaSnapshotMsg{snapshot: snapshot, err: err}
	}
}

type serviceTickMsg struct{}

type serviceSnapshotMsg struct {
	services []dataplane.ServiceDescriptor
	err      error
}

func tickServiceRefresh() tea.Cmd {
	return tea.Tick(dataRefreshInterval, func(time.Time) tea.Msg {
		return serviceTickMsg{}
	})
}

func fetchServiceSnapshotCmd() tea.Cmd {
	return func() tea.Msg {
		client, err := dataplane.NewDefault()
		if err != nil {
			return serviceSnapshotMsg{err: err}
		}

		services, err := client.FetchServices(context.Background())
		return serviceSnapshotMsg{services: services, err: err}
	}
}

type policyTickMsg struct{}

type policySnapshotMsg struct {
	policies []dataplane.PolicyBundle
	applied  *dataplane.PolicyBundle
	err      error
}

func tickPolicyRefresh() tea.Cmd {
	return tea.Tick(dataRefreshInterval, func(time.Time) tea.Msg {
		return policyTickMsg{}
	})
}

func fetchPolicySnapshotCmd() tea.Cmd {
	return func() tea.Msg {
		client, err := dataplane.NewDefault()
		if err != nil {
			return policySnapshotMsg{err: err}
		}

		policies, err := client.FetchPolicies(context.Background())

		var applied *dataplane.PolicyBundle
		if current, curErr := client.GetCurrentPolicy(context.Background()); curErr == nil {
			applied = &current
		}

		return policySnapshotMsg{policies: policies, applied: applied, err: err}
	}
}

type revocationTickMsg struct{}

type revocationSnapshotMsg struct {
	revocations []dataplane.AuthRevokeDescriptor
	err         error
}

func tickRevocationRefresh() tea.Cmd {
	return tea.Tick(dataRefreshInterval, func(time.Time) tea.Msg {
		return revocationTickMsg{}
	})
}

func fetchRevocationSnapshotCmd() tea.Cmd {
	return func() tea.Msg {
		client, err := dataplane.NewDefault()
		if err != nil {
			return revocationSnapshotMsg{err: err}
		}

		revocations, err := client.FetchRevocations(context.Background())
		return revocationSnapshotMsg{revocations: revocations, err: err}
	}
}

func appendCapped(history []int, value int, limit int) []int {
	history = append(history, value)
	if len(history) > limit {
		history = history[len(history)-limit:]
	}
	return history
}

// Check if admin server is live
func (m Model) isAdminOnline() bool {
	return m.state.visa.fetchErr == nil &&
		m.state.service.fetchErr == nil &&
		m.state.actor.fetchErr == nil &&
		m.state.policy.fetchErr == nil &&
		m.state.revocation.fetchErr == nil
}

func (m *Model) refreshOnlineSince() {
	if m.isAdminOnline() {
		if m.onlineSince.IsZero() {
			m.onlineSince = time.Now()
		}
	} else {
		m.onlineSince = time.Time{}
	}
}

func (m Model) liveAlerts() []components.Alert {
	return components.KeepUndismissed(components.DeriveAlerts(components.AlertInputs{
		Online:        m.isAdminOnline(),
		AdminErr:      m.adminErr(),
		Actors:        m.state.actor.actors,
		Services:      m.state.service.services,
		Visas:         m.state.visa.recentVisas,
		Revocations:   m.state.revocation.revocations,
		AppliedPolicy: m.state.policy.applied,
	}), m.state.dismissedAlerts)
}

func (m Model) adminErr() error {
	for _, err := range []error{
		m.state.actor.fetchErr,
		m.state.service.fetchErr,
		m.state.visa.fetchErr,
		m.state.policy.fetchErr,
		m.state.revocation.fetchErr,
	} {
		if err != nil {
			return err
		}
	}

	return nil
}

func (m Model) visaCounts() pages.VisaCounts {
	return pages.VisaCounts{
		Active:    m.state.visa.activeCount,
		Requested: m.state.visa.requested,
		Approved:  m.state.visa.approved,
		Denied:    m.state.visa.denied,
	}
}

type actorTickMsg struct{}

type actorSnapshotMsg struct {
	actors  []dataplane.ActorDescriptor
	network []dataplane.NodeConnections
	err     error
}

type actorVisasMsg struct {
	cn    string
	visas []dataplane.VisaDescriptor
	err   error
}

func tickActorRefresh() tea.Cmd {
	return tea.Tick(dataRefreshInterval, func(time.Time) tea.Msg {
		return actorTickMsg{}
	})
}

func fetchActorsSnapshotCmd() tea.Cmd {
	return func() tea.Msg {
		client, err := dataplane.NewDefault()
		if err != nil {
			return actorSnapshotMsg{err: err}
		}

		actors, err := client.FetchActors(context.Background())

		// The topology reads from /admin/network rather than each node's
		// record, which the service only serves for nodes it authenticated.
		network, netErr := client.GetNetwork(context.Background())
		if err == nil {
			err = netErr
		}

		return actorSnapshotMsg{actors: actors, network: network, err: err}
	}
}

func fetchActorVisasCmd(cn string) tea.Cmd {
	return func() tea.Msg {
		client, err := dataplane.NewDefault()
		if err != nil {
			return actorVisasMsg{cn: cn, err: err}
		}

		visas, err := client.FetchActorVisas(context.Background(), cn)
		return actorVisasMsg{cn: cn, visas: visas, err: err}
	}
}

func (m Model) selectedActorCN() (string, bool) {
	idx := m.state.actor.selectedIndex
	if idx < 0 || idx >= len(m.state.actor.actors) {
		return "", false
	}
	return m.state.actor.actors[idx].CName, true
}

type Model struct {
	activeTab     int
	tabs          []string
	width         int
	height        int
	viewport      viewport.Model
	viewportReady bool
	content       string
	state         *state
	onlineSince   time.Time
	showStatic    bool
}

func InitialModel() Model {
	m := Model{
		activeTab:     0,
		tabs:          []string{"Dashboard", "Visas", "Actors", "Services", "Policies", "Revocations"},
		width:         80,
		height:        24,
		viewportReady: false,
		state:         new(state),
		showStatic:    config.ShowStatic(),
	}
	m.state.header.hoverTab = -1

	return m
}

// Run all fetch operations in a batch
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		fetchVisaSnapshotCmd(), tickVisaRefresh(),
		fetchServiceSnapshotCmd(), tickServiceRefresh(),
		fetchActorsSnapshotCmd(), tickActorRefresh(),
		fetchPolicySnapshotCmd(), tickPolicyRefresh(),
		fetchRevocationSnapshotCmd(), tickRevocationRefresh(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.state.policy.rollbackOpen {
			switch msg.String() {
			case "y", "enter", "n", "esc", "ctrl+c", "q":
				m.state.policy.rollbackOpen = false
			}

			return m, nil
		}

		if m.state.actor.revokeOpen {
			switch msg.String() {
			case " ":
				m.state.actor.revokeVisas = !m.state.actor.revokeVisas
			case "y", "enter", "n", "esc", "ctrl+c", "q":
				m.state.actor.revokeOpen = false
			}

			return m, nil
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab", "l", "right":
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
			m.state.header.hoverTab = -1
			m.viewport.SetContent(m.Content())
			return m, nil
		case "shift+tab", "h", "left":
			m.activeTab = (m.activeTab - 1 + len(m.tabs)) % len(m.tabs)
			m.state.header.hoverTab = -1
			m.viewport.SetContent(m.Content())
			return m, nil
		case "c":
			if m.activeTab == tabDashboard {
				if m.state.dismissedAlerts == nil {
					m.state.dismissedAlerts = map[string]bool{}
				}

				for _, key := range components.AlertKeys(m.liveAlerts()) {
					m.state.dismissedAlerts[key] = true
				}

				m.viewport.SetContent(m.Content())
				return m, nil
			}
		case "r":
			if !m.showStatic {
				break
			}

			if m.activeTab == tabPolicies && len(m.state.policy.policies) > 0 {
				m.state.policy.rollbackOpen = true
				return m, nil
			}

			if m.activeTab == tabActors && len(m.state.actor.actors) > 0 {
				m.state.actor.revokeOpen = true
				m.state.actor.revokeVisas = false
				return m, nil
			}
		case "v":
			if m.activeTab == tabVisas {
				m.state.visa.view = m.state.visa.view.Toggled()
				m.viewport.SetContent(m.Content())
				return m, nil
			}
		case "up":
			if m.activeTab == tabVisas && m.state.visa.selectedIndex > 0 {
				m.state.visa.selectedIndex -= 1
				m.viewport.SetContent(m.Content())
				return m, nil
			}

			if m.activeTab == tabPolicies && m.state.policy.selectedIndex > 0 {
				m.state.policy.selectedIndex -= 1
				m.viewport.SetContent(m.Content())
				return m, nil
			}

			if m.activeTab == tabServices && m.state.service.selectedIndex > 0 {
				m.state.service.selectedIndex -= 1
				m.viewport.SetContent(m.Content())
				return m, nil
			}

			if m.activeTab == tabActors && m.state.actor.selectedIndex > 0 {
				m.state.actor.selectedIndex -= 1
				m.state.actor.visas = nil
				m.state.actor.visaCountHistory = nil
				m.viewport.SetContent(m.Content())
				if cn, ok := m.selectedActorCN(); ok {
					return m, fetchActorVisasCmd(cn)
				}
				return m, nil
			}
		case "down":
			if m.activeTab == tabVisas && m.state.visa.selectedIndex < len(m.state.visa.recentVisas)-1 {
				m.state.visa.selectedIndex += 1
				m.viewport.SetContent(m.Content())
				return m, nil
			}

			if m.activeTab == tabPolicies && m.state.policy.selectedIndex < len(m.state.policy.policies)-1 {
				m.state.policy.selectedIndex += 1
				m.viewport.SetContent(m.Content())
				return m, nil
			}

			if m.activeTab == tabServices && m.state.service.selectedIndex < len(m.state.service.services)-1 {
				m.state.service.selectedIndex += 1
				m.viewport.SetContent(m.Content())
				return m, nil
			}

			if m.activeTab == tabActors && m.state.actor.selectedIndex < len(m.state.actor.actors)-1 {
				m.state.actor.selectedIndex += 1
				m.state.actor.visas = nil
				m.state.actor.visaCountHistory = nil
				m.viewport.SetContent(m.Content())
				if cn, ok := m.selectedActorCN(); ok {
					return m, fetchActorVisasCmd(cn)
				}
				return m, nil
			}
		}

	case visaTickMsg:
		return m, tea.Batch(fetchVisaSnapshotCmd(), tickVisaRefresh())

	case visaSnapshotMsg:
		m.state.visa.fetchErr = msg.err
		m.refreshOnlineSince()
		if msg.err == nil {
			m.state.visa.activeCount = msg.snapshot.ActiveCount
			m.state.visa.revokedCount = msg.snapshot.RevokedCount
			m.state.visa.recentVisas = msg.snapshot.RecentVisas
			m.state.visa.uptime = msg.snapshot.Uptime
			m.state.visa.requested = msg.snapshot.Requested
			m.state.visa.approved = msg.snapshot.Approved
			m.state.visa.denied = msg.snapshot.Denied
			if m.state.visa.selectedIndex >= len(m.state.visa.recentVisas) {
				m.state.visa.selectedIndex = max(0, len(m.state.visa.recentVisas)-1)
			}
			m.state.visa.activeHistory = appendCapped(m.state.visa.activeHistory, msg.snapshot.ActiveCount, visaHistoryLimit)
			m.state.visa.revokedHistory = appendCapped(m.state.visa.revokedHistory, msg.snapshot.RevokedCount, visaHistoryLimit)
		}
		if m.viewportReady {
			m.viewport.SetContent(m.Content())
		}
		return m, nil

	case serviceTickMsg:
		return m, tea.Batch(fetchServiceSnapshotCmd(), tickServiceRefresh())

	case serviceSnapshotMsg:
		m.state.service.fetchErr = msg.err
		m.refreshOnlineSince()
		if msg.err == nil {
			m.state.service.services = msg.services
			if m.state.service.selectedIndex >= len(m.state.service.services) {
				m.state.service.selectedIndex = max(0, len(m.state.service.services)-1)
			}
		}
		if m.viewportReady {
			m.viewport.SetContent(m.Content())
		}
		return m, nil

	case actorTickMsg:
		return m, tea.Batch(fetchActorsSnapshotCmd(), tickActorRefresh())

	case actorSnapshotMsg:
		m.state.actor.fetchErr = msg.err
		m.refreshOnlineSince()
		var visasCmd tea.Cmd
		if msg.err == nil {
			m.state.actor.actors = msg.actors
			m.state.actor.network = msg.network
			if m.state.actor.selectedIndex >= len(m.state.actor.actors) {
				m.state.actor.selectedIndex = max(0, len(m.state.actor.actors)-1)
			}
			if cn, ok := m.selectedActorCN(); ok {
				visasCmd = fetchActorVisasCmd(cn)
			}
		}
		if m.viewportReady {
			m.viewport.SetContent(m.Content())
		}
		return m, visasCmd

	case actorVisasMsg:
		if cn, ok := m.selectedActorCN(); ok && cn == msg.cn {
			m.state.actor.visasFetchErr = msg.err
			if msg.err == nil {
				m.state.actor.visas = msg.visas
				m.state.actor.visaCountHistory = appendCapped(m.state.actor.visaCountHistory, len(msg.visas), visaHistoryLimit)
			}
			if m.viewportReady {
				m.viewport.SetContent(m.Content())
			}
		}
		return m, nil

	case policyTickMsg:
		return m, tea.Batch(fetchPolicySnapshotCmd(), tickPolicyRefresh())

	case policySnapshotMsg:
		m.state.policy.fetchErr = msg.err
		m.refreshOnlineSince()
		if msg.err == nil {
			m.state.policy.policies = msg.policies
			m.state.policy.applied = msg.applied
			if m.state.policy.selectedIndex >= len(m.state.policy.policies) {
				m.state.policy.selectedIndex = max(0, len(m.state.policy.policies)-1)
			}
		}
		if m.viewportReady {
			m.viewport.SetContent(m.Content())
		}
		return m, nil

	case revocationTickMsg:
		return m, tea.Batch(fetchRevocationSnapshotCmd(), tickRevocationRefresh())

	case revocationSnapshotMsg:
		m.state.revocation.fetchErr = msg.err
		m.refreshOnlineSince()
		if msg.err == nil {
			m.state.revocation.revocations = msg.revocations
		}
		if m.viewportReady {
			m.viewport.SetContent(m.Content())
		}
		return m, nil

	case tea.MouseMsg:
		return m.handleCursor(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Setup Viewport
		if !m.viewportReady {
			m.viewport = viewport.New(viewport.WithWidth(m.width), viewport.WithHeight(m.height-3))
			m.viewport.SetContent(m.Content())
			m.viewport.KeyMap = viewport.DefaultKeyMap()
			m.viewportReady = true
		} else {
			m.viewport.SetWidth(m.width)
			m.viewport.SetHeight(m.height - 3)
			m.viewport.SetContent(m.Content())
		}

		return m, nil
	}

	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m Model) Header() string {
	title := styles.HeaderStyle.Render("ZPR Dashboard")
	header := m.renderTabs()

	return lipgloss.JoinVertical(
		lipgloss.Top,
		lipgloss.JoinHorizontal(lipgloss.Left, title, header),
	)
}

func (m Model) uptime() time.Duration {
	if m.state.visa.uptime > 0 {
		return m.state.visa.uptime
	}

	if m.onlineSince.IsZero() {
		return 0
	}

	return time.Since(m.onlineSince)
}

func (m Model) Content() string {
	var content string

	switch m.activeTab {
	case tabDashboard:
		content = pages.HomePage(
			m.viewport,
			len(m.state.revocation.revocations),
			len(m.state.actor.actors),
			m.state.visa.requested,
			m.isAdminOnline(),
			m.uptime(),
			m.state.service.services,
			m.state.actor.actors,
			m.state.actor.network,
			m.state.visa.revokedHistory,
			m.liveAlerts(),
			m.state.service.fetchErr,
			m.showStatic,
		)
	case tabVisas:
		content = pages.VisaTab(
			m.viewport,
			m.state.visa.view,
			m.visaCounts(),
			m.state.visa.activeHistory,
			m.state.visa.revokedHistory,
			m.state.visa.recentVisas,
			m.state.actor.actors,
			m.state.visa.selectedIndex,
			m.state.visa.fetchErr,
			m.showStatic,
		)
	case tabActors:
		content = pages.ActorsPage(
			m.viewport,
			m.state.actor.actors,
			m.state.actor.selectedIndex,
			m.state.actor.fetchErr,
			m.state.actor.visas,
			m.state.actor.visasFetchErr,
			m.state.actor.visaCountHistory,
			m.state.service.services,
			m.state.service.fetchErr,
			m.showStatic,
		)
	case tabServices:
		content = pages.ServicesPage(
			m.viewport,
			m.state.service.services,
			m.state.service.selectedIndex,
			m.state.service.fetchErr,
			m.state.actor.actors,
			m.state.actor.fetchErr,
			m.state.visa.recentVisas,
			m.state.visa.fetchErr,
			m.showStatic,
		)
	case tabPolicies:
		content = pages.PoliciesPage(
			m.viewport,
			m.state.policy.policies,
			m.state.policy.selectedIndex,
			m.state.policy.applied,
			m.state.visa.recentVisas,
			m.state.policy.fetchErr,
			m.showStatic,
		)
	case tabRevocations:
		content = pages.RevocationsPage(
			m.viewport,
			m.state.revocation.revocations,
			m.state.revocation.fetchErr,
			m.state.actor.actors,
			m.state.visa.revokedHistory,
			dataRefreshInterval,
			m.showStatic,
		)
	}

	return content
}

func (m Model) View() tea.View {
	var v tea.View

	if !m.viewportReady {
		v.SetContent("Initializing...")
		return v
	}

	v.AltScreen = true
	v.MouseMode = tea.MouseModeAllMotion

	// Modal dialogue
	if m.state.policy.rollbackOpen {
		v.SetContent(components.PolicyRollbackModal(
			m.width, m.height,
			m.state.policy.policies[min(m.state.policy.selectedIndex, len(m.state.policy.policies)-1)],
			m.state.policy.applied,
		))

		return v
	}

	if m.state.actor.revokeOpen {
		v.SetContent(components.ActorRevokeModal(
			m.width, m.height,
			m.state.actor.actors[min(m.state.actor.selectedIndex, len(m.state.actor.actors)-1)],
			m.state.actor.visas,
			m.state.actor.revokeVisas,
		))

		return v
	}

	doc := strings.Builder{}
	doc.WriteString(styles.HeaderWrapper.Render(m.Header()) + "\n")
	doc.WriteString(m.viewport.View())

	doc.WriteString("\n" + m.renderHelpBar() + "\n")

	v.SetContent(doc.String())

	return v
}

type helpEntry struct {
	key  string
	desc string
}

// helpEntries lists the bindings that do something on the current tab.
func (m Model) helpEntries() []helpEntry {
	entries := []helpEntry{
		{"q", "quit"},
		{"←/→", "switch tab"},
	}

	switch m.activeTab {
	case tabDashboard:
		if len(m.liveAlerts()) > 0 {
			entries = append(entries, helpEntry{"c", "clear alerts"})
		}
	case tabVisas:
		entries = append(entries, helpEntry{"v", "toggle view"})
		if m.state.visa.view == components.VisaViewActive {
			entries = append(entries, helpEntry{"↑/↓", "select visa"})
		}
	case tabActors:
		entries = append(entries, helpEntry{"↑/↓", "select actor"})
		if m.showStatic {
			entries = append(entries, helpEntry{"r", "revoke"})
		}
	case tabServices:
		entries = append(entries, helpEntry{"↑/↓", "select service"})
	case tabPolicies:
		entries = append(entries, helpEntry{"↑/↓", "select policy"})
		if m.showStatic {
			entries = append(entries, helpEntry{"r", "rollback"})
		}
	}

	return append(entries, helpEntry{"pgup/pgdn", "scroll"})
}

func (m Model) renderHelpBar() string {
	keyStyle := lipgloss.NewStyle().Foreground(styles.ColorBlue).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(styles.ColorDimmed)
	separator := descStyle.Render(" | ")

	var blocks []string
	for _, entry := range m.helpEntries() {
		blocks = append(blocks, keyStyle.Render(entry.key)+" "+descStyle.Render(entry.desc))
	}

	bar := " " + strings.Join(blocks, separator)
	for len(blocks) > 1 && lipgloss.Width(bar) > m.width {
		blocks = blocks[:len(blocks)-1]
		bar = " " + strings.Join(blocks, separator)
	}

	percent := descStyle.Render(fmt.Sprintf("%3.f%% ", m.viewport.ScrollPercent()*100))
	gap := m.width - lipgloss.Width(bar) - lipgloss.Width(percent)
	if gap < 1 {
		return bar
	}

	return bar + strings.Repeat(" ", gap) + percent
}

func (m Model) renderTabs() string {
	var tabs []string
	var tabsSize = 0

	m.state.header.tabRect = make([]int, len(m.tabs))

	for i, t := range m.tabs {
		if i == m.activeTab {
			tabs = append(tabs, styles.ActiveTab.Render(t))
		} else if i == m.state.header.hoverTab {
			tabs = append(tabs, styles.HoverTab.Render(t))
		} else {
			tabs = append(tabs, styles.InactiveTab.Render(t))
		}

		m.state.header.tabRect[i] = tabsSize + len(t) + 4
		tabsSize += len(t) + 4
	}

	// Start counting from the right
	m.state.header.tabStart = m.width - tabsSize

	return styles.TabsWrapper.Width(m.width - 20).Render(lipgloss.JoinHorizontal(lipgloss.Right, tabs...))
}
