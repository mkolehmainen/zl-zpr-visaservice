package app

import tea "charm.land/bubbletea/v2"

func (m Model) handleCursor(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	m.state.header.hoverTab = -1

	mouse := msg.Mouse()
	x := mouse.X
	y := mouse.Y

	// Header tab hover
	if y == 0 {
		for i, rect := range m.state.header.tabRect {
			if x >= m.state.header.tabStart && x <= m.state.header.tabStart+rect {
				if mouse.Button == tea.MouseLeft {
					m.activeTab = i
					m.viewport.SetContent(m.Content())
					break
				}

				m.state.header.hoverTab = i
				break
			}
		}
	}

	return m, nil
}
