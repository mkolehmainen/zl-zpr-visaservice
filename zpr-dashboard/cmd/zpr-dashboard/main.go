package main

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"

	"neboagency.com/zpr-dashborad/internal/app"
	"neboagency.com/zpr-dashborad/internal/config"
)

func main() {
	// Read config
	if err := config.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("\033[H\033[2J")

	p := tea.NewProgram(app.InitialModel())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
