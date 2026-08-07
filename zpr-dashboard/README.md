# ZPR Dashboard TUI Application

This repository contains the Zero-Trust Packet Routing (ZPR) Terminal User Interface application. The dashboard application allows you to manage your ZPR infrastructure quickly through an easy-to-understand and easy-to-use interface.

# Development

To setup your development environment, run `go mod download` to install the local dependencies. Finally, run `make run` to start the TUI.

## Project layout

```
config.toml.example  Endpoint, timeout and credential file paths
cmd/zpr-dashboard/   Program entry point (thin main)
internal/
  app/               Bubble Tea model: Init/Update/View, input handling
  pages/             Top-level tab views (Dashboard, Visas, Actors)
  components/        Reusable panels, tables, charts and their data
  charts/            Braille dot chart and bar chart primitives
  styles/            Color palette and shared lipgloss styles
  config/            Reads config.toml into the environment
  dataplane/         HTTP client for the vs-admin API
```

# Compiling the binary

To compile the final binary, run `make all`. The binaries will be located at bin/zpr-dashboard and bin/zpr-sim.


## Running it

Copy `config.toml.example` to `config.toml` and edit it.


```sh
make run                                # Start admin panel
```

