# ZPR Dashboard TUI Application

This repository contains the Zero-Trust Packet Routing (ZPR) Terminal User Interface application. The dashboard application allows you to manage your ZPR infrastructure quickly through an easy-to-understand and easy-to-use interface.

# Development

To setup your development environment, run `go mod download` to install the local dependencies. Finally, run `make run` to start the TUI.

## Project layout

```
config.toml          Endpoint, timeout and credential file paths
cmd/zpr-dashboard/   Program entry point (thin main)
cmd/zpr-sim/         Fills a visa service with seed data
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

# Simulating a visa service

The dashboard reads a live service, and a freshly started one has nothing in it.
`cmd/zpr-sim` fills it, so the panels show data that came from a real service
rather than from the placeholder ones.

```sh
make sim          # build it as bin/zpr-sim
bin/zpr-sim       # the commands
```

## Running it

```sh
make seed                               # If seeding
vs <policy.bin2> --config config.toml   # Start VS server
make status                             # Confirm connectivity
make simulate                           # Start fake traffic and calls
make run                                # Start admin panel
```

The seed writes to ValKey at `127.0.0.1:6379`, which `ZPR_DB_ADDR` overrides. The
rest reads `ZPR_BASE_URL` and `ZPR_KEY_FILE`, which `config.toml` sets.

## What the seed puts on each tab

| Dashboard | Comes from |
| --- | --- |
| Actors — roster | the seeded `actor:*` records |
| Services — name, actor | `service:<name>` and the actors that register them |
| Dashboard — topology | `GET /admin/network`, built from `topology:edges` |
| Policies — format, size, applied | whatever policy the service was started with |
| Visas | nothing: see below |
