# zpr-dashboard

This is a TUI (terminal UI) written in go that uses the HTTPS API offered by the visa
service (see ../vs) to display information about the running Visa
Service.

## Architecture Overview

The app is a Bubble Tea (charm.land v2) program using the Elm/MVU pattern:
a single `Model` with `Init`/`Update`/`View`, all mutation driven by messages.

Layers (each package only depends on the ones below it):

- `cmd/zpr-dashboard` — entrypoint: load config, run the tea program.
- `internal/app` — the only stateful layer. `Model.Update` handles input and
  data messages; per-tab UI/data state lives in the `state` struct
  (`state.go`). Each data domain (visas, actors, services, policies,
  revocations, denies) follows the same pattern: a `tick*Msg` on a 5s
  interval schedules a `fetch*Cmd` that runs the HTTP call off the UI thread
  and returns a `*SnapshotMsg{data, err}`.
- `internal/pages` — pure layout functions (one per tab), no state. They take
  the viewport plus data slices and compose components with lipgloss joins.
- `internal/components` — pure render functions returning strings, one file
  per pane. Shared helpers (panels, tables, line clamping) are in `panel.go`.
- `internal/dataplane` — HTTP client for the vs admin API (TLS with pinned
  CA, API key header). `dataplane.Shared()` is the process-wide singleton
  (`sync.OnceValues`). One file per resource; JSON decoding and sorting
  happen here, so panes receive display-ready slices.
- `internal/config`, `internal/styles`, `internal/charts`, `internal/timefmt`
  — leaf utilities (TOML config, lipgloss styles/colors, ASCII charts, time
  formatting).

Conventions:

- Rendering is stateless: pages/components never fetch or mutate; all data
  flows down from `app` as function arguments.
- Sort in the dataplane fetcher (or in `Update` when selection indexes into
  the slice), never at render time.
- On fetch error, keep the last good data and record the error in
  `state.*.fetchErr`; panes render an error note instead of blanking.
- Panels clamp to their width/height budget (`clampLines`,
  `tableRowsThatFit*`) — an overflowing panel breaks the whole layout.
- Not-yet-real features are gated behind `config.ShowStatic()` and labelled
  "(Placeholder)".
- Tests are table-driven `_test.go` files beside the code; components are
  tested by asserting on rendered strings.

## Go Workflow

- Run `make test` after Go changes.
- Check formatting with `test -z "$(gofmt -l .)"`; `gofmt -l .` alone only
  lists unformatted files and does not return a failing exit status.
