//use colored::Colorize;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{
        Block, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
        TableState,
    },
};
use reqwest::tls::Certificate;

use chrono::{DateTime, SecondsFormat, Utc};
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use admin_api_types::{ActorDescriptor, ServiceDescriptor, VisaDescriptor};

use crate::vsclient::{RoleFilter, VsClient};

mod details;
mod format;
mod text;
mod widgets;

use details::{actor_detail_text, service_detail_text, visa_detail_text};
use format::fmt_uptime;
use widgets::{
    SPARK_MAX, SPARK_MIN, clamp_scroll, clamp_state, detail_line, move_selection, pane_block,
    sparkline,
};

/// Do not hit the VS ADMIN api more than this often.
const REFRESH_RATE: Duration = Duration::from_millis(2000);

/// Which content pane is currently selected for keyboard interaction.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Pane {
    Actors,
    Services,
    Visas,
    Details,
}

#[derive(Debug)]
struct Gui {
    exit: bool,
    err_msg: Option<String>,
    last_updated: Option<Instant>,
    vs_cli: VsClient,
    actors: Vec<ActorDescriptor>,
    services: Vec<ServiceDescriptor>,
    visas: Vec<VisaDescriptor>,
    selected: Pane,
    detail_source: Pane,
    detail_scroll: u16, // top line offset of the Details pane
    actor_state: TableState,
    service_state: TableState,
    visa_state: TableState,
    table_header_style: Style,
    zpr_addr_style: Style,
    cn_style: Style,
    visa_id_style: Style,
    uptime_secs: u64,
    approved_hist: VecDeque<u64>,
    denied_hist: VecDeque<u64>,
    last_approved: u64,
    last_denied: u64,
}

/// Fire up the terminal based gui which is just a simple dashboard.
/// Returns on terrible error or if user exits.
pub fn enter_gui(
    api_url: &str,
    cert: Certificate,
    api_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal = ratatui::init();
    let mut g = Gui::new(api_url, cert, api_key);
    let result = g.run(&mut terminal);
    ratatui::restore();
    result
}

impl Gui {
    fn new(api_url: &str, cert: Certificate, api_key: String) -> Self {
        Self {
            exit: false,
            err_msg: None,
            vs_cli: VsClient::new(api_url.to_string(), cert, api_key, true),
            actors: Vec::new(),
            services: Vec::new(),
            visas: Vec::new(),
            selected: Pane::Actors,
            detail_source: Pane::Actors,
            detail_scroll: 0,
            actor_state: TableState::default().with_selected(Some(0)),
            service_state: TableState::default().with_selected(Some(0)),
            visa_state: TableState::default().with_selected(Some(0)),
            last_updated: None,
            table_header_style: Style::default().fg(Color::LightGreen).bg(Color::Black),
            zpr_addr_style: Color::Yellow.into(),
            cn_style: Color::White.into(),
            visa_id_style: Color::White.into(),
            uptime_secs: 0,
            // Pre-fill so sparklines render full-width immediately, new samples
            // pushing in from the right.
            approved_hist: VecDeque::from(vec![0u64; SPARK_MAX]),
            denied_hist: VecDeque::from(vec![0u64; SPARK_MAX]),
            last_approved: 0,
            last_denied: 0,
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<(), Box<dyn std::error::Error>> {
        while !self.exit {
            terminal.draw(|f| self.draw(f))?;
            self.handle_events()?;
            match self.refresh_state() {
                Ok(_) => {}
                Err(e) => {
                    self.err_msg = Some(e.to_string());
                }
            }
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame) {
        self.render_gui(frame, frame.area());
    }

    fn handle_events(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => self.exit = true,
                    KeyCode::Char('a') => {
                        self.selected = Pane::Actors;
                        self.detail_source = Pane::Actors;
                        self.detail_scroll = 0;
                    }
                    KeyCode::Char('s') => {
                        self.selected = Pane::Services;
                        self.detail_source = Pane::Services;
                        self.detail_scroll = 0;
                    }
                    KeyCode::Char('v') => {
                        self.selected = Pane::Visas;
                        self.detail_source = Pane::Visas;
                        self.detail_scroll = 0;
                    }
                    KeyCode::Char('d') => self.selected = Pane::Details,
                    KeyCode::Tab => {
                        // Cycle Actors -> Services -> Visas -> Details -> Actors.
                        self.selected = match self.selected {
                            Pane::Actors => Pane::Services,
                            Pane::Services => Pane::Visas,
                            Pane::Visas => Pane::Details,
                            Pane::Details => Pane::Actors,
                        };
                        if self.selected != Pane::Details {
                            self.detail_source = self.selected;
                            self.detail_scroll = 0;
                        }
                    }
                    KeyCode::Up | KeyCode::Down => {
                        let down = key.code == KeyCode::Down;
                        if self.selected == Pane::Details {
                            // Scroll one line; bottom clamp is applied in render
                            // against the real content/viewport heights.
                            self.detail_scroll = if down {
                                self.detail_scroll.saturating_add(1)
                            } else {
                                self.detail_scroll.saturating_sub(1)
                            };
                        } else {
                            let (state, len) = match self.selected {
                                Pane::Actors => (&mut self.actor_state, self.actors.len()),
                                Pane::Services => (&mut self.service_state, self.services.len()),
                                Pane::Visas => (&mut self.visa_state, self.visas.len()),
                                Pane::Details => unreachable!(),
                            };
                            state.select(move_selection(state.selected(), len, down));
                            self.detail_scroll = 0; // row changed → reset Details scroll
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Call the VS-API to get data.
    fn refresh_state(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.last_updated.is_some() && self.last_updated.unwrap().elapsed() < REFRESH_RATE {
            return Ok(());
        }
        self.last_updated = Some(Instant::now()); // set first here in case we error out.
        self.err_msg = None;

        {
            let actor_cns = self.vs_cli.get_actors(RoleFilter::All)?;
            self.actors.clear();
            for entry in &actor_cns {
                match self.vs_cli.get_actor(&entry.cn) {
                    Ok(a) => {
                        self.actors.push(a);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.actors.sort(); // uses Ord trait
            clamp_state(&mut self.actor_state, self.actors.len());
        }
        self.last_updated = Some(Instant::now());

        {
            let service_ids = self.vs_cli.get_services()?;
            self.services.clear();
            for entry in &service_ids {
                match self.vs_cli.get_service(&entry.id) {
                    Ok(s) => {
                        self.services.push(s);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.services.sort(); // uses Ord trait
            clamp_state(&mut self.service_state, self.services.len());
        }

        {
            let visa_ids = self.vs_cli.get_visas()?;
            self.visas.clear();
            for entry in &visa_ids {
                match self.vs_cli.get_visa(entry.id) {
                    Ok(v) => {
                        self.visas.push(v);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.visas.sort(); // uses Ord trait
            self.visas.reverse();
            clamp_state(&mut self.visa_state, self.visas.len());
        }

        // Sample counters/uptime; non-fatal so a stats error never blanks the screen.
        if let Ok(stats) = self.vs_cli.get_stats() {
            let get = |k: &str| {
                stats
                    .stats
                    .get(k)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            self.uptime_secs = get("uptime");

            let approved = get("visa_requests_approved");
            self.approved_hist
                .push_back(approved.saturating_sub(self.last_approved));
            while self.approved_hist.len() > SPARK_MAX {
                self.approved_hist.pop_front();
            }
            self.last_approved = approved;

            let denied = get("visa_requests_denied");
            self.denied_hist
                .push_back(denied.saturating_sub(self.last_denied));
            while self.denied_hist.len() > SPARK_MAX {
                self.denied_hist.pop_front();
            }
            self.last_denied = denied;
        }

        self.last_updated = Some(Instant::now());
        Ok(())
    }

    /// Compose the header as three independently-aligned lines — title (left),
    /// counts (centered), uptime (right) — degrading to fit `width`: full →
    /// shrink sparklines (16→8 bars) → drop sparklines → drop counts → title only.
    fn build_header(&self, width: usize) -> (Line<'static>, Line<'static>, Line<'static>) {
        let title = Line::from("  ZPR Visa Service".bold());
        let uptime = Line::from(vec![
            "UPTIME ".cyan(),
            fmt_uptime(self.uptime_secs).cyan().bold(),
            " ".into(),
        ]);
        let approved = self.last_approved;
        let denied = self.last_denied;
        let a_hist: Vec<u64> = self.approved_hist.iter().copied().collect();
        let d_hist: Vec<u64> = self.denied_hist.iter().copied().collect();

        // One widget: `[LABEL:SPARKLINE:VALUE]` (value bold), colon+spark omitted
        // when `spark_n == 0`.
        let block = |label: &str, hist: &[u64], spark_n: usize, value: u64, color: Color| {
            let plain = Style::default().fg(color);
            let mut spans = vec![Span::styled(format!("[{label}:"), plain)];
            if spark_n > 0 {
                let s = &hist[hist.len().saturating_sub(spark_n)..];
                spans.push(Span::styled(sparkline(s), plain));
                spans.push(Span::styled(":", plain));
            }
            spans.push(Span::styled(format!("{value}"), plain.bold()));
            spans.push(Span::styled("]", plain));
            spans
        };

        // Centered counts: the two widgets side by side, `spark_n` bars each.
        let counts = |spark_n: usize| -> Line<'static> {
            let mut spans = block("APPROVED", &a_hist, spark_n, approved, Color::Green);
            spans.push(Span::raw(" "));
            spans.extend(block("DENIED", &d_hist, spark_n, denied, Color::Red));
            Line::from(spans)
        };

        // The centered block must clear the wider of title/uptime on both sides
        // (+2 for a visual gap), else it overlaps the pegged ends.
        let side = title.width().max(uptime.width());
        let avail = width.saturating_sub(2 * side + 2);

        // Widest → narrowest; first sparkline width that fits shows all three.
        for n in (SPARK_MIN..=SPARK_MAX).rev() {
            let c = counts(n);
            if c.width() <= avail {
                return (title, c, uptime);
            }
        }
        let c = counts(0); // no sparklines
        if c.width() <= avail {
            return (title, c, uptime);
        }
        if title.width() + uptime.width() <= width {
            return (title, Line::default(), uptime); // drop counts
        }
        (title, Line::default(), Line::default()) // title only
    }

    fn render_gui(&mut self, frame: &mut Frame, area: Rect) {
        let instructions = Line::from(vec![
            " a/s/v/d".blue().bold(),
            " select · ".into(),
            "↑/↓".blue().bold(),
            " move · ".into(),
            "q".blue().bold(),
            " quit ".into(),
        ]);

        let [header_area, content_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        let (title, counts, uptime) = self.build_header(header_area.width as usize);
        frame.render_widget(
            Paragraph::new(Text::from(title)).left_aligned(),
            header_area,
        );
        frame.render_widget(Paragraph::new(Text::from(counts)).centered(), header_area);
        frame.render_widget(
            Paragraph::new(Text::from(uptime)).right_aligned(),
            header_area,
        );
        frame.render_widget(
            Paragraph::new(Text::from(instructions)).centered(),
            footer_area,
        );

        if let Some(err) = &self.err_msg {
            frame.render_widget(
                Paragraph::new(Text::from(err.to_string().red())).block(Block::default()),
                content_area,
            );
            return;
        }

        // Else proceed with our layout.
        let [top, visa_area, detail_area] = Layout::vertical([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .areas(content_area);

        let [actor_area, service_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);

        self.render_actors(frame, actor_area);
        self.render_services(frame, service_area);
        self.render_visas(frame, visa_area);
        self.render_details(frame, detail_area);
    }

    fn render_services(&mut self, frame: &mut Frame, area: Rect) {
        let is_selected = self.selected == Pane::Services;
        if self.services.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No services found.").red()).block(pane_block(
                    "S",
                    "ervices ",
                    is_selected,
                )),
                area,
            );
            return;
        }
        let header = ["Service Name", "CN", "ZPR Address", ""]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(self.table_header_style)
            .height(1);
        let mut row_max_lens = (0u16, 0u16, 0u16); // (SERVICE_NAME, CN, ZPR_ADDR)
        for srec in &self.services {
            if row_max_lens.0 < srec.service_name.len() as u16 {
                row_max_lens.0 = srec.service_name.len() as u16;
            }
            if row_max_lens.1 < srec.actor_cn.len() as u16 {
                row_max_lens.1 = srec.actor_cn.len() as u16;
            }
            if row_max_lens.2 < srec.zpr_addr.len() as u16 {
                row_max_lens.2 = srec.zpr_addr.len() as u16;
            }
        }

        let rows = self.services.iter().map(|srec| {
            let cn = srec.actor_cn.clone();
            let zpr_addr = srec.zpr_addr.clone();
            let flag = "".to_string(); // Used to put "[node]" here
            let cells = [
                Cell::from(srec.service_name.clone()),
                Cell::from(cn).style(self.cn_style),
                Cell::from(zpr_addr).style(self.zpr_addr_style),
                Cell::from(flag),
            ];
            Row::new(cells)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(row_max_lens.0 + 3),
                Constraint::Length(row_max_lens.1 + 3),
                Constraint::Length(row_max_lens.2 + 3),
                Constraint::Length(6), // flag
            ],
        )
        .header(header)
        .block(pane_block("S", "ervices ", is_selected));
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.service_state);
            self.render_list_scrollbar(
                frame,
                area,
                self.services.len(),
                self.service_state.offset(),
            );
        } else {
            frame.render_widget(table, area);
        }
    }

    // Overlay a scrollbar on a list pane when its rows overflow the visible area.
    fn render_list_scrollbar(&self, frame: &mut Frame, area: Rect, rows: usize, offset: usize) {
        let viewport = area.height.saturating_sub(3) as usize; // borders (2) + header row (1)
        if rows <= viewport {
            return; // everything fits — no indicator
        }
        let max = rows - viewport;
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(if offset > 0 { Some("▲") } else { None })
                .end_symbol(if offset < max { Some("▼") } else { None }),
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut ScrollbarState::new(rows).position(offset),
        );
    }

    fn render_actors(&mut self, frame: &mut Frame, area: Rect) {
        let is_selected = self.selected == Pane::Actors;
        if self.actors.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No actors found.").red()).block(pane_block(
                    "A",
                    "ctors ",
                    is_selected,
                )),
                area,
            );
            return;
        }
        let header = ["CN", "ZPR Address", "Join Date", ""]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(self.table_header_style)
            .height(1);
        let mut row_max_lens = (0u16, 0u16); // (CN, ZPR_ADDR)
        for actor in &self.actors {
            if row_max_lens.0 < actor.cn.len() as u16 {
                row_max_lens.0 = actor.cn.len() as u16;
            }
            if row_max_lens.1 < actor.zpr_addr.len() as u16 {
                row_max_lens.1 = actor.zpr_addr.len() as u16;
            }
        }
        let rows = self.actors.iter().map(|actor| {
            let cn = actor.cn.clone();
            let zpr_addr = actor.zpr_addr.clone();
            let ts: DateTime<Utc> = actor.ctime.into();
            let join_date = ts.to_rfc3339_opts(SecondsFormat::Secs, true);
            let flag = if actor.node {
                "[node]".light_magenta()
            } else {
                "".into()
            };
            let cells = [
                Cell::from(cn).style(self.cn_style),
                Cell::from(zpr_addr).style(self.zpr_addr_style),
                Cell::from(join_date),
                Cell::from(flag),
            ];
            Row::new(cells)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(row_max_lens.0 + 3),
                Constraint::Length(row_max_lens.1 + 3),
                Constraint::Length(20), // join date
                Constraint::Length(6),  // flag
            ],
        )
        .header(header)
        .block(pane_block("A", "ctors ", is_selected));
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.actor_state);
            self.render_list_scrollbar(frame, area, self.actors.len(), self.actor_state.offset());
        } else {
            frame.render_widget(table, area);
        }
    }

    fn render_visas(&mut self, frame: &mut Frame, area: Rect) {
        let is_selected = self.selected == Pane::Visas;
        if self.visas.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No visas found.").red()).block(pane_block(
                    "V",
                    "isas ",
                    is_selected,
                )),
                area,
            );
            return;
        }
        let header = ["ID", "Source", "", "Dest", "Expires"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(self.table_header_style)
            .height(1);

        // Max column lengths does not include our "->" col.
        let mut row_max_lens = (0u16, 0u16, 0u16, 20u16); // (ID, SOURCE, DEST, EXPIRES)

        // Iterate once to figure out column widths
        for vrec in &self.visas {
            let idstr = format!("{}", vrec.id);
            if row_max_lens.0 < idstr.len() as u16 {
                row_max_lens.0 = idstr.len() as u16;
            }
            if row_max_lens.1 < vrec.source_addr.as_ref().unwrap_or(&"-".into()).len() as u16 {
                row_max_lens.1 = vrec.source_addr.as_ref().unwrap_or(&"-".into()).len() as u16;
            }
            if row_max_lens.2 < vrec.dest_addr.as_ref().unwrap_or(&"-".into()).len() as u16 {
                row_max_lens.2 = vrec.dest_addr.as_ref().unwrap_or(&"-".into()).len() as u16;
            }
        }

        let rows = self.visas.iter().map(|vrec| {
            let dt: DateTime<Utc> = vrec.expires.into();

            let source_addr = vrec.source_addr.as_ref().unwrap_or(&"-".into()).clone();
            let dest_addr = vrec.dest_addr.as_ref().unwrap_or(&"-".into()).clone();

            let idstr = format!("{}", vrec.id);
            let expstr = dt.to_rfc3339_opts(SecondsFormat::Secs, true);

            let cells = [
                Cell::from(idstr).style(self.visa_id_style),
                Cell::from(source_addr).style(self.zpr_addr_style),
                Cell::from("->".light_magenta()),
                Cell::from(dest_addr).style(self.zpr_addr_style),
                Cell::from(expstr),
            ];
            Row::new(cells)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(row_max_lens.0 + 3),
                Constraint::Length(row_max_lens.1 + 3),
                Constraint::Length(3), // for the "->" column
                Constraint::Length(row_max_lens.2 + 3),
                Constraint::Length(row_max_lens.3),
            ],
        )
        .header(header)
        .block(pane_block("V", "isas ", is_selected));
        if is_selected {
            let table = table.row_highlight_style(Style::default().reversed());
            frame.render_stateful_widget(table, area, &mut self.visa_state);
            self.render_list_scrollbar(frame, area, self.visas.len(), self.visa_state.offset());
        } else {
            frame.render_widget(table, area);
        }
    }

    /// CN of the actor at `zpr_addr`, if known.
    // ponytail: linear scan, index by addr only if the actor list gets large.
    fn cn_for(&self, zpr_addr: &str) -> Option<&str> {
        self.actors
            .iter()
            .find(|a| a.zpr_addr == zpr_addr)
            .map(|a| a.cn.as_str())
    }

    /// Clamp `detail_scroll` to the content, render the scrolled paragraph, and
    /// overlay a scrollbar only when the content overflows the pane.
    fn render_detail_text(&mut self, frame: &mut Frame, area: Rect, text: Text<'static>) {
        let is_selected = self.selected == Pane::Details;
        let content = text.height() as u16;
        let viewport = area.height.saturating_sub(2); // minus borders
        self.detail_scroll = clamp_scroll(self.detail_scroll, content, viewport);
        let max = content.saturating_sub(viewport);
        frame.render_widget(
            Paragraph::new(text)
                .scroll((self.detail_scroll, 0))
                .block(pane_block("D", "etails ", is_selected)),
            area,
        );
        if max > 0 {
            // Content above/below the visible window → show the matching arrow.
            let above = self.detail_scroll > 0;
            let below = self.detail_scroll < max;
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(if above { Some("▲") } else { None })
                    .end_symbol(if below { Some("▼") } else { None }),
                area.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut ScrollbarState::new(content as usize).position(self.detail_scroll as usize),
            );
        }
    }

    /// Render the details pane. For a selected visa (`detail_source ==
    /// Pane::Visas`) this shows the full descriptor; every other case shows
    /// the "<entity> <id>" placeholder.
    fn render_details(&mut self, frame: &mut Frame, area: Rect) {
        // Full visa detail when the Visas pane feeds Details and a row is set.
        if self.detail_source == Pane::Visas {
            if let Some(v) = self.visa_state.selected().and_then(|i| self.visas.get(i)) {
                let cn = self.cn_for(&v.requesting_node);
                // area.width - 2 excludes the block borders.
                let text = visa_detail_text(v, cn, SystemTime::now(), area.width.saturating_sub(2));
                self.render_detail_text(frame, area, text);
                return;
            }
        }

        // Full actor detail when the Actors pane feeds Details and a row is set.
        if self.detail_source == Pane::Actors {
            if let Some(a) = self.actor_state.selected().and_then(|i| self.actors.get(i)) {
                let mut services: Vec<&str> = self
                    .services
                    .iter()
                    .filter(|s| s.actor_cn == a.cn)
                    .map(|s| s.service_name.as_str())
                    .collect();
                // Stable order across refreshes.
                services.sort_unstable();
                let text = actor_detail_text(
                    a,
                    &services,
                    SystemTime::now(),
                    area.width.saturating_sub(2),
                );
                self.render_detail_text(frame, area, text);
                return;
            }
        }

        // Full service detail when the Services pane feeds Details and a row is set.
        if self.detail_source == Pane::Services {
            if let Some(s) = self
                .service_state
                .selected()
                .and_then(|i| self.services.get(i))
            {
                let text = service_detail_text(s, area.width.saturating_sub(2));
                self.render_detail_text(frame, area, text);
                return;
            }
        }

        let id = match self.detail_source {
            Pane::Actors => self
                .actor_state
                .selected()
                .and_then(|i| self.actors.get(i))
                .map(|a| a.cn.clone()),
            Pane::Services => self
                .service_state
                .selected()
                .and_then(|i| self.services.get(i))
                .map(|s| s.service_name.clone()),
            Pane::Visas => self
                .visa_state
                .selected()
                .and_then(|i| self.visas.get(i))
                .map(|v| v.id.to_string()),
            Pane::Details => None,
        };
        let text = detail_line(self.detail_source, id);
        // Placeholder is short, so max == 0 → no scrollbar; same path is harmless.
        self.render_detail_text(frame, area, Text::from(text));
    }
}
