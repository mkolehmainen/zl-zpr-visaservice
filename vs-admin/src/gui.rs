//use colored::Colorize;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use reqwest::tls::Certificate;

use chrono::{DateTime, SecondsFormat, Utc};
use std::time::{Duration, Instant};

use admin_api_types::{ActorDescriptor, ServiceDescriptor, VisaDescriptor};

use crate::vsclient::{RoleFilter, VsClient};

/// Do not hit the VS ADMIN api more than this often.
const REFRESH_RATE: Duration = Duration::from_millis(2000);

#[derive(Debug)]
struct Gui {
    exit: bool,
    err_msg: Option<String>,
    last_updated: Option<Instant>,
    vs_cli: VsClient,
    actors: Vec<ActorDescriptor>,
    services: Vec<ServiceDescriptor>,
    visas: Vec<VisaDescriptor>,
    table_header_style: Style,
    zpr_addr_style: Style,
    cn_style: Style,
    visa_id_style: Style,
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
            last_updated: None,
            table_header_style: Style::default().fg(Color::LightGreen).bg(Color::Black),
            zpr_addr_style: Color::Yellow.into(),
            cn_style: Color::White.into(),
            visa_id_style: Color::White.into(),
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

    fn draw(&self, frame: &mut Frame) {
        self.render_gui(frame, frame.area());
    }

    fn handle_events(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => self.exit = true,
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
            for cn in &actor_cns {
                match self.vs_cli.get_actor(cn) {
                    Ok(a) => {
                        self.actors.push(a);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.actors.sort(); // uses Ord trait
        }
        self.last_updated = Some(Instant::now());

        {
            let service_ids = self.vs_cli.get_services()?;
            self.services.clear();
            for sid in &service_ids {
                match self.vs_cli.get_service(sid) {
                    Ok(s) => {
                        self.services.push(s);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.services.sort(); // uses Ord trait
        }

        {
            let visa_ids = self.vs_cli.get_visas()?;
            self.visas.clear();
            for vid in &visa_ids {
                match self.vs_cli.get_visa(*vid) {
                    Ok(v) => {
                        self.visas.push(v);
                    }
                    Err(_) => (), // silently ignore load errors for now
                }
            }
            self.visas.sort(); // uses Ord trait
            self.visas.reverse();
        }

        self.last_updated = Some(Instant::now());
        Ok(())
    }

    fn render_gui(&self, frame: &mut Frame, area: Rect) {
        let title = Line::from("  ZPR Visa Service  ".bold());
        let instructions = Line::from(vec![
            " Press".into(),
            " <q> ".blue().bold(),
            "to quit ".into(),
        ]);

        let [header_area, content_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        frame.render_widget(Paragraph::new(Text::from(title)).centered(), header_area);
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
        let [actor_area, service_area, visa_area] = Layout::vertical([
            Constraint::Percentage(20),
            Constraint::Percentage(30),
            Constraint::Percentage(50),
        ])
        .areas(content_area);

        self.render_actors(frame, actor_area);
        self.render_services(frame, service_area);
        self.render_visas(frame, visa_area);
    }

    fn render_services(&self, frame: &mut Frame, area: Rect) {
        if self.services.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No services found.").red())
                    .block(Block::default().borders(Borders::ALL).title("Services ")),
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Services ".bold()),
        );
        frame.render_widget(table, area);
    }

    fn render_actors(&self, frame: &mut Frame, area: Rect) {
        if self.actors.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No actors found.").red())
                    .block(Block::default().borders(Borders::ALL).title("Actors ")),
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
        let clock_unix = DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        let clock = format!(" {}", clock_unix.to_rfc3339_opts(SecondsFormat::Secs, true));
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Actors ".bold())
                .title(Line::from(clock.cyan()).right_aligned()),
        );
        frame.render_widget(table, area);
    }

    fn render_visas(&self, frame: &mut Frame, area: Rect) {
        if self.visas.is_empty() {
            frame.render_widget(
                Paragraph::new(Text::from("No visas found.").red())
                    .block(Block::default().borders(Borders::ALL).title("Visas ")),
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Visas ".bold()),
        );
        frame.render_widget(table, area);
    }
}
