use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

/// Target of a log message, for filtering.
/// Convention: const name = UPPER(string value).
pub mod targets {
    pub const MAIN: &str = "main";
    pub const ADMIN: &str = "admin";
    pub const API: &str = "api";
    pub const CC: &str = "cc";
    pub const DB: &str = "db";
    pub const EVENT: &str = "event";
    pub const VISA: &str = "visa";
    #[allow(dead_code)]
    pub const ACTOR: &str = "actor";
    pub const VSS: &str = "vss";
    pub const VREQ: &str = "vreq";
    pub const TOPO: &str = "topo";
    pub const TS: &str = "ts";
}

pub enum Verbosity {
    NotVerbose,
    SomewhatVerbose,
    VeryVerboseIndeed,
}

pub fn enable_logging(verbosity: Verbosity) {
    let level = match verbosity {
        Verbosity::NotVerbose => Level::INFO,
        Verbosity::SomewhatVerbose => Level::DEBUG,
        Verbosity::VeryVerboseIndeed => Level::TRACE,
    };
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            //.with(fmt::layer().with_thread_ids(true))
            .with(fmt::layer())
            .with(LevelFilter::from_level(level)),
    )
    .expect("failed to initialize logging");
}
