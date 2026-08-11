use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// How `vs-admin` renders JSON responses on stdout.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum OutputFormat {
    /// Indented, human-readable JSON.
    Pretty,
    /// Single-line JSON.
    Compact,
}

#[derive(Parser)]
#[command(version, about = "Visa Service Admin Tool", long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: Option<SubCmd>,
    /// The visa service base API url without any final slash, eg "https://[fd5a:5052::1]:8182".
    #[arg(short, long, value_name = "URL")]
    pub svc_url: String,

    /// Path to the CA certificate file used to validate the visa service TLS credentials.
    #[arg(short, long, value_name = "PEM_CERT_FILE")]
    pub ca_cert: PathBuf,

    /// API key for authenticating with the visa service admin API.
    /// WARNING: insecure — key will be visible in shell history. Prefer --api-key-file or VS_API_KEY.
    #[arg(long, value_name = "KEY", conflicts_with = "api_key_file")]
    pub api_key: Option<String>,

    /// Path to a file containing the API key for the visa service admin API.
    #[arg(long, value_name = "PATH", conflicts_with = "api_key")]
    pub api_key_file: Option<PathBuf>,

    /// Output format for JSON responses.
    #[arg(long, value_enum, default_value = "pretty", value_name = "FMT")]
    pub format: OutputFormat,
}

#[derive(Subcommand)]
pub enum SubCmd {
    /// Commands related to policies, provide no additional arguments to see list of IDs of all policies
    #[command()]
    Policies {
        /// See more information on a specific policy
        #[arg(long, short = 'i', conflicts_with_all = ["path", "curr"])]
        id: Option<u64>,
        /// Path to compiled policy when installing a new policy. If path is provided, version must be as well
        #[arg(long, short = 'p', conflicts_with_all = ["id", "curr"])]
        path: Option<String>,
        /// See the current policy in the VS
        #[arg(long, short = 'c', conflicts_with_all = ["path", "id"])]
        curr: bool,
    },

    /// Commands related to policies, provide no additional arguments to see list of IDs of all visas
    #[command()]
    Visas {
        /// See more information on a specific visa
        #[arg(long, short = 'i')]
        id: Option<u64>,
        /// Revoke a policy with a given visa ID. If revoke is supplied, id must be as well
        // TODO decide if it should be visas --revoke --id ID or if revoke should also take a u64 and be visas --revoke ID
        #[arg(long, short = 'r', requires = "id")]
        revoke: bool,
        /// List the visas currently installed on the node with the given CN
        #[arg(long, short = 'n', value_name = "CN", conflicts_with_all = ["id", "revoke"])]
        on_node: Option<String>,
        /// Show the recent visa denies, most recent first
        #[arg(long, conflicts_with_all = ["id", "revoke", "on_node"])]
        denies: bool,
        /// Only show denies from within the last <TIMESPEC>, eg "45s", "3m", "2h"
        #[arg(long, value_name = "TIMESPEC", requires = "denies", value_parser = parse_timespec)]
        last: Option<u64>,
        /// Limit output to the most recent <COUNT> denies
        #[arg(long, value_name = "COUNT", requires = "denies")]
        limit: Option<usize>,
    },

    /// Commands related to actors, provide no additional arguments to see list of CNs of all actors
    #[command()]
    Actors {
        /// See more information on a specific actor
        #[arg(long, short = 'c', conflicts_with = "nodes")]
        cn: Option<String>,
        /// Remove the actor with a given CN in the VS, along with any associated visas. If revoke is supplied, cn must be as well
        // TODO decide if it should be visas --revoke --id ID or if revoke should also take a u64 and be visas --revoke ID
        #[arg(long, short = 'r', requires = "cn", conflicts_with_all = ["nodes", "visas"])]
        revoke: bool,
        /// See list of CNs of all actors that are nodes
        #[arg(long, short = 'n', conflicts_with_all = ["cn", "revoke", "visas"])]
        nodes: bool,
        /// Provide visas related to the actor with a given CN. If visas is supplied, cn must be as well
        #[arg(long, short = 'v', requires = "cn", conflicts_with_all = ["revoke", "nodes"])]
        visas: bool,
    },

    /// Commands related to services, provide no additional arguments to see list of IDs of all services
    #[command()]
    Services {
        /// See more information on a specific service
        #[arg(long, short = 'i')]
        id: Option<String>,
        /// Refresh a trusted service's attribute data and revalidate active visas against
        /// it. If flush is supplied, id must be as well
        #[arg(long, short = 'f', requires = "id")]
        flush: bool,
    },

    /// Commands related to auth revokes, provide no additional arguments to see list of IDs of all auth revokes
    #[command()]
    AuthRevoke {
        /// See more information on a specific auth revoke
        #[arg(long, short = 'i', conflicts_with = "clear")]
        id: Option<String>,
        /// Clear list of auth-revokes in the VS
        #[arg(long, short = 'c', conflicts_with_all = ["id", "add", "remove"])]
        clear: bool,
        /// Add auth revoke for a visa with a given ID. If add is supplied, id must be as well
        #[arg(long, short = 'a', requires = "id", conflicts_with_all = ["clear", "remove"])]
        add: bool,
        /// Remove the auth revoke for a visa with a given ID. If remove is supplied, id must be as well
        #[arg(long, short = 'r', requires = "id", conflicts_with_all = ["clear", "add"])]
        remove: bool,
    },

    #[command()]
    Network,

    /// Show visa service statistics
    #[command()]
    Stats,

    /// Enter GUI mode
    #[command()]
    Gui,
}

/// Parses a `<N><unit>` duration into milliseconds, where the unit is exactly
/// one of the lowercase `h`, `m`, `s`. Used as the clap value parser for
/// `visas --denies --last`.
fn parse_timespec(spec: &str) -> Result<u64, String> {
    let bad = || format!("invalid time spec '{spec}', expected <N>h, <N>m, or <N>s (eg \"3m\")");

    // split_at_checked, not split_at: a trailing multi-byte char (eg "3µ") would
    // otherwise land the index inside a char and panic instead of erroring.
    let Some((digits, unit)) = spec.split_at_checked(spec.len().saturating_sub(1)) else {
        return Err(bad());
    };
    let secs_per_unit: u64 = match unit {
        "h" => 3600,
        "m" => 60,
        "s" => 1,
        _ => return Err(bad()),
    };
    // Rejects signs, whitespace and any other non-digit; also rejects an empty number.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }

    let n: u64 = digits.parse().map_err(|_| bad())?;
    n.checked_mul(secs_per_unit)
        .and_then(|secs| secs.checked_mul(1000))
        .ok_or_else(|| format!("time spec '{spec}' is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Accepts each supported unit and converts it to milliseconds.
    #[test]
    fn parse_timespec_accepts_all_units() {
        assert_eq!(parse_timespec("45s").unwrap(), 45_000);
        assert_eq!(parse_timespec("3m").unwrap(), 180_000);
        assert_eq!(parse_timespec("2h").unwrap(), 7_200_000);
        assert_eq!(parse_timespec("0s").unwrap(), 0);
    }

    /// Rejects everything outside the exact `<N><unit>` form, plus overflow.
    #[test]
    fn parse_timespec_rejects_malformed_specs() {
        for bad in [
            "", "m", "3", "-3m", "+3m", " 3m", "3m ", "3 m", "3M", "3H", "3S", "3ms", "3d", "3.5m",
            "three m", // Multi-byte trailing chars must error, not panic on a char-boundary split.
            "3µ", "3秒", "3🕐",
        ] {
            assert!(parse_timespec(bad).is_err(), "should reject {bad:?}");
        }
        assert!(parse_timespec(&format!("{}h", u64::MAX)).is_err());
        // Fits u64 seconds but overflows once converted to milliseconds.
        assert!(parse_timespec(&format!("{}s", u64::MAX / 999)).is_err());
    }

    /// Parses a `vs-admin visas ...` command line with the required global args.
    fn try_parse_visas(extra: &[&str]) -> Result<Cmd, clap::Error> {
        let mut argv = vec![
            "vs-admin",
            "--svc-url",
            "https://[::1]:8182",
            "--ca-cert",
            "ca.pem",
            "--api-key",
            "k",
            "visas",
        ];
        argv.extend_from_slice(extra);
        Cmd::try_parse_from(argv)
    }

    /// `--last` and `--limit` are only meaningful alongside `--denies`.
    #[test]
    fn last_and_limit_require_denies() {
        assert!(try_parse_visas(&["--last", "3m"]).is_err());
        assert!(try_parse_visas(&["--limit", "5"]).is_err());
        assert!(try_parse_visas(&["--denies", "--last", "3m", "--limit", "5"]).is_ok());
    }

    /// `--denies` cannot be combined with the single-visa or per-node options.
    #[test]
    fn denies_conflicts_with_other_visa_options() {
        assert!(try_parse_visas(&["--denies", "--id", "7"]).is_err());
        assert!(try_parse_visas(&["--denies", "--id", "7", "--revoke"]).is_err());
        assert!(try_parse_visas(&["--denies", "--on-node", "node-1"]).is_err());
    }

    /// Output defaults to pretty, accepts both format names, and no longer takes `--pretty`.
    #[test]
    fn format_defaults_to_pretty() {
        let parse = |extra: &[&str]| {
            let mut argv = vec![
                "vs-admin",
                "--svc-url",
                "https://[::1]:8182",
                "--ca-cert",
                "ca.pem",
                "--api-key",
                "k",
            ];
            argv.extend_from_slice(extra);
            argv.push("stats");
            Cmd::try_parse_from(argv)
        };
        assert_eq!(parse(&[]).unwrap().format, OutputFormat::Pretty);
        assert_eq!(
            parse(&["--format", "compact"]).unwrap().format,
            OutputFormat::Compact
        );
        assert!(parse(&["--pretty"]).is_err());
        assert!(parse(&["--format", "bogus"]).is_err());
    }

    /// The clap definition itself is well formed (catches bad `requires`/`conflicts_with` names).
    #[test]
    fn command_definition_is_valid() {
        Cmd::command().debug_assert();
    }
}
