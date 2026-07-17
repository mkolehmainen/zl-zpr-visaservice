use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
