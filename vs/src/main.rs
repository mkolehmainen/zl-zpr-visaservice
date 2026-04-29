use clap::Parser;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use libeval::attribute::{ROLE_ADAPTER, key};
use libeval::pio;

mod actor_mgr;
mod admin_apikeys;
mod admin_service;
mod apikey;
mod assembly;
mod auth;
mod config;
mod connection_control;
mod counters;
mod db;
mod db_worker;
mod error;
mod event_mgr;
mod logging;
mod net_mgr;
mod packet;
mod policy_mgr;
mod signal_worker;
mod visa_mgr;
mod visareq_worker;
mod vsapi_worker;
mod vss_mgr;

#[cfg(test)]
mod test_helpers;

use crate::actor_mgr::ActorMgr;
use crate::admin_apikeys::ReloadableApiKeys;
use crate::admin_service::start_admin_server;
use crate::assembly::Assembly;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::counters::Counters;
use crate::db::{DbConnection, LockDescriptor, LockType};
use crate::error::ServiceError;
use crate::event_mgr::EventMgr;
use crate::event_mgr::VsEvent;
use crate::logging::enable_logging;
use crate::logging::targets::MAIN;
use crate::net_mgr::NetMgr;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;

use redis::AsyncCommands;
use zpr::vsapi_types::Claim;

const DEFAULT_CONFIG_PATH: &str = "vs.toml";

/// vs - ZPR visa service
#[derive(Parser, Debug)]
#[command(name = "vs")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Initial policy file (.bin2 format). If not specified we will load the current policy set in the database.
    /// If there is no policy in the database the visa service will fail to start.
    policy: Option<PathBuf>,

    /// Enable verbose debug output (use twice for more, eg "-vv").
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Clear any existing state in the database and start fresh. WARNING: REMOVES ALL REDIS KEYS INCLUDING LOCK.
    #[arg(long)]
    clear_state: bool,

    /// Force a regeneration of the visa service identity UUID.
    #[arg(long)]
    regen_identity: bool,

    /// Path to the configuration file. If "vs.toml" is present in the current directory, it will be used by default.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Emit a default configuration file and exit.
    #[arg(long)]
    gen_config: bool,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    if cli.gen_config {
        let default_cfg = VSConfig::default();
        match toml::to_string_pretty(&default_cfg) {
            Ok(toml_str) => {
                println!("{}", toml_str);
                return std::process::ExitCode::SUCCESS;
            }
            Err(e) => {
                error!(target: MAIN, "failed to generate default configuration: {}", e);
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    let verbosity = if cli.verbose >= 2 {
        logging::Verbosity::VeryVerboseIndeed
    } else if cli.verbose == 1 {
        logging::Verbosity::SomewhatVerbose
    } else {
        logging::Verbosity::NotVerbose
    };
    enable_logging(verbosity);
    info!(target: MAIN, "vs version {}", env!("CARGO_PKG_VERSION"));
    let cfg = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            error!(target: MAIN, "failed to load configuration: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let identity = match initialize_identity(&cfg.core.identity, &cli.regen_identity) {
        Ok(id) => id,
        Err(e) => {
            error!(target: MAIN, "failed to initialize identity: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };
    info!("visa service identity: {}", identity);

    // If a policy path was provided, attempt to load it here. If not provided, we set this None
    // and then later the policy_mgr will attempt to load the current policy from the database.
    let initial_policy = {
        if let Some(ref policy_path) = cli.policy {
            match pio::load_policy(
                policy_path,
                pio::Version(
                    config::POLICY_MIN_COMPILER_MAJOR,
                    config::POLICY_MIN_COMPILER_MINOR,
                    config::POLICY_MIN_COMPILER_PATCH,
                ),
            ) {
                Ok(p) => Some(p),
                Err(e) => {
                    error!(target: MAIN, "failed to load initial policy from {}: {}", policy_path.display(), e);
                    return std::process::ExitCode::FAILURE;
                }
            }
        } else {
            None
        }
    };

    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();

    let vk_uri = cfg.core.vk_uri.as_deref().unwrap_or(config::VALKEY_URI);
    let vk_client = redis::Client::open(vk_uri).expect("failed to create ValKey redis client");
    debug!(target: MAIN, "connecting to ValKey at {}...", vk_uri);

    let mut vk_conn = redis::aio::ConnectionManager::new(vk_client)
        .await
        .expect("failed to get redis connection");

    let res: String = vk_conn.ping().await.expect("failed to ping ValKey server");
    info!(target: MAIN, "connected to ValKey at {vk_uri}, ping response: {}", res);

    let db_handle = Arc::new(db::RedisDb::new(vk_conn));

    let vslock_desc = LockDescriptor::new(
        LockType::VsInstance,
        identity.clone(),
        config::VALKEY_LOCK_TIMEOUT,
    );

    if cli.clear_state {
        if let Err(e) = db_handle.clear_state().await {
            error!(target: MAIN, "failed to clear state in the database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
        info!(target: MAIN, "database state cleared successfully");
    }

    match db_handle.acquire_or_renew_lock(&vslock_desc).await {
        Ok(acquired) => {
            if acquired {
                info!(target: MAIN, "acquired visa service lock in the database, starting up");
            } else {
                error!(target: MAIN, "visa service lock is currently held by another instance, exiting");
                return std::process::ExitCode::FAILURE;
            }
        }
        Err(e) => {
            error!(target: MAIN, "failed to acquire visa service lock on the database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut js = JoinSet::new();

    let counters = Arc::new(Counters::default());

    let (vreq_tx, vreq_rx) =
        mpsc::channel::<visareq_worker::VisaRequestJob>(config::VISA_REQUEST_QUEUE_DEPTH);

    let actor_mgr = match create_actor_mgr(db_handle.clone(), counters.clone()).await {
        Ok(adb) => adb,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate actor database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let policy_mgr_res = match initial_policy {
        Some(p) => {
            PolicyMgr::new_with_initial_policy(p, db::PolicyRepo::new(db_handle.clone())).await
        }
        None => PolicyMgr::new_from_state(db::PolicyRepo::new(db_handle.clone())).await,
    };

    let net_mgr = NetMgr::new_v6().expect("failed to create NetMgr");

    if !cli.clear_state {
        if let Err(e) = synchronize_state(&actor_mgr, &net_mgr).await {
            error!(target: MAIN, "error during state synchronization: {}", e);
            // For now treat this as a fail.  Force user to reset state.
            return std::process::ExitCode::FAILURE;
        }
    }

    let policy_mgr = match policy_mgr_res {
        Ok(pm) => pm,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate policy manager: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let visa_repo = match db::VisaRepo::new(db_handle.clone(), config::INITIAL_VISA_ID).await {
        Ok(vr) => vr,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate visa repository: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let (event_tx, event_rx) = mpsc::channel(config::EVENT_QUEUE_DEPTH);

    let admin_api_keys = match ReloadableApiKeys::new_from_file(
        cfg.core
            .api_keys
            .clone()
            .unwrap_or_else(|| PathBuf::from(config::DEFAULT_API_KEYS_FILE)),
        true,
    ) {
        Ok(keys) => keys,
        Err(e) => {
            error!(target: MAIN, "failed to load admin API keys: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if admin_api_keys.is_empty() {
        warn!(target: MAIN, "no active admin API keys, admin API will be inaccessible until keys file '{}' is created and contains active keys",
            admin_api_keys.get_path().display());
    }

    let asm = Arc::new(Assembly {
        config: cfg.clone(),
        counters,
        system_start_time: std::time::Instant::now(),
        cc: ConnectionControl::new(identity),
        policy_mgr: policy_mgr,
        actor_mgr: Arc::new(actor_mgr),
        state_db: db_handle,
        vreq_chan: vreq_tx,
        visa_mgr: VisaMgr::new(visa_repo),
        vss_mgr: VssMgr::new(),
        net_mgr: Arc::new(net_mgr),
        event_mgr: EventMgr::new(event_tx),
        admin_api_keys: Arc::new(admin_api_keys),
    });

    js.spawn_local(signal_worker::launch(asm.clone()));
    js.spawn_local(db_worker::launch(asm.clone(), vslock_desc));
    js.spawn_local(event_mgr::launch(asm.clone(), event_rx));

    js.spawn_local(vsapi_worker::launch(
        asm.clone(),
        SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.vsapi_port.unwrap_or(config::VSAPI_PORT),
        ),
    ));

    {
        let admin_key = cfg.core.admin_key.clone();
        let admin_cert = cfg.core.admin_cert.clone();
        let admin_listen = SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.admin_port.unwrap_or(config::ADMIN_HTTPS_PORT),
        );
        let admin_asm = asm.clone();
        js.spawn_local(async move {
            start_admin_server(&admin_key, &admin_cert, admin_listen, &admin_asm).await;
        });
    }

    js.spawn_local(visareq_worker::launch_arena(
        asm.clone(),
        vreq_rx,
        config::MAX_VISA_REQUEST_WORKERS,
    ));

    // perform initial self-authorization
    if let Err(e) = self_authorize(asm.clone(), &cfg.get_vs_addr()).await {
        error!(target: MAIN, "self-authorization failed: {}", e);
        return std::process::ExitCode::FAILURE;
    }

    // TODO: Setup/launch the workers for the visa service. Those that will do the actual work
    // of generating visas, and all the housekeeping.

    local_set
        .run_until(async {
            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        })
        .await;

    info!(target: MAIN, "exiting");
    std::process::ExitCode::SUCCESS
}

/// Load configuration from an explicit path, the default path, or fall back to defaults.
fn load_config(explicit: Option<&std::path::Path>) -> Result<VSConfig, ServiceError> {
    match explicit {
        Some(path) => {
            let cfg = VSConfig::from_file(path)?;
            info!(target: MAIN, "using configuration: {}", path.display());
            Ok(cfg)
        }
        None => {
            let default_path = std::path::Path::new(DEFAULT_CONFIG_PATH);
            if default_path.exists() {
                let cfg = VSConfig::from_file(default_path)?;
                info!(target: MAIN, "using configuration: {}", default_path.display());
                Ok(cfg)
            } else {
                info!(target: MAIN, "no configuration file found, using defaults");
                Ok(VSConfig::default())
            }
        }
    }
}

async fn create_actor_mgr(
    dbh: Arc<dyn DbConnection>,
    counters: Arc<Counters>,
) -> Result<ActorMgr, ServiceError> {
    let adb = db::ActorRepo::new(dbh.clone());
    let ndb = db::NodeRepo::new(dbh);
    let mgr = ActorMgr::new(adb, ndb, counters);
    Ok(mgr)
}

// TODO: This belongs somewhere else. Must be run every time we load a new policy.
//
// Also this "authorizes" the visa service actor by fiat, but we do not yet know what
// node the vs adapter is docked to.  We also have no way at the moment to tell the
// vs what node it is docked to.
//
// One idea is to query our local ph (via ph-cli) and get the substrate address of
// the docking node.  We can use that to find the node record.
//
async fn self_authorize(asm: Arc<Assembly>, vs_addr: &IpAddr) -> Result<(), ServiceError> {
    let mut claims = Vec::new();
    claims.push(Claim::new(key::ZPR_ADDR.into(), vs_addr.to_string()));
    claims.push(Claim::new(key::CN.into(), config::VS_CN.into()));
    claims.push(Claim::new(key::ROLE.into(), ROLE_ADAPTER.into()));

    let actor = asm
        .cc
        .authenticate_visa_service(asm.clone(), claims)
        .await?;

    asm.actor_mgr.add_adapter_no_node(&actor).await?;

    let evt = VsEvent::ActorJoins(vs_addr.clone());
    if let Err(e) = asm.event_mgr.record_event(evt).await {
        warn!(target: MAIN, "failed to record actor joins event for adapter {:?}: {}", actor.get_cn(), e);
    }

    Ok(())
}

fn initialize_identity(
    config_identity: &Option<String>,
    regen_identity: &bool,
) -> Result<String, ServiceError> {
    // If user has supplied a non-empty identity string, use it and ignore any stored
    // identity file.
    if let Some(id) = config_identity {
        if !id.trim().is_empty() {
            return Ok(id.clone());
        }
    }

    // If we have an identity stored locally, use that -- unless user wants a regen.
    let mut id_path = config::get_data_home();
    id_path.push("vs_identity.txt");
    if id_path.exists() && !regen_identity {
        let contents = fs::read_to_string(&id_path)?;
        let id_str = contents.trim();
        if !id_str.is_empty() {
            debug!(target: MAIN, "loaded existing identity from {}", id_path.display());
            return Ok(id_str.to_string());
        }
    }

    // Else create a new identity, store it, and return it.
    let new_identity = uuid::Uuid::new_v4().to_string();
    fs::create_dir_all(config::get_data_home())?;
    fs::write(&id_path, &new_identity)?;
    debug!(target: MAIN, "created new identity file at {}", id_path.display());
    Ok(new_identity)
}

/// If we are starting with state in the DB, do any housekeeping needed to get in sync.
///
/// TODO: If we have state in the db, and we are loading a policy that differs from
/// the saved "curent" policy, we may have visas that are not longer valid.
async fn synchronize_state(actor_mgr: &ActorMgr, net_mgr: &NetMgr) -> Result<(), ServiceError> {
    actor_mgr.refresh_state().await?;

    // Grab all the adapter addresses we have handed out already so that we do not try
    // to hand out the same address to a new adapter.
    for zpr_addr in actor_mgr.list_zpr_addrs().await.unwrap_or_default() {
        if net_mgr.is_managed_address(&zpr_addr) {
            net_mgr.take_zpr_addr(&zpr_addr)?;
        }
    }
    Ok(())
}
