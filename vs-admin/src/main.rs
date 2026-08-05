mod error;
mod executor;
mod gui;
mod main_args;
mod vsclient;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use clap::{Args, Parser};
use colored::Colorize;
use reqwest;
use reqwest::tls::Certificate;

use crate::executor::Executor;
use crate::main_args::{Cmd, SubCmd};

#[derive(Args)]
#[group(required = true, multiple = false)]
struct RevokeArg {
    /// Revoke a visa ID
    #[arg(long)]
    visa_id: Option<u64>,

    /// Revoke access to a given adapter CN
    #[arg(long)]
    actor_cn: Option<String>,
}

fn resolve_api_key(args: &Cmd) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(key) = &args.api_key {
        return Ok(key.clone());
    }
    if let Some(path) = &args.api_key_file {
        let contents = std::fs::read_to_string(path)
            .map_err(|_| format!("api key file not found: {}", path.display()))?;
        let key = contents.trim().to_string();
        if key.is_empty() {
            return Err(format!("api key file is invalid (empty): {}", path.display()).into());
        }
        return Ok(key);
    }
    if let Ok(key) = std::env::var("VS_API_KEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    Err("an api key is required; use --api-key, --api-key-file, or set VS_API_KEY".into())
}

fn main() {
    let args = Cmd::parse();

    let ca_cert = load_cert(&args.ca_cert).unwrap();

    let api_key = resolve_api_key(&args).unwrap_or_else(|e| {
        eprintln!("{} {}", "Error:".red(), e);
        std::process::exit(1);
    });

    let exec = Executor::new(args.svc_url.clone(), ca_cert.clone(), api_key.clone());

    match args.command {
        Some(SubCmd::Policies { id, path, curr }) => exec.do_cmd_policies(id, path, curr),

        Some(SubCmd::Visas {
            id,
            revoke,
            on_node,
        }) => exec.do_cmd_visas(id, revoke, on_node),

        Some(SubCmd::Actors {
            cn,
            revoke,
            nodes,
            visas,
        }) => exec.do_cmd_actors(cn, revoke, nodes, visas),

        Some(SubCmd::Services { id, flush }) => exec.do_cmd_services(id, flush),
        // Some(SubCmd::Install {
        //     compiler_version,
        //     policy,
        // }) => install(&args.svc_url, ca_cert, &compiler_version, &policy).unwrap_or_else(|e| {
        //     eprintln!("{} {}", "Error: ".red(), e);
        // }),
        Some(SubCmd::AuthRevoke {
            clear,
            add,
            remove,
            id,
        }) => exec.do_cmd_auth_revoke(clear, add, remove, id),

        Some(SubCmd::Gui) => gui::enter_gui(&args.svc_url, ca_cert, api_key),

        Some(SubCmd::Network) => exec.do_cmd_network(),

        Some(SubCmd::Stats) => exec.do_cmd_stats(),

        None => Err("no command specified".into()),
    }
    .unwrap_or_else(|e| {
        eprintln!("{} {}", "Error: ".red(), e);
    })
}

fn load_cert(ca: &Path) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut cert_buf = Vec::new();
    File::open(ca)?.read_to_end(&mut cert_buf)?;
    let cert = Certificate::from_pem(&cert_buf)?;
    Ok(cert)
}
