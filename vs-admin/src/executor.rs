//! "Executes" all the commands kicked off in main (except gui).

use colored::Colorize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use admin_api_types::ListEntry;

use zpr::policy_types::PolicyBundle;

use crate::main_args::OutputFormat;
use crate::vsclient::{RoleFilter, VsClient};

pub struct Executor {
    vs_cli: VsClient,
    format: OutputFormat,
}

impl Executor {
    /// `format` selects between indented and single-line JSON output.
    pub fn new(
        api_url: String,
        cert: reqwest::tls::Certificate,
        api_key: String,
        format: OutputFormat,
    ) -> Self {
        Executor {
            // Not quiet: the request trace and HTTP error bodies go to stderr, leaving
            // stdout carrying only the JSON response so it can (eg) be piped to jq.
            vs_cli: VsClient::new(api_url, cert, api_key, false),
            format,
        }
    }

    /// Renders an admin API response as JSON on stdout, honoring `--format`.
    fn print_json<T: serde::Serialize>(&self, v: &T) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "{}",
            match self.format {
                OutputFormat::Pretty => serde_json::to_string_pretty(v)?,
                OutputFormat::Compact => serde_json::to_string(v)?,
            }
        );
        Ok(())
    }

    pub fn do_cmd_policies(
        &self,
        id: Option<u64>,
        path: Option<String>,
        curr: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            Some(id) => self.get_policy(id)?,
            None => match curr {
                true => self.get_curr_policy()?,
                false => match path {
                    Some(path) => self.install_policy(Path::new(&path))?,
                    _ => self.get_policies()?,
                },
            },
        }
        Ok(())
    }

    pub fn do_cmd_visas(
        &self,
        id: Option<u64>,
        revoke: bool,
        on_node: Option<String>,
        denies: bool,
        last: Option<u64>,
        limit: Option<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if denies {
            return self.get_denies(last, limit);
        }
        match (id, on_node) {
            (Some(id), _) => match revoke {
                true => self.revoke_visa(id)?,
                false => self.get_visa(id)?,
            },
            (None, Some(cn)) => self.get_visas_on_node(&cn)?,
            (None, None) => self.get_visas()?,
        }
        Ok(())
    }

    /// Prints the visa service statistics as name/value pairs.
    pub fn do_cmd_stats(&self) -> Result<(), Box<dyn std::error::Error>> {
        let stats = self.vs_cli.get_stats()?;
        self.print_json(&stats)
    }

    pub fn do_cmd_actors(
        &self,
        cn: Option<String>,
        revoke: bool,
        nodes: bool,
        visas: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match cn {
            Some(cn) => match (revoke, visas) {
                (true, _) => self.revoke_actor(&cn)?,
                (_, true) => self.get_related_visas(&cn)?,
                _ => self.get_actor(&cn)?,
            },
            None => self.get_actors(nodes)?,
        }

        Ok(())
    }

    pub fn do_cmd_services(
        &self,
        id: Option<String>,
        flush: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            Some(id) => match flush {
                true => self.flush_service_cache(&id)?,
                false => self.get_service(&id)?,
            },
            None => self.get_services()?,
        }
        Ok(())
    }

    pub fn do_cmd_auth_revoke(
        &self,
        clear: bool,
        add: bool,
        remove: bool,
        id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            Some(id) => match remove {
                true => self.remove_revoke(&id)?,
                false => match add {
                    false => self.get_revoke(&id)?,
                    true => self.add_revoke(&id)?,
                },
            },
            None => match clear {
                true => self.clear_revokes()?,
                false => self.get_revokes()?,
            },
        }

        Ok(())
    }

    pub fn do_cmd_network(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.get_network()?;
        Ok(())
    }

    fn get_policies(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_policies()?;
        self.print_json(&entries)
    }

    fn get_policy(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.get_policy(id)?;
        self.print_json(&entry)
    }

    fn get_curr_policy(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.get_curr_policy()?;
        self.print_json(&entry)
    }

    // Push a binary policy file to the visa service.
    //
    // TODO: Ideally we would open the policy file and read the version from it.  The version
    // passed here through the API is only used to catch potential problems early. The
    // visa service will open the policy file and check the actual version itself.
    //
    fn install_policy(&self, policy: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut policy_buf = Vec::new();
        File::open(policy)?.read_to_end(&mut policy_buf)?;

        match PolicyBundle::new_from_policy_container(0, policy_buf.into()) {
            Ok(pb) => {
                eprintln!("{}", "sending policy container".magenta());
                let entry: ListEntry = self.vs_cli.install_policy(&pb)?;
                self.print_json(&entry)
            }
            Err(e) => {
                eprintln!("{} {}", "Error creating policy bundle:".red(), e);
                return Err(e.into());
            }
        }
    }

    fn get_visas(&self) -> Result<(), Box<dyn std::error::Error>> {
        let visas = self.vs_cli.get_visas()?;
        self.print_json(&visas)
    }

    fn get_visa(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let visa = self.vs_cli.get_visa(id)?;
        self.print_json(&visa)
    }

    /// Prints the recent-denies window, newest first. `last` is a lookback
    /// duration in milliseconds; without it every recorded deny is requested.
    fn get_denies(
        &self,
        last: Option<u64>,
        limit: Option<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let since = last.map(|d| since_from_last(epoch_ms_now(), d));
        let records = self.vs_cli.get_denies(since, limit)?;
        self.print_json(&records)
    }

    fn revoke_visa(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let revoke = self.vs_cli.revoke_visa(id)?;
        self.print_json(&revoke)
    }

    // Either all actors or just nodes.
    fn get_actors(&self, nodes: bool) -> Result<(), Box<dyn std::error::Error>> {
        let filter = if nodes {
            RoleFilter::NodesOnly
        } else {
            RoleFilter::All
        };
        let actors = self.vs_cli.get_actors(filter)?;
        self.print_json(&actors)
    }

    fn get_actor(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let actor = self.vs_cli.get_actor(cn)?;
        self.print_json(&actor)
    }

    fn revoke_actor(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let revoke = self.vs_cli.revoke_actor(cn)?;
        self.print_json(&revoke)
    }

    fn get_related_visas(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_related_visas(cn)?;
        self.print_json(&entries)
    }

    /// Prints the IDs of the visas currently installed on the node with the given CN.
    fn get_visas_on_node(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_visas_on_node(cn)?;
        self.print_json(&entries)
    }

    fn get_services(&self) -> Result<(), Box<dyn std::error::Error>> {
        let services = self.vs_cli.get_services()?;
        self.print_json(&services)
    }

    fn get_service(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let svc = self.vs_cli.get_service(id)?;
        self.print_json(&svc)
    }

    /// Refresh a trusted service's attribute data. The visa service then revalidates
    /// active visas against the refreshed attributes asynchronously.
    fn flush_service_cache(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vs_cli.flush_service_cache(id)?;
        eprintln!("refreshed {id}; active visas are being revalidated");
        Ok(())
    }

    fn get_revokes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_revokes()?;
        self.print_json(&entries)
    }

    fn get_revoke(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.get_revoke(id)?;
        self.print_json(&entry)
    }

    fn clear_revokes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.clear_revokes()?;
        self.print_json(&entries)
    }

    fn remove_revoke(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.remove_revoke(id)?;
        self.print_json(&entry)
    }

    // TODO figure out how we want to get the visa information from the user.
    // Some options would be take in a file with a JSON VisaDescriptor or take in
    // the parts we care about via arguments on the command line
    fn add_revoke(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.add_revoke(id)?;
        self.print_json(&entry)
    }

    fn get_network(&self) -> Result<(), Box<dyn std::error::Error>> {
        let network = self.vs_cli.get_network()?;
        self.print_json(&network)
    }
}

/// Current epoch time in milliseconds, clamped rather than panicking on a
/// pre-epoch or absurdly future clock.
fn epoch_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Turns a `--last` lookback duration into the `since` value for the HTTP API.
/// A lookback reaching before the Unix epoch saturates to 0, ie "everything".
fn since_from_last(now_ms: u64, duration_ms: u64) -> u64 {
    now_ms.saturating_sub(duration_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `--last` window subtracts from now, and one reaching past the epoch clamps to 0.
    #[test]
    fn since_from_last_subtracts_and_saturates() {
        let now_ms = 1_700_000_000_000u64;
        // "3m" arrives here as 180_000 ms from parse_timespec.
        assert_eq!(since_from_last(now_ms, 180_000), 1_699_999_820_000);
        assert_eq!(since_from_last(1_000, 5_000), 0);
        assert_eq!(since_from_last(now_ms, 0), now_ms);
    }
}
