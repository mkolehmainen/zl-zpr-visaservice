//! "Executes" all the commands kicked off in main (except gui).

use colored::Colorize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use admin_api_types::ListEntry;

use zpr::policy_types::PolicyBundle;

use crate::vsclient::{RoleFilter, VsClient};

pub struct Executor {
    vs_cli: VsClient,
}

impl Executor {
    pub fn new(api_url: String, cert: reqwest::tls::Certificate, api_key: String) -> Self {
        Executor {
            vs_cli: VsClient::new(api_url, cert, api_key, false),
        }
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
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        for (name, value) in &stats.stats {
            println!("{}: {}", name.bold(), value);
        }
        Ok(())
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
        for (i, entry) in entries.iter().enumerate() {
            println!("{} {entry}", format!("ENTRY {}", i).bold());
        }
        Ok(())
    }

    fn get_policy(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.get_policy(id)?;
        println!("{entry}");
        Ok(())
    }

    fn get_curr_policy(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.get_curr_policy()?;
        println!("{entry}");
        Ok(())
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
                println!("{}", "sending policy container".magenta());
                let entry: ListEntry = self.vs_cli.install_policy(&pb)?;
                println!("{entry}");
                Ok(())
            }
            Err(e) => {
                eprintln!("{} {}", "Error creating policy bundle:".red(), e);
                return Err(e.into());
            }
        }
    }

    fn get_visas(&self) -> Result<(), Box<dyn std::error::Error>> {
        let visas = self.vs_cli.get_visas()?;
        for visa_id in visas {
            println!("{} {}", format!("VISA ID").bold(), visa_id);
        }
        Ok(())
    }

    fn get_visa(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let visa = self.vs_cli.get_visa(id)?;
        println!("{visa}");
        Ok(())
    }

    fn revoke_visa(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let revoke = self.vs_cli.revoke_visa(id)?;
        println!("{revoke}");
        Ok(())
    }

    // Either all actors or just nodes.
    fn get_actors(&self, nodes: bool) -> Result<(), Box<dyn std::error::Error>> {
        let filter = if nodes {
            RoleFilter::NodesOnly
        } else {
            RoleFilter::All
        };
        let actor_cns = self.vs_cli.get_actors(filter)?;

        for (i, cn) in actor_cns.iter().enumerate() {
            println!("{} {}", format!("ACTOR {}", i).bold(), cn);
        }
        Ok(())
    }

    fn get_actor(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let actor = self.vs_cli.get_actor(cn)?;
        println!("{actor}");
        Ok(())
    }

    fn revoke_actor(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let revoke = self.vs_cli.revoke_actor(cn)?;
        println!("{revoke}");
        Ok(())
    }

    fn get_related_visas(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_related_visas(cn)?;
        for (i, entry) in entries.iter().enumerate() {
            println!("{} {entry}", format!("ENTRY {}", i).bold());
        }
        Ok(())
    }

    /// Prints the IDs of the visas currently installed on the node with the given CN.
    fn get_visas_on_node(&self, cn: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_visas_on_node(cn)?;
        for (i, entry) in entries.iter().enumerate() {
            println!("{} {entry}", format!("ENTRY {}", i).bold());
        }
        Ok(())
    }

    fn get_services(&self) -> Result<(), Box<dyn std::error::Error>> {
        let svc_names = self.vs_cli.get_services()?;
        for (i, id) in svc_names.iter().enumerate() {
            println!("{} {}", format!("SERVICE {}", i).bold(), id);
        }
        Ok(())
    }

    fn get_service(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let svc = self.vs_cli.get_service(id)?;
        println!("{svc}");
        Ok(())
    }

    /// Refresh a trusted service's attribute data. The visa service then revalidates
    /// active visas against the refreshed attributes asynchronously.
    fn flush_service_cache(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.vs_cli.flush_service_cache(id)?;
        println!("refreshed {id}; active visas are being revalidated");
        Ok(())
    }

    fn get_revokes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.get_revokes()?;
        for (i, entry) in entries.iter().enumerate() {
            println!("{} {entry}", format!("ENTRY {}", i).bold());
        }
        Ok(())
    }

    fn get_revoke(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.get_revoke(id)?;
        println!("{entry}");
        Ok(())
    }

    fn clear_revokes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.vs_cli.clear_revokes()?;
        for (i, entry) in entries.iter().enumerate() {
            println!("{} {entry}", format!("ENTRY {}", i).bold());
        }
        Ok(())
    }

    fn remove_revoke(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.remove_revoke(id)?;
        println!("{entry}");
        Ok(())
    }

    // TODO figure out how we want to get the visa information from the user.
    // Some options would be take in a file with a JSON VisaDescriptor or take in
    // the parts we care about via arguments on the command line
    fn add_revoke(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.vs_cli.add_revoke(id)?;
        println!("{entry}");
        Ok(())
    }

    fn get_network(&self) -> Result<(), Box<dyn std::error::Error>> {
        let network = self.vs_cli.get_network()?;

        println!("{network}");
        Ok(())
    }
}
