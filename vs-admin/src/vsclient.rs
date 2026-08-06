use std::time::Duration;

use colored::Colorize;
use reqwest;
use reqwest::tls::Certificate;

use zpr::policy_types::PolicyBundle;

use admin_api_types::{
    ActorDescriptor, AuthRevokeDescriptor, CnEntry, DenyRecord, ListEntry, NamedListEntry,
    NetworkDetails, Revokes, ServiceDescriptor, Stats, VisaDescriptor, reason_for,
};

use crate::error::VsaError;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const API_KEY_HEADER: &str = "X-API-Key";

#[derive(Debug)]
pub struct VsClient {
    cert: Certificate,
    api_url: String,
    api_key: String,
    quiet: bool,
}

#[allow(dead_code)]
pub enum RoleFilter {
    All,
    NodesOnly,
    AdaptersOnly,
}

impl VsClient {
    pub fn new(svc_url: String, cert: Certificate, api_key: String, quiet: bool) -> Self {
        VsClient {
            cert,
            api_url: svc_url,
            api_key,
            quiet,
        }
    }

    fn build_client(&self) -> Result<reqwest::blocking::Client, VsaError> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(HTTP_TIMEOUT);
        let client = cb.build()?;
        Ok(client)
    }

    fn ht_get(&self, url: &str) -> Result<reqwest::blocking::Response, VsaError> {
        let client = self.build_client()?;
        if !self.quiet {
            print!("{}", format!(">> get {url}").dimmed());
        }
        let resp = client
            .get(url)
            .header(API_KEY_HEADER, &self.api_key)
            .send()?;

        let stat = resp.status();
        if !self.quiet {
            println!("  {}", stat);
        }

        if stat.is_success() {
            return Ok(resp);
        }
        self.display_hterror(resp);
        Err(VsaError::HttpError(stat))
    }

    fn ht_post(&self, url: &str) -> Result<reqwest::blocking::Response, VsaError> {
        let client = self.build_client()?;
        if !self.quiet {
            print!("{}", format!(">> post {url}").dimmed());
        }
        let resp = client
            .post(url)
            .header(API_KEY_HEADER, &self.api_key)
            .send()?;

        let stat = resp.status();
        if !self.quiet {
            println!("  {}", stat);
        }

        if stat.is_success() {
            return Ok(resp);
        }
        self.display_hterror(resp);
        Err(VsaError::HttpError(stat))
    }

    fn ht_post_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<reqwest::blocking::Response, VsaError> {
        let client = self.build_client()?;
        if !self.quiet {
            print!("{}", format!(">> post {url}").dimmed());
        }
        let resp = client
            .post(url)
            .header(API_KEY_HEADER, &self.api_key)
            .json(body)
            .send()?;

        let stat = resp.status();
        if !self.quiet {
            println!("  {}", stat);
        }

        if stat.is_success() {
            return Ok(resp);
        }
        self.display_hterror(resp);
        Err(VsaError::HttpError(stat))
    }

    fn ht_delete(&self, url: &str) -> Result<reqwest::blocking::Response, VsaError> {
        let client = self.build_client()?;
        if !self.quiet {
            print!("{}", format!(">> delete {url}").dimmed());
        }
        let resp = client
            .delete(url)
            .header(API_KEY_HEADER, &self.api_key)
            .send()?;

        let stat = resp.status();
        if !self.quiet {
            println!("  {}", stat);
        }

        if stat.is_success() {
            return Ok(resp);
        }
        self.display_hterror(resp);
        Err(VsaError::HttpError(stat))
    }

    fn display_hterror(&self, error_resp: reqwest::blocking::Response) {
        if self.quiet {
            return;
        }
        eprintln!(
            "{} {}: {}",
            "HTTP Error".red(),
            error_resp.status(),
            reason_for(error_resp.status())
        );
        if let Ok(txt) = error_resp.text() {
            eprintln!("       {}", txt);
        }
    }

    fn request_get_list_entries<T>(&self, req_uri: &str) -> Result<Vec<T>, VsaError>
    where
        T: serde::de::DeserializeOwned,
    {
        let resp = self.ht_get(req_uri)?;
        let entries: Vec<T> = resp.json()?;
        Ok(entries)
    }

    /// `GET <api_url>/admin/actors[?role=node|adapter]`
    ///
    /// Returns a list of CN values.
    pub fn get_actors(&self, filter: RoleFilter) -> Result<Vec<String>, VsaError> {
        let query = match filter {
            RoleFilter::NodesOnly => "?role=node",
            RoleFilter::AdaptersOnly => "?role=adapter",
            RoleFilter::All => "",
        };
        let entry_vec = self.request_get_list_entries::<CnEntry>(&format!(
            "{}/admin/actors{}",
            self.api_url, query
        ))?;
        let cn_list: Vec<String> = entry_vec.into_iter().map(|e| e.cn).collect();
        Ok(cn_list)
    }

    /// `GET <api_url>/admin/actors/<cn>`
    pub fn get_actor(&self, cn: &str) -> Result<ActorDescriptor, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/actors", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(cn);
        let resp = self.ht_get(requrl.as_str())?;
        let entry: ActorDescriptor = resp.json()?;
        Ok(entry)
    }

    /// `GET <api_url>/admin/services`
    ///
    /// Returns a list of service IDs (whihch are names)
    pub fn get_services(&self) -> Result<Vec<String>, VsaError> {
        let entry_vec = self.request_get_list_entries::<NamedListEntry>(&format!(
            "{}/admin/services",
            self.api_url
        ))?;
        let service_ids: Vec<String> = entry_vec.into_iter().map(|e| e.id).collect();
        Ok(service_ids)
    }

    /// `GET <api_url>/admin/services/<id>`
    pub fn get_service(&self, id: &str) -> Result<ServiceDescriptor, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/services", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(id);
        let resp = self.ht_get(requrl.as_str())?;
        let entry: ServiceDescriptor = resp.json()?;
        Ok(entry)
    }

    /// `DELETE <api_url>/admin/services/<id>/cache`
    ///
    /// Reloads the trusted service's attribute data. The visa service then refreshes the
    /// actors behind live visas and revalidates those visas asynchronously (202 Accepted).
    pub fn flush_service_cache(&self, id: &str) -> Result<(), VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/services", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(id).push("cache");
        self.ht_delete(requrl.as_str())?;
        Ok(())
    }

    /// `GET <api_url>/admin/visas`
    pub fn get_visas(&self) -> Result<Vec<u64>, VsaError> {
        let entry_vec =
            self.request_get_list_entries::<ListEntry>(&format!("{}/admin/visas", self.api_url))?;
        let visa_ids: Vec<u64> = entry_vec.into_iter().map(|e| e.id).collect();
        Ok(visa_ids)
    }

    /// `GET <api_url>/admin/visas/<id>`
    pub fn get_visa(&self, id: u64) -> Result<VisaDescriptor, VsaError> {
        let req = format!("{}/admin/visas/{}", self.api_url, id);
        let resp = self.ht_get(&req)?;
        let entry: VisaDescriptor = resp.json()?;
        Ok(entry)
    }

    /// `GET <api_url>/admin/policies`
    pub fn get_policies(&self) -> Result<Vec<ListEntry>, VsaError> {
        let entry_vec = self
            .request_get_list_entries::<ListEntry>(&format!("{}/admin/policies", self.api_url))?;
        Ok(entry_vec)
    }

    /// `GET <api_url>/admin/policies/<id>`
    pub fn get_policy(&self, id: u64) -> Result<PolicyBundle, VsaError> {
        let req = format!("{}/admin/policies/{}", self.api_url, id);
        let resp = self.ht_get(&req)?;
        let entry: PolicyBundle = resp.json()?;
        Ok(entry)
    }

    /// `GET <api_url>/admin/policies/curr`
    pub fn get_curr_policy(&self) -> Result<PolicyBundle, VsaError> {
        let req = format!("{}/admin/policies/curr", self.api_url);
        let resp = self.ht_get(&req)?;
        let entry: PolicyBundle = resp.json()?;
        Ok(entry)
    }

    /// `POST <api_url>/admin/policies`
    pub fn install_policy(&self, bundle: &PolicyBundle) -> Result<ListEntry, VsaError> {
        let req = format!("{}/admin/policies", self.api_url);
        let resp = self.ht_post_json(&req, bundle)?;
        let entry: ListEntry = resp.json()?;
        Ok(entry)
    }

    /// `DELETE <api_url>/admin/visas/<id>`
    pub fn revoke_visa(&self, id: u64) -> Result<Revokes, VsaError> {
        let req = format!("{}/admin/visas/{}", self.api_url, id);
        let resp = self.ht_delete(&req)?;
        let revoke: Revokes = resp.json()?;
        Ok(revoke)
    }

    /// `DELETE <api_url>/admin/actors/<cn>`
    pub fn revoke_actor(&self, cn: &str) -> Result<Revokes, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/actors", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(cn);
        let resp = self.ht_delete(requrl.as_str())?;
        let revoke: Revokes = resp.json()?;
        Ok(revoke)
    }

    /// `GET <api_url>/admin/actors/<cn>/visas`
    pub fn get_related_visas(&self, cn: &str) -> Result<Vec<ListEntry>, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/actors", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(cn).push("visas");
        let entry_vec = self.request_get_list_entries::<ListEntry>(requrl.as_str())?;
        Ok(entry_vec)
    }

    /// `GET <api_url>/admin/authrevoke`
    pub fn get_revokes(&self) -> Result<Vec<ListEntry>, VsaError> {
        let entry_vec = self
            .request_get_list_entries::<ListEntry>(&format!("{}/admin/authrevoke", self.api_url))?;
        Ok(entry_vec)
    }

    /// `GET <api_url>/admin/authrevoke/<id>`
    pub fn get_revoke(&self, id: &str) -> Result<AuthRevokeDescriptor, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/authrevoke", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(id);
        let resp = self.ht_get(requrl.as_str())?;
        let entry: AuthRevokeDescriptor = resp.json()?;
        Ok(entry)
    }

    /// `POST <api_url>/admin/authrevoke/clear`
    pub fn clear_revokes(&self) -> Result<Vec<ListEntry>, VsaError> {
        let req = format!("{}/admin/authrevoke/clear", self.api_url);
        let resp = self.ht_post(&req)?;
        let entries: Vec<ListEntry> = resp.json()?;
        Ok(entries)
    }

    /// `DELETE <api_url>/admin/authrevoke/<id>`
    pub fn remove_revoke(&self, id: &str) -> Result<ListEntry, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/authrevoke", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(id);
        let resp = self.ht_delete(requrl.as_str())?;
        let entry: ListEntry = resp.json()?;
        Ok(entry)
    }

    /// `POST <api_url>/admin/authrevoke/<id>`
    pub fn add_revoke(&self, id: &str) -> Result<ListEntry, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/authrevoke", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(id);
        let resp = self.ht_post(requrl.as_str())?;
        let entry: ListEntry = resp.json()?;
        Ok(entry)
    }

    /// `GET <api_url>/admin/network`
    pub fn get_network(&self) -> Result<NetworkDetails, VsaError> {
        let req = reqwest::Url::parse(&format!("{}/admin/network", self.api_url))?;
        let resp = self.ht_get(req.as_str())?;
        let entry: NetworkDetails = resp.json()?;
        Ok(entry)
    }

    /// `GET <api_url>/admin/nodes/<cn>/visas`
    ///
    /// Returns the IDs of the visas currently installed on the given node.
    pub fn get_visas_on_node(&self, cn: &str) -> Result<Vec<ListEntry>, VsaError> {
        let mut requrl = reqwest::Url::parse(&format!("{}/admin/nodes", self.api_url))?;
        requrl.path_segments_mut().unwrap().push(cn).push("visas");
        let entry_vec = self.request_get_list_entries::<ListEntry>(requrl.as_str())?;
        Ok(entry_vec)
    }

    /// `GET <api_url>/admin/visas/denies[?since=<EPOCH_MS>][&limit=<COUNT>]`
    ///
    /// Returns the recent-denies window, newest request first.
    pub fn get_denies(
        &self,
        since: Option<u64>,
        limit: Option<usize>,
    ) -> Result<Vec<DenyRecord>, VsaError> {
        let requrl = denies_url(&self.api_url, since, limit)?;
        let entry_vec = self.request_get_list_entries::<DenyRecord>(requrl.as_str())?;
        Ok(entry_vec)
    }

    /// `GET <api_url>/admin/stats`
    pub fn get_stats(&self) -> Result<Stats, VsaError> {
        let req = format!("{}/admin/stats", self.api_url);
        let resp = self.ht_get(&req)?;
        let entry: Stats = resp.json()?;
        Ok(entry)
    }
}

/// Builds the `/admin/visas/denies` URL, omitting each query parameter that is
/// `None` so the service applies its own default.
fn denies_url(
    api_url: &str,
    since: Option<u64>,
    limit: Option<usize>,
) -> Result<reqwest::Url, VsaError> {
    let mut requrl = reqwest::Url::parse(&format!("{api_url}/admin/visas/denies"))?;
    if since.is_none() && limit.is_none() {
        // query_pairs_mut() would leave a bare trailing "?" with nothing to append.
        return Ok(requrl);
    }
    {
        let mut qp = requrl.query_pairs_mut();
        if let Some(since) = since {
            qp.append_pair("since", &since.to_string());
        }
        if let Some(limit) = limit {
            qp.append_pair("limit", &limit.to_string());
        }
    }
    Ok(requrl)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `since`/`limit` are passed through verbatim, and omitted entirely when None.
    #[test]
    fn denies_url_includes_only_supplied_query_params() {
        let base = "https://[fd5a:5052::1]:8182";
        let url = |since, limit| denies_url(base, since, limit).unwrap().to_string();

        assert_eq!(url(None, None), format!("{base}/admin/visas/denies"));
        assert_eq!(
            url(Some(1_700_000_000_000), None),
            format!("{base}/admin/visas/denies?since=1700000000000")
        );
        assert_eq!(
            url(None, Some(25)),
            format!("{base}/admin/visas/denies?limit=25")
        );
        assert_eq!(
            url(Some(5), Some(25)),
            format!("{base}/admin/visas/denies?since=5&limit=25")
        );
    }
}
