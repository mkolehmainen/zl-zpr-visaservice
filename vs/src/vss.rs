//! Shared VSS related types.

use std::net::IpAddr;
use tokio::sync::oneshot;

use zpr::vsapi_types::{Param, ServiceDescriptor, Visa};

use crate::error::VssSyncError;

pub type VssPushResponse = Result<usize, VssSyncError>; // usize is number items pushed.
pub type VssRevokeAuthResponse = Result<usize, VssSyncError>; // usize is number of items revoked.
pub type VssSetServicesResponse = Result<(), VssSyncError>;
pub type VssConfigureResponse = Result<(), VssSyncError>;

// Each API call is expressed as a message using this enum.
#[allow(dead_code)]
pub enum VssCmd {
    Stop(),
    PushVisas(Vec<Visa>, oneshot::Sender<VssPushResponse>),
    RevokeVisasById(Vec<u64>, oneshot::Sender<VssPushResponse>),
    RevokeAuthsByZprAddr(Vec<IpAddr>, oneshot::Sender<VssRevokeAuthResponse>),
    SetServices(
        Vec<ServiceDescriptor>,
        oneshot::Sender<VssSetServicesResponse>,
    ), // (version, services-descriptor-list, channel)
    Configure(Vec<Param>, oneshot::Sender<VssConfigureResponse>),
}
