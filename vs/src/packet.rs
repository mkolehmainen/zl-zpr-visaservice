use std::net::IpAddr;

use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{PacketDesc, VsapiFiveTuple};

use crate::error::ServiceError;

pub fn make_fivetuple_tcp(
    source: IpAddr,
    dest: IpAddr,
    source_port: u16,
    dest_port: u16,
) -> Result<VsapiFiveTuple, ServiceError> {
    if (source.is_ipv4() && dest.is_ipv6()) || (source.is_ipv6() && dest.is_ipv4()) {
        return Err(ServiceError::Internal(
            "make_fivetuple_tcp: source and destination IP addresses must be of the same family"
                .into(),
        ));
    }
    let l3t = match source {
        IpAddr::V4(_) => zpr::packet_info::L3Type::Ipv4,
        IpAddr::V6(_) => zpr::packet_info::L3Type::Ipv6,
    };
    Ok(VsapiFiveTuple {
        source_addr: source,
        dest_addr: dest,
        l3_type: l3t,
        l4_protocol: ip_proto::TCP,
        source_port,
        dest_port,
    })
}

/// One-line `src:port -> dst:port proto` for logging a request's flow.
pub fn describe_five_tuple(pdesc: &PacketDesc) -> String {
    let ft = &pdesc.five_tuple;
    format!(
        "{}:{} -> {}:{} proto {}",
        ft.source_addr, ft.source_port, ft.dest_addr, ft.dest_port, ft.l4_protocol
    )
}
