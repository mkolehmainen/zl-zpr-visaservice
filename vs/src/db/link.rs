//! Redis/ValKey operations related to network topology links (edges).
//!
//! This persists the set of node-to-node link adjacencies so the in-memory
//! router graph (see `topology_mgr.rs` / `router.rs`) can be rebuilt on startup.
//! Only the undirected node pairs are stored here; link attributes and cost are
//! re-derived from policy on restore.
//!
//! This updates:
//! - topology:edges - a SET whose members are canonical undirected edges of the
//!   form "<zaddr_a>|<zaddr_b>", with the endpoints sorted so that each edge is
//!   stored exactly once regardless of insertion direction.

use std::net::IpAddr;
use std::sync::Arc;

use crate::db::{DbConnection, DbOp, ZAddr};
use crate::error::StoreError;

/// Redis SET key holding all topology edges.
const KEY_TOPOLOGY_EDGES: &str = "topology:edges";

/// Separator between the two endpoint addresses in a canonical edge member.
/// Safe because neither the dash-encoded IPv6 form nor dotted IPv4 contains '|'.
const EDGE_SEP: char = '|';

pub struct LinkRepo {
    db: Arc<dyn DbConnection>,
}

impl LinkRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        LinkRepo { db }
    }

    /// Persist an undirected edge between two nodes. Idempotent (set semantics);
    /// `add_edge(a, b)` and `add_edge(b, a)` store the same single member.
    pub async fn add_edge(&self, a: &IpAddr, b: &IpAddr) -> Result<(), StoreError> {
        self.db
            .sadd(KEY_TOPOLOGY_EDGES, &Self::canonical(a, b))
            .await?;
        Ok(())
    }

    /// Remove an undirected edge between two nodes. No-op if the edge is absent.
    pub async fn remove_edge(&self, a: &IpAddr, b: &IpAddr) -> Result<(), StoreError> {
        // TODO: replace with a dedicated `DbConnection::srem` helper when that API
        // is added, instead of going through `atomic_pipeline` for a single removal.
        self.db
            .atomic_pipeline(&[DbOp::SRem {
                set_key: KEY_TOPOLOGY_EDGES.to_string(),
                member: Self::canonical(a, b),
            }])
            .await?;
        Ok(())
    }

    /// List all persisted edges as endpoint pairs. Returns an error if any stored
    /// member is malformed.
    pub async fn list_edges(&self) -> Result<Vec<(IpAddr, IpAddr)>, StoreError> {
        let members = self.db.smembers(KEY_TOPOLOGY_EDGES).await?;
        let mut edges = Vec::with_capacity(members.len());
        for member in members {
            edges.push(Self::parse_member(&member)?);
        }
        Ok(edges)
    }

    /// Build the canonical SET member for an undirected edge: the two dash-encoded
    /// endpoint addresses sorted lexically and joined by `EDGE_SEP`, so that (a,b)
    /// and (b,a) map to the same member.
    fn canonical(a: &IpAddr, b: &IpAddr) -> String {
        let za = ZAddr::from(a).to_string();
        let zb = ZAddr::from(b).to_string();
        if za <= zb {
            format!("{za}{EDGE_SEP}{zb}")
        } else {
            format!("{zb}{EDGE_SEP}{za}")
        }
    }

    /// Parse a canonical edge member back into its two endpoint addresses.
    /// Returns `StoreError::InvalidData` if the member is not exactly two
    /// parseable, separator-joined addresses.
    fn parse_member(member: &str) -> Result<(IpAddr, IpAddr), StoreError> {
        let mut parts = member.split(EDGE_SEP);
        let (Some(a_str), Some(b_str), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(StoreError::InvalidData(format!(
                "malformed topology edge member: '{member}'"
            )));
        };
        let a = IpAddr::try_from(ZAddr::new_from_encoded(a_str)).map_err(|e| {
            StoreError::InvalidData(format!("failed to parse edge endpoint '{a_str}': {e}"))
        })?;
        let b = IpAddr::try_from(ZAddr::new_from_encoded(b_str)).map_err(|e| {
            StoreError::InvalidData(format!("failed to parse edge endpoint '{b_str}': {e}"))
        })?;
        Ok((a, b))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::FakeDb;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// add_edge then list_edges returns the stored edge.
    #[tokio::test]
    async fn test_add_and_list_edge_roundtrip() {
        let db = Arc::new(FakeDb::new());
        let repo = LinkRepo::new(db);
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");

        repo.add_edge(&a, &b).await.unwrap();

        let edges = repo.list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
        let (ea, eb) = edges[0];
        // Endpoints survive the roundtrip (order is canonical, not insertion order).
        assert!((ea == a && eb == b) || (ea == b && eb == a));
    }

    /// (a,b) and (b,a) canonicalize to the same member, so the set holds one edge.
    #[tokio::test]
    async fn test_canonical_dedup_regardless_of_order() {
        let db = Arc::new(FakeDb::new());
        let repo = LinkRepo::new(db);
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");

        repo.add_edge(&a, &b).await.unwrap();
        repo.add_edge(&b, &a).await.unwrap();

        let edges = repo.list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
    }

    /// remove_edge deletes the edge regardless of the direction it is removed in.
    #[tokio::test]
    async fn test_remove_edge() {
        let db = Arc::new(FakeDb::new());
        let repo = LinkRepo::new(db);
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");

        repo.add_edge(&a, &b).await.unwrap();
        repo.remove_edge(&b, &a).await.unwrap();

        let edges = repo.list_edges().await.unwrap();
        assert!(edges.is_empty());

        // Removing a non-existent edge is a no-op.
        repo.remove_edge(&a, &b).await.unwrap();
    }

    /// IPv4 endpoints also roundtrip correctly.
    #[tokio::test]
    async fn test_ipv4_roundtrip() {
        let db = Arc::new(FakeDb::new());
        let repo = LinkRepo::new(db);
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");

        repo.add_edge(&a, &b).await.unwrap();
        let edges = repo.list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
        let (ea, eb) = edges[0];
        assert!((ea == a && eb == b) || (ea == b && eb == a));
    }

    /// list_edges errors when a stored member is malformed.
    #[tokio::test]
    async fn test_parse_error_on_malformed_member() {
        let db = Arc::new(FakeDb::new());
        // Insert junk directly into the edges set.
        db.sadd(KEY_TOPOLOGY_EDGES, "this-is-not-an-edge")
            .await
            .unwrap();
        let repo = LinkRepo::new(db);

        let err = repo.list_edges().await.unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
