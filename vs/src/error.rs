use libeval::actor;
use libeval::error::EvalError;
use std::net::SocketAddr;
use thiserror::Error;

use zpr::vsapi_types::{ApiResponseError, ErrorCode, VsapiTypeError};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(#[from] toml::de::Error),

    #[error("parameter error: {0}")]
    Param(String),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("timed out: {0}")]
    Timeout(String),

    #[error("evaluation error: {0}")]
    Eval(#[from] EvalError),

    #[error("policy error: {0}")]
    Policy(#[from] libeval::policy::PolicyError),

    #[error("visa denied: {0}")]
    VisaDenied(String),

    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Capn Proto not in schema: {0}")]
    CapnpSchema(#[from] capnp::NotInSchema),

    #[error("attribute error: {0}")]
    Attribute(#[from] actor::AttributeError),

    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("error queue full: {0}")]
    QueueFull(String),

    #[error("vsapi error: {0}")]
    VsapiType(#[from] VsapiTypeError),

    #[error("admin key error: {0}")]
    AdminKeyError(String),
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("openssl error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("policy missing required details: {0}")]
    MissingRequired(String),

    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error("openssl error: {0}")]
    Tls(#[from] openssl::error::ErrorStack),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("serialization/deserialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("attribute error: {0}")]
    Attribute(#[from] actor::AttributeError),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("vsapi error: {0}")]
    VsapiType(#[from] VsapiTypeError),
}

#[derive(Debug, Error)]
pub enum VssSyncError {
    #[error("internal error: {0}")]
    Internal(String),

    #[error("queue full: {0}")]
    QueueFull(String),

    #[error("vss connection closed")]
    ConnClosed,

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("vsapi error: {0}")]
    VsapiType(#[from] VsapiTypeError),

    #[error("api response error: {0:?} ({1}, retry {2})")]
    ApiResponse(ErrorCode, String, u32),

    #[error("duplicate vss worker for {0}")]
    DuplicateWorker(SocketAddr),

    #[error("timeout: {0}")]
    Timeout(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum TopologyError {
    #[error("node already exists: {0}")]
    NodeExists(String),

    #[error("link already exists: {0}")]
    LinkExists(String),

    #[error("link to self is not allowed: {0}")]
    LinkToSelf(String),

    #[error("node not found: {0}")]
    NodeNotFound(String),
}

impl From<ApiResponseError> for VssSyncError {
    fn from(err: ApiResponseError) -> Self {
        VssSyncError::ApiResponse(err.code, err.message, err.retry_in)
    }
}
