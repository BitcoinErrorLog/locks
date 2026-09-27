use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use locks_core::ids::LockServerPubky;
use serde::Deserialize;
use thiserror::Error;

use super::defaults::DEFAULT_CREATOR_AUTHORITY_KEY_ENV;

pub const PAYKIT_CONNECT_TIMEOUT_SECONDS: u64 = 5;
pub const PAYKIT_REQUEST_TIMEOUT_SECONDS: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockServerRuntimeConfig {
    pub bind_addr: SocketAddr,
    pub credentials: LockServerCredentialsConfig,
    pub database: DatabaseConfig,
    pub worker: WorkerConfig,
    pub runtime: RuntimeConfig,
    pub creator_authority_acquisition: CreatorAuthorityAcquisitionConfig,
    pub secrets: SecretsConfig,
    pub logging: LoggingConfig,
    pub pubky: PubkyConfig,
    pub pkdns: PkdnsConfig,
    pub rate_limits: RateLimitsConfig,
    pub content_locks: ContentLocksConfig,
    pub authority_revalidation: AuthorityRevalidationConfig,
    pub paykit: Option<PaykitConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaykitConfig {
    pub server_url: String,
    pub minimum_confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLocksConfig {
    pub max_resource_bytes: usize,
    pub max_resources: usize,
    pub max_total_resource_bytes: u64,
}

impl Default for ContentLocksConfig {
    fn default() -> Self {
        Self {
            max_resource_bytes: 10_000_000,
            max_resources: 10,
            max_total_resource_bytes: 100_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubkyConfig {
    pub network: PubkyNetwork,
    pub resolution: PubkyResolution,
    pub pkarr_relays: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PubkyNetwork {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PubkyResolution {
    #[default]
    Default,
    RelayOnly,
}

impl Default for PubkyConfig {
    fn default() -> Self {
        Self {
            network: PubkyNetwork::Testnet,
            resolution: PubkyResolution::Default,
            pkarr_relays: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkdnsConfig {
    pub public_ip: IpAddr,
    pub public_pubky_tls_port: Option<u16>,
    pub public_icann_http_port: Option<u16>,
    pub icann_domain: Option<String>,
    pub key_republisher_interval_seconds: u64,
}

impl Default for PkdnsConfig {
    fn default() -> Self {
        Self {
            public_ip: "127.0.0.1".parse().expect("static loopback IP is valid"),
            public_pubky_tls_port: Some(6287),
            public_icann_http_port: Some(80),
            icann_domain: Some("localhost".to_owned()),
            key_republisher_interval_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsConfig {
    pub creator_authority_key_env: String,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            creator_authority_key_env: DEFAULT_CREATOR_AUTHORITY_KEY_ENV.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatorAuthorityAcquisitionConfig {
    pub enabled: bool,
    pub method: CreatorAuthorityAcquisitionMethod,
    pub frontend_session_ttl_seconds: u64,
    pub frontend_session_code_ttl_seconds: u64,
    pub legacy_connect: LegacyConnectAcquisitionConfig,
    /// Offers a Bitkit-compatible `signin_grant` QR beside the legacy cookie QR when set.
    pub grant_connect: Option<GrantConnectAcquisitionConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyConnectAcquisitionConfig {
    pub allowed_return_origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantConnectAcquisitionConfig {
    /// Grant `client_id`: the Lock Server's public hostname. Display identity for the
    /// signer only; `allowed_return_origins` stays the return gate.
    pub client_id: String,
}

impl Default for CreatorAuthorityAcquisitionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            method: CreatorAuthorityAcquisitionMethod::LegacyConnect,
            frontend_session_ttl_seconds: 86_400,
            frontend_session_code_ttl_seconds: 120,
            legacy_connect: LegacyConnectAcquisitionConfig {
                allowed_return_origins: Vec::new(),
            },
            grant_connect: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CreatorAuthorityAcquisitionMethod {
    LegacyConnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub run_migrations_on_startup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    pub enabled: bool,
    pub poll_interval_ms: u64,
    pub claim_timeout_seconds: u64,
    pub worker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub environment: RuntimeEnvironment,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RateLimitsConfig {
    pub verification_submission: VerificationSubmissionRateLimitConfig,
    pub public_authority_status: PublicAuthorityStatusRateLimitConfig,
    /// `X-Forwarded-For` hops trusted from the right. Zero, the default, uses the TCP peer.
    /// Set this only after a header capture on this deployment. Locks does not infer a hop
    /// count from `RAILWAY_ENVIRONMENT`.
    pub trusted_proxy_hops: u32,
}

/// Anonymous `GET /creators/{creator}/authority-status` admission limit.
///
/// The default window admits a Shop settings page, a reload, and a few extra tabs
/// without refusing a person, and still stops one client from reading the route in a loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAuthorityStatusRateLimitConfig {
    pub enabled: bool,
    pub max_requests: u32,
    pub window_seconds: u64,
}

impl Default for PublicAuthorityStatusRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_requests: 120,
            window_seconds: 60,
        }
    }
}

/// Background pass that re-runs the real authority check on stale rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRevalidationConfig {
    pub enabled: bool,
    /// Rows whose last real check is older than this are due.
    pub stale_after_hours: u64,
    /// Creators contacted per pass.
    pub batch_size: u32,
    /// Homeserver checks in flight during a pass.
    pub concurrency: u32,
    /// Delay between starting checks in one pass.
    pub stagger_ms: u64,
    /// Delay between passes.
    pub poll_interval_seconds: u64,
    /// First delay after a check that did not honor the authority.
    pub retry_base_seconds: u64,
    /// Upper bound, in hours, on that delay.
    pub retry_cap_hours: u64,
}

impl Default for AuthorityRevalidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stale_after_hours: 6,
            batch_size: 4,
            concurrency: 1,
            stagger_ms: 1_000,
            poll_interval_seconds: 60,
            retry_base_seconds: 3_600,
            retry_cap_hours: 24,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationSubmissionRateLimitConfig {
    pub enabled: bool,
    pub max_requests: u32,
    pub window_seconds: u64,
}

impl Default for VerificationSubmissionRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_requests: 60,
            window_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeEnvironment {
    Development,
    Staging,
    Production,
}

impl RuntimeEnvironment {
    pub fn is_development(self) -> bool {
        self == Self::Development
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockServerCredentialsConfig {
    pub lock_server_secret_key: PathBuf,
    pub lock_server_public_key: LockServerPubky,
    pub max_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigPathResolution {
    LoadExisting {
        config_path: PathBuf,
    },
    InitializeDefault {
        config_path: PathBuf,
        service_home: PathBuf,
        secret_path: PathBuf,
    },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("custom config file does not exist: {0}")]
    MissingCustomConfig(PathBuf),
    #[error("config file path has no parent directory: {0}")]
    ConfigPathHasNoParent(PathBuf),
    #[error("failed to read config file {path}: {source}")]
    ReadConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "credentials.lock_server_public_key must be a valid Lock Server Pubky, not a placeholder"
    )]
    PlaceholderPublicKey,
    #[error("invalid credentials.lock_server_public_key: {0}")]
    InvalidPublicKey(#[from] locks_core::ids::IdParseError),
    #[error("unsupported path expansion in {field}: {value}")]
    UnsupportedPathExpansion { field: &'static str, value: String },
    #[error("failed to create service home {path}: {source}")]
    CreateServiceHome {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write generated config file {path}: {source}")]
    WriteGeneratedConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("configured secret file does not exist: {0}")]
    MissingConfiguredSecret(PathBuf),
    #[error(
        "credentials.lock_server_public_key does not match public key derived from configured secret"
    )]
    PublicKeyMismatch,
    #[error("failed to generate lock server secret {path}: {message}")]
    GenerateSecret { path: PathBuf, message: String },
    #[error("failed to derive lock server public key from {path}: {message}")]
    DerivePublicKey { path: PathBuf, message: String },
    #[error("HOME is not set")]
    MissingHome,
    #[error("invalid command line: {0}")]
    InvalidArgs(String),
    #[error("database.url and database.url_env are mutually exclusive")]
    DatabaseUrlConflict,
    #[error("database config must set exactly one of database.url or database.url_env")]
    MissingDatabaseUrl,
    #[error("database.url_env environment variable is not set: {0}")]
    MissingDatabaseUrlEnv(String),
    #[error("database.max_connections must be greater than zero")]
    InvalidDatabaseMaxConnections,
    #[error("worker.poll_interval_ms must be greater than zero")]
    InvalidWorkerPollInterval,
    #[error(
        "rate_limits.verification_submission.max_requests must be greater than zero when enabled"
    )]
    InvalidVerificationSubmissionRateLimitMaxRequests,
    #[error(
        "rate_limits.verification_submission.window_seconds must be greater than zero when enabled"
    )]
    InvalidVerificationSubmissionRateLimitWindow,
    #[error(
        "rate_limits.public_authority_status.max_requests must be greater than zero when enabled"
    )]
    InvalidPublicAuthorityStatusRateLimitMaxRequests,
    #[error(
        "rate_limits.public_authority_status.window_seconds must be greater than zero when enabled"
    )]
    InvalidPublicAuthorityStatusRateLimitWindow,
    #[error("authority_revalidation.stale_after_hours must be greater than zero when enabled")]
    InvalidAuthorityRevalidationStaleAfter,
    #[error("authority_revalidation.stale_after_hours is too large to represent as a duration")]
    InvalidAuthorityRevalidationStaleAfterRange,
    #[error("authority_revalidation.retry_base_seconds must be greater than zero when enabled")]
    InvalidAuthorityRevalidationRetryBase,
    #[error("authority_revalidation.retry_cap_hours must be greater than zero when enabled")]
    InvalidAuthorityRevalidationRetryCap,
    #[error("authority_revalidation.retry_cap_hours is too large to represent as a duration")]
    InvalidAuthorityRevalidationRetryCapRange,
    #[error("authority_revalidation.batch_size must be greater than zero when enabled")]
    InvalidAuthorityRevalidationBatchSize,
    #[error("authority_revalidation.concurrency must be greater than zero when enabled")]
    InvalidAuthorityRevalidationConcurrency,
    #[error("authority_revalidation.poll_interval_seconds must be greater than zero when enabled")]
    InvalidAuthorityRevalidationPollInterval,
    #[error("content_locks.max_resource_bytes must be greater than zero")]
    InvalidMaxResourceBytes,
    #[error("content_locks.max_resources must be greater than zero")]
    InvalidMaxResources,
    #[error("content_locks.max_total_resource_bytes must be greater than zero")]
    InvalidMaxTotalResourceBytes,
    #[error(
        "content_locks.max_total_resource_bytes must be at least content_locks.max_resource_bytes"
    )]
    InvalidContentLocksTotalResourceBytes,
    #[error("invalid logging.level filter: {0}")]
    InvalidLoggingLevel(String),
    #[error("secrets.creator_authority_key_env must not be empty")]
    InvalidCreatorAuthorityKeyEnv,
    #[error(
        "creator_authority_acquisition.allowed_return_origins must contain http(s) origins without path, query, or fragment: {0}"
    )]
    InvalidCreatorAuthorityAllowedReturnOrigin(String),
    #[error(
        "creator_authority_acquisition.allowed_return_origins must not be \"*\" when runtime.environment is production; list explicit origins"
    )]
    WildcardReturnOriginInProduction,
    #[error(
        "creator_authority_acquisition.grant_connect.client_id must be a hostname with an optional port, without scheme, path, query, or fragment: {0}"
    )]
    InvalidGrantConnectClientId(String),
    #[error("pubky.pkarr_relays must contain at least one relay when configured")]
    EmptyPubkyPkarrRelays,
    #[error(
        "pubky.pkarr_relays must contain valid http(s) URLs without credentials, query, or fragment"
    )]
    InvalidPubkyPkarrRelayUrl,
    #[error("paykit.server_url must be an exact HTTP(S) origin without credentials")]
    InvalidPaykitServerUrl,
    #[error(
        "paykit requires credentials.lock_server_secret_key to contain keypair-seed:<base64url-no-pad-32-byte-seed>"
    )]
    InvalidPaykitSigningSeed,
    #[error(
        "worker.claim_timeout_seconds must exceed the {request_timeout_seconds}-second Paykit request timeout when Paykit and the in-process worker are enabled"
    )]
    InvalidPaykitWorkerClaimTimeout { request_timeout_seconds: u64 },
}
