use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

use locks_core::ids::CreatorPubky;
use time::OffsetDateTime;

use crate::client_address::rate_limit_bucket;
use crate::config::{PublicAuthorityStatusRateLimitConfig, VerificationSubmissionRateLimitConfig};

/// Upper bound on tracked public-status clients. Expired windows are dropped first.
pub const PUBLIC_AUTHORITY_STATUS_MAX_WINDOWS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerificationSubmissionRateLimitKey {
    pub client_address: IpAddr,
    pub creator: CreatorPubky,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug)]
pub struct InMemoryVerificationSubmissionRateLimiter {
    config: VerificationSubmissionRateLimitConfig,
    windows: Mutex<HashMap<VerificationSubmissionRateLimitKey, WindowCounter>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowCounter {
    started_at: OffsetDateTime,
    count: u32,
}

impl InMemoryVerificationSubmissionRateLimiter {
    pub fn new(config: VerificationSubmissionRateLimitConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(
        &self,
        key: &VerificationSubmissionRateLimitKey,
        now: OffsetDateTime,
    ) -> RateLimitDecision {
        if !self.config.enabled {
            return RateLimitDecision::allowed();
        }

        let mut windows = self.windows.lock().expect("rate limiter mutex poisoned");
        let window = windows.entry(key.clone()).or_insert(WindowCounter {
            started_at: now,
            count: 0,
        });

        if window_has_expired(window.started_at, now, self.config.window_seconds) {
            window.started_at = now;
            window.count = 0;
        }

        if window.count < self.config.max_requests {
            window.count += 1;
            return RateLimitDecision::allowed();
        }

        RateLimitDecision::rejected(retry_after_seconds(
            window.started_at,
            now,
            self.config.window_seconds,
        ))
    }
}

/// Per-client limiter for anonymous creator authority status reads.
pub struct InMemoryPublicAuthorityStatusRateLimiter {
    config: PublicAuthorityStatusRateLimitConfig,
    windows: Mutex<HashMap<IpAddr, WindowCounter>>,
    max_windows: usize,
}

impl fmt::Debug for InMemoryPublicAuthorityStatusRateLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tracked = self
            .windows
            .lock()
            .map(|windows| windows.len())
            .unwrap_or(0);
        formatter
            .debug_struct("InMemoryPublicAuthorityStatusRateLimiter")
            .field("enabled", &self.config.enabled)
            .field("max_requests", &self.config.max_requests)
            .field("window_seconds", &self.config.window_seconds)
            .field("max_windows", &self.max_windows)
            .field("tracked_clients", &tracked)
            .finish()
    }
}

impl InMemoryPublicAuthorityStatusRateLimiter {
    pub fn new(config: PublicAuthorityStatusRateLimitConfig) -> Self {
        Self::with_max_windows(config, PUBLIC_AUTHORITY_STATUS_MAX_WINDOWS)
    }

    pub fn with_max_windows(
        config: PublicAuthorityStatusRateLimitConfig,
        max_windows: usize,
    ) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
            max_windows: max_windows.max(1),
        }
    }

    pub fn tracked_clients(&self) -> usize {
        self.windows
            .lock()
            .expect("rate limiter mutex poisoned")
            .len()
    }

    pub fn check(&self, client_address: IpAddr, now: OffsetDateTime) -> RateLimitDecision {
        if !self.config.enabled {
            return RateLimitDecision::allowed();
        }
        let client_address = rate_limit_bucket(client_address);

        let mut windows = self.windows.lock().expect("rate limiter mutex poisoned");
        if let Some(window) = windows.get_mut(&client_address) {
            if window_has_expired(window.started_at, now, self.config.window_seconds) {
                window.started_at = now;
                window.count = 0;
            }
            if window.count < self.config.max_requests {
                window.count += 1;
                return RateLimitDecision::allowed();
            }
            return RateLimitDecision::rejected(retry_after_seconds(
                window.started_at,
                now,
                self.config.window_seconds,
            ));
        }

        evict_public_status_windows(
            &mut windows,
            now,
            self.config.window_seconds,
            self.max_windows,
        );
        windows.insert(
            client_address,
            WindowCounter {
                started_at: now,
                count: 1,
            },
        );
        RateLimitDecision::allowed()
    }
}

fn evict_public_status_windows(
    windows: &mut HashMap<IpAddr, WindowCounter>,
    now: OffsetDateTime,
    window_seconds: u64,
    max_windows: usize,
) {
    if windows.len() < max_windows {
        return;
    }
    windows.retain(|_, window| !window_has_expired(window.started_at, now, window_seconds));
    while windows.len() >= max_windows {
        let oldest = windows
            .iter()
            .min_by_key(|(_, window)| window.started_at)
            .map(|(address, _)| *address);
        let Some(oldest) = oldest else {
            break;
        };
        windows.remove(&oldest);
    }
}

impl RateLimitDecision {
    fn allowed() -> Self {
        Self {
            allowed: true,
            retry_after_seconds: None,
        }
    }

    fn rejected(retry_after_seconds: u64) -> Self {
        Self {
            allowed: false,
            retry_after_seconds: Some(retry_after_seconds),
        }
    }
}

fn window_has_expired(
    started_at: OffsetDateTime,
    now: OffsetDateTime,
    window_seconds: u64,
) -> bool {
    retry_after_seconds(started_at, now, window_seconds) == 0
}

fn retry_after_seconds(
    started_at: OffsetDateTime,
    now: OffsetDateTime,
    window_seconds: u64,
) -> u64 {
    let elapsed = (now - started_at).whole_seconds();
    if elapsed < 0 {
        return window_seconds;
    }
    window_seconds.saturating_sub(elapsed as u64)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use locks_core::ids::CreatorPubky;
    use time::macros::datetime;

    use super::{
        InMemoryPublicAuthorityStatusRateLimiter, InMemoryVerificationSubmissionRateLimiter,
        VerificationSubmissionRateLimitKey,
    };
    use crate::config::{
        PublicAuthorityStatusRateLimitConfig, VerificationSubmissionRateLimitConfig,
    };

    #[test]
    fn allows_requests_under_limit() {
        let limiter = limiter(2, 60);
        let key = key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            [127, 0, 0, 1],
        );
        let now = datetime!(2026-06-03 12:00:00 UTC);

        let first = limiter.check(&key, now);
        let second = limiter.check(&key, now);

        assert!(first.allowed);
        assert_eq!(first.retry_after_seconds, None);
        assert!(second.allowed);
        assert_eq!(second.retry_after_seconds, None);
    }

    #[test]
    fn rejects_request_after_limit_until_window_resets() {
        let limiter = limiter(2, 60);
        let key = key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            [127, 0, 0, 1],
        );
        let now = datetime!(2026-06-03 12:00:00 UTC);

        assert!(limiter.check(&key, now).allowed);
        assert!(limiter.check(&key, now).allowed);
        let rejected = limiter.check(&key, now);

        assert!(!rejected.allowed);
        assert_eq!(rejected.retry_after_seconds, Some(60));

        let reset = limiter.check(&key, now + time::Duration::seconds(60));

        assert!(reset.allowed);
        assert_eq!(reset.retry_after_seconds, None);
    }

    #[test]
    fn disabled_rate_limiter_always_allows() {
        let limiter =
            InMemoryVerificationSubmissionRateLimiter::new(VerificationSubmissionRateLimitConfig {
                enabled: false,
                max_requests: 0,
                window_seconds: 0,
            });
        let key = key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            [127, 0, 0, 1],
        );
        let now = datetime!(2026-06-03 12:00:00 UTC);

        for _ in 0..10 {
            let decision = limiter.check(&key, now);
            assert!(decision.allowed);
            assert_eq!(decision.retry_after_seconds, None);
        }
    }

    #[test]
    fn separate_creators_have_separate_windows() {
        let limiter = limiter(1, 60);
        let first_creator = key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            [127, 0, 0, 1],
        );
        let second_creator = key(
            "pubkyorhzqdiexwmi6iidktucgud63ufa5nwtsuzdxe176a8izd6jsqky",
            [127, 0, 0, 1],
        );
        let now = datetime!(2026-06-03 12:00:00 UTC);

        assert!(limiter.check(&first_creator, now).allowed);
        assert!(!limiter.check(&first_creator, now).allowed);
        assert!(limiter.check(&second_creator, now).allowed);
    }

    #[test]
    fn separate_client_addresses_have_separate_windows() {
        let limiter = limiter(1, 60);
        let first_client = key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            [127, 0, 0, 1],
        );
        let second_client = key(
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            [127, 0, 0, 2],
        );
        let now = datetime!(2026-06-03 12:00:00 UTC);

        assert!(limiter.check(&first_client, now).allowed);
        assert!(!limiter.check(&first_client, now).allowed);
        assert!(limiter.check(&second_client, now).allowed);
    }

    #[test]
    fn public_status_windows_stay_within_the_cap() {
        let limiter = InMemoryPublicAuthorityStatusRateLimiter::with_max_windows(
            PublicAuthorityStatusRateLimitConfig {
                enabled: true,
                max_requests: 1,
                window_seconds: 60,
            },
            2,
        );
        let now = datetime!(2026-06-03 12:00:00 UTC);
        assert!(
            limiter
                .check(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), now)
                .allowed
        );
        assert!(
            limiter
                .check(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), now)
                .allowed
        );
        assert!(
            limiter
                .check(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), now)
                .allowed
        );
        assert_eq!(limiter.tracked_clients(), 2);
        let rendered = format!("{limiter:?}");
        assert!(!rendered.contains("203.0.113"));
        assert!(rendered.contains("tracked_clients"));
    }

    #[test]
    fn public_status_ipv6_keys_share_a_64() {
        let limiter =
            InMemoryPublicAuthorityStatusRateLimiter::new(PublicAuthorityStatusRateLimitConfig {
                enabled: true,
                max_requests: 1,
                window_seconds: 60,
            });
        let now = datetime!(2026-06-03 12:00:00 UTC);
        let left: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let right: IpAddr = "2001:db8:1:2::abcd".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(limiter.check(left, now).allowed);
        assert!(!limiter.check(right, now).allowed);
        assert!(limiter.check(other, now).allowed);
    }

    fn limiter(
        max_requests: u32,
        window_seconds: u64,
    ) -> InMemoryVerificationSubmissionRateLimiter {
        InMemoryVerificationSubmissionRateLimiter::new(VerificationSubmissionRateLimitConfig {
            enabled: true,
            max_requests,
            window_seconds,
        })
    }

    fn key(creator: &str, ip_octets: [u8; 4]) -> VerificationSubmissionRateLimitKey {
        VerificationSubmissionRateLimitKey {
            client_address: IpAddr::V4(Ipv4Addr::from(ip_octets)),
            creator: CreatorPubky::from_str(creator).unwrap(),
        }
    }
}
