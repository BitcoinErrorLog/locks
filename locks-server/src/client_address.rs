use std::net::{IpAddr, Ipv6Addr};

use axum::http::HeaderMap;

/// Hop count measured on paykit-server's Railway edge on 2026-09-22: `X-Forwarded-For`
/// was `client, railway-hop`, and a spoofed leading value stayed in the real client's bucket
/// when two hops were trusted. Locks does not apply that count automatically. There is no
/// header capture for a locks deployment, and the TCP peer behind Railway is one shared
/// address, so the public status limit stays off until an operator sets a hop count.
pub const RAILWAY_TRUSTED_PROXY_HOPS: u32 = 2;

/// Set to `1` or `true` to log the `X-Forwarded-For` hop count for
/// `GET /creators/{creator}/authority-status`. The line is the count only.
pub const FORWARDED_HOP_COUNT_LOG_ENV: &str = "PUBKY_LOCK_LOG_FORWARDED_HOP_COUNT";

/// Client key for the public authority-status limit.
///
/// * `trusted_proxy_hops == 0` returns nothing. The TCP peer is not a key.
/// * `trusted_proxy_hops >= 1` takes the Nth `X-Forwarded-For` hop from the right.
///   Leading entries are ignored. A missing, short, or unparseable chain returns nothing,
///   not the peer.
/// * `X-Real-IP` is never a key.
/// * IPv6 keys are the `/64` prefix. IPv4-mapped IPv6 is the embedded IPv4 address.
pub fn public_status_client_key(
    trusted_proxy_hops: u32,
    x_forwarded_for: Option<&str>,
) -> Option<IpAddr> {
    if trusted_proxy_hops == 0 {
        return None;
    }
    let hops: Vec<&str> = x_forwarded_for?
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if hops.len() < trusted_proxy_hops as usize {
        return None;
    }
    let index = hops.len() - trusted_proxy_hops as usize;
    parse_forwarded_hop(hops[index]).map(rate_limit_bucket)
}

pub fn public_status_client_key_from_headers(
    trusted_proxy_hops: u32,
    headers: &HeaderMap,
) -> Option<IpAddr> {
    public_status_client_key(trusted_proxy_hops, header_str(headers, "x-forwarded-for"))
}

pub fn forwarded_hop_count_log_enabled_from_env() -> bool {
    std::env::var(FORWARDED_HOP_COUNT_LOG_ENV)
        .map(|value| {
            let value = value.trim();
            value == "1" || value.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

pub fn forwarded_hop_count(x_forwarded_for: Option<&str>) -> u32 {
    let Some(xff) = x_forwarded_for else {
        return 0;
    };
    u32::try_from(
        xff.split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .count(),
    )
    .unwrap_or(u32::MAX)
}

/// Diagnostic line for verifying a deployment's proxy chain. Absent unless `enabled`.
/// The event field is the hop count. The header value is not recorded.
pub fn log_forwarded_hop_count(enabled: bool, headers: &HeaderMap) {
    if !enabled {
        return;
    }
    let forwarded_hop_count = forwarded_hop_count(header_str(headers, "x-forwarded-for"));
    tracing::info!(
        forwarded_hop_count,
        "public authority status x-forwarded-for hop count"
    );
}

/// Explicit configuration wins, including zero. A missing key is zero.
/// `railway_environment_set` does not change the result: this service has no
/// captured proxy chain to infer a hop count from.
pub fn resolve_trusted_proxy_hops(configured: Option<u32>, railway_environment_set: bool) -> u32 {
    let _ = railway_environment_set;
    configured.unwrap_or(0)
}

/// Bucket key. IPv4 is itself. IPv6 is its `/64` network address.
pub fn rate_limit_bucket(ip: IpAddr) -> IpAddr {
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            ))
        }
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn parse_forwarded_hop(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim().trim_matches('"').trim_matches('\'');
    let raw = raw
        .strip_prefix("for=")
        .or_else(|| raw.strip_prefix("For="))
        .unwrap_or(raw)
        .trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("unknown") {
        return None;
    }
    let unbracketed = raw
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next())
        .unwrap_or(raw);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Some(canonicalize_ip(ip));
    }
    if let Some((host, port)) = unbracketed.rsplit_once(':')
        && !host.contains(':')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && let Ok(ip) = host.parse::<IpAddr>()
    {
        return Some(canonicalize_ip(ip));
    }
    None
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn hops_zero_is_not_a_client_key() {
        assert_eq!(
            public_status_client_key(0, Some("203.0.113.10, 198.51.100.7")),
            None
        );
    }

    #[test]
    fn an_explicit_two_hops_select_the_client_not_the_appended_proxy() {
        let xff = "203.0.113.10, 198.51.100.7";
        let client: IpAddr = "203.0.113.10".parse().unwrap();
        let railway: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(public_status_client_key(1, Some(xff)), Some(railway));
        assert_eq!(public_status_client_key(2, Some(xff)), Some(client));
    }

    #[test]
    fn a_spoofed_leading_hop_does_not_change_an_explicit_two_hop_key() {
        let honest = public_status_client_key(2, Some("203.0.113.10, 198.51.100.7"));
        let spoofed = public_status_client_key(2, Some("192.0.2.9, 203.0.113.10, 198.51.100.7"));
        assert_eq!(honest, spoofed);
        assert_eq!(honest, Some("203.0.113.10".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn a_short_xff_is_not_a_client_key_and_x_real_ip_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.10".parse().unwrap());
        assert_eq!(public_status_client_key_from_headers(2, &headers), None);
        assert_eq!(public_status_client_key(2, None), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_embedded_address() {
        let mapped: IpAddr = "::ffff:203.0.113.10".parse().unwrap();
        assert_eq!(
            public_status_client_key(2, Some("::ffff:203.0.113.10, 198.51.100.7")),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
        assert_eq!(
            canonicalize_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn ipv6_clients_in_one_prefix_share_a_bucket() {
        let left = public_status_client_key(1, Some("[2001:db8:1:2::1]:443"));
        let right = public_status_client_key(1, Some("2001:db8:1:2::abcd"));
        let other = public_status_client_key(1, Some("2001:db8:1:3::1"));
        let prefix: IpAddr = "2001:db8:1:2::".parse().unwrap();
        assert_eq!(left, Some(prefix));
        assert_eq!(right, Some(prefix));
        assert_ne!(other, Some(prefix));
    }

    #[test]
    fn forwarded_hop_count_log_records_the_count_and_not_the_addresses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.10, 198.51.100.7".parse().unwrap(),
        );
        let (writer, buf) = SharedBuf::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(writer)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_forwarded_hop_count(false, &headers);
            log_forwarded_hop_count(true, &headers);
        });
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(text.contains("forwarded_hop_count=2"));
        assert!(!text.contains("203.0.113.10"));
        assert!(!text.contains("198.51.100.7"));
        assert_eq!(text.matches("hop count").count(), 1);
    }

    #[test]
    fn railway_environment_does_not_select_a_hop_count() {
        assert_eq!(resolve_trusted_proxy_hops(Some(0), true), 0);
        assert_eq!(
            resolve_trusted_proxy_hops(Some(RAILWAY_TRUSTED_PROXY_HOPS), false),
            2
        );
        assert_eq!(resolve_trusted_proxy_hops(None, true), 0);
        assert_eq!(resolve_trusted_proxy_hops(None, false), 0);
    }

    #[derive(Clone)]
    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl SharedBuf {
        fn new() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (Self(std::sync::Arc::clone(&buf)), buf)
        }
    }

    impl std::io::Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
}
