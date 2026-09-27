use std::net::{IpAddr, Ipv6Addr};

use axum::http::HeaderMap;

/// Hop count measured on paykit-server's Railway edge on 2026-09-22: `X-Forwarded-For`
/// was `client, railway-hop`, and a spoofed leading value stayed in the real client's bucket
/// when two hops were trusted. Locks does not apply that count automatically. There is no
/// header capture for a locks deployment, and `X-Real-IP` was not shown to be overwrite-only,
/// so the default key is the TCP peer.
pub const RAILWAY_TRUSTED_PROXY_HOPS: u32 = 2;

/// Client address used to key a public rate limit.
///
/// * `trusted_proxy_hops == 0` ignores forwarding headers and returns the peer.
///   That is the default, including when `RAILWAY_ENVIRONMENT` is set.
/// * `trusted_proxy_hops >= 1` takes the Nth `X-Forwarded-For` hop from the right.
///   Leading entries are ignored. A missing, short, or unparseable chain returns the peer.
/// * `X-Real-IP` is never a key. A client can supply it when the edge does not overwrite it.
/// * IPv6 keys are the `/64` prefix. IPv4-mapped IPv6 is the embedded IPv4 address.
pub fn client_ip(peer: IpAddr, trusted_proxy_hops: u32, x_forwarded_for: Option<&str>) -> IpAddr {
    if trusted_proxy_hops == 0 {
        return rate_limit_bucket(peer);
    }
    if let Some(xff) = x_forwarded_for {
        let hops: Vec<&str> = xff
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();
        if hops.len() >= trusted_proxy_hops as usize {
            let index = hops.len() - trusted_proxy_hops as usize;
            if let Some(ip) = parse_forwarded_hop(hops[index]) {
                return rate_limit_bucket(ip);
            }
        }
    }
    rate_limit_bucket(peer)
}

pub fn client_ip_from_headers(
    peer: IpAddr,
    trusted_proxy_hops: u32,
    headers: &HeaderMap,
) -> IpAddr {
    client_ip(
        peer,
        trusted_proxy_hops,
        header_str(headers, "x-forwarded-for"),
    )
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

    fn peer() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[test]
    fn hops_zero_ignores_forwarding_headers() {
        assert_eq!(
            client_ip(peer(), 0, Some("203.0.113.10, 198.51.100.7")),
            peer()
        );
    }

    #[test]
    fn an_explicit_two_hops_select_the_client_not_the_appended_proxy() {
        let xff = "203.0.113.10, 198.51.100.7";
        let client: IpAddr = "203.0.113.10".parse().unwrap();
        let railway: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_ip(peer(), 1, Some(xff)), railway);
        assert_eq!(client_ip(peer(), 2, Some(xff)), client);
    }

    #[test]
    fn a_spoofed_leading_hop_does_not_change_an_explicit_two_hop_key() {
        let honest = client_ip(peer(), 2, Some("203.0.113.10, 198.51.100.7"));
        let spoofed = client_ip(peer(), 2, Some("192.0.2.9, 203.0.113.10, 198.51.100.7"));
        assert_eq!(honest, spoofed);
        assert_eq!(honest, "203.0.113.10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_short_xff_uses_the_peer_and_not_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.10".parse().unwrap());
        assert_eq!(client_ip_from_headers(peer(), 2, &headers), peer());
        assert_eq!(client_ip(peer(), 2, None), peer());
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_embedded_address() {
        let mapped: IpAddr = "::ffff:203.0.113.10".parse().unwrap();
        assert_eq!(
            client_ip(peer(), 2, Some("::ffff:203.0.113.10, 198.51.100.7")),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
        assert_eq!(
            canonicalize_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn ipv6_clients_in_one_prefix_share_a_bucket() {
        let left = client_ip(peer(), 1, Some("[2001:db8:1:2::1]:443"));
        let right = client_ip(peer(), 1, Some("2001:db8:1:2::abcd"));
        let other = client_ip(peer(), 1, Some("2001:db8:1:3::1"));
        let prefix: IpAddr = "2001:db8:1:2::".parse().unwrap();
        assert_eq!(left, prefix);
        assert_eq!(right, prefix);
        assert_ne!(other, prefix);
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
}
