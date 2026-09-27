use std::net::IpAddr;

use axum::http::HeaderMap;

/// Railway's edge appends its own address as the rightmost `X-Forwarded-For` hop.
/// The client the edge observed is the hop before that, so a Railway deployment
/// trusts two hops counted from the right. One hop would key Railway's proxy and
/// put every client in the same bucket.
pub const RAILWAY_TRUSTED_PROXY_HOPS: u32 = 2;

/// Client address used to key a public rate limit.
///
/// * `trusted_proxy_hops == 0` ignores forwarding headers and returns `peer`.
/// * `trusted_proxy_hops >= 1` takes the Nth `X-Forwarded-For` hop from the right,
///   the hop a trusted proxy appended. Leading entries are client-supplied and ignored.
/// * A missing or unparseable hop falls back to `X-Real-IP` (Railway overwrites it
///   with the client) and then to `peer`.
pub fn client_ip(
    peer: IpAddr,
    trusted_proxy_hops: u32,
    x_forwarded_for: Option<&str>,
    x_real_ip: Option<&str>,
) -> IpAddr {
    if trusted_proxy_hops == 0 {
        return canonicalize_ip(peer);
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
                return ip;
            }
        }
    }
    if let Some(real) = x_real_ip.and_then(parse_forwarded_hop) {
        return real;
    }
    canonicalize_ip(peer)
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
        header_str(headers, "x-real-ip"),
    )
}

/// `Some(configured)` is explicit, including zero. When the key is absent, a
/// process running on Railway trusts [`RAILWAY_TRUSTED_PROXY_HOPS`].
pub fn resolve_trusted_proxy_hops(configured: Option<u32>, railway_environment_set: bool) -> u32 {
    match configured {
        Some(hops) => hops,
        None if railway_environment_set => RAILWAY_TRUSTED_PROXY_HOPS,
        None => 0,
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn peer() -> IpAddr {
        "10.0.0.1".parse().unwrap()
    }

    #[test]
    fn hops_zero_ignores_forwarding_headers() {
        assert_eq!(
            client_ip(
                peer(),
                0,
                Some("203.0.113.10, 198.51.100.7"),
                Some("203.0.113.10")
            ),
            peer()
        );
    }

    #[test]
    fn railway_two_hops_select_the_client_not_the_appended_proxy() {
        // Railway writes "client, railway-hop". The rightmost entry is the proxy.
        let xff = "203.0.113.10, 198.51.100.7";
        let client: IpAddr = "203.0.113.10".parse().unwrap();
        let railway: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_ip(peer(), 1, Some(xff), None), railway);
        assert_eq!(client_ip(peer(), 2, Some(xff), None), client);
    }

    #[test]
    fn a_spoofed_leading_hop_does_not_change_the_railway_client() {
        let honest = client_ip(peer(), 2, Some("203.0.113.10, 198.51.100.7"), None);
        let spoofed = client_ip(
            peer(),
            2,
            Some("192.0.2.9, 203.0.113.10, 198.51.100.7"),
            None,
        );
        assert_eq!(honest, spoofed);
        assert_eq!(honest, "203.0.113.10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn too_few_xff_hops_fall_back_to_x_real_ip_then_the_peer() {
        assert_eq!(
            client_ip(peer(), 2, Some("198.51.100.7"), Some("203.0.113.10")),
            "203.0.113.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(client_ip(peer(), 2, None, None), peer());
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_embedded_address() {
        let mapped: IpAddr = "::ffff:203.0.113.10".parse().unwrap();
        assert_eq!(
            client_ip(peer(), 2, Some("::ffff:203.0.113.10, 198.51.100.7"), None),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
        assert_eq!(
            canonicalize_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn bracketed_ipv6_hop_parses() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            client_ip(peer(), 1, Some("[2001:db8::1]:443"), None),
            IpAddr::V6(v6)
        );
    }

    #[test]
    fn an_explicit_hop_count_wins_over_the_railway_default() {
        assert_eq!(resolve_trusted_proxy_hops(Some(0), true), 0);
        assert_eq!(resolve_trusted_proxy_hops(Some(2), false), 2);
        assert_eq!(
            resolve_trusted_proxy_hops(None, true),
            RAILWAY_TRUSTED_PROXY_HOPS
        );
        assert_eq!(resolve_trusted_proxy_hops(None, false), 0);
    }
}
