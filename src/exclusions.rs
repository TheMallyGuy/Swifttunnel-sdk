//! User-configured URL/host exclusions.
//!
//! Traffic destined to any of these hosts is **never** tunneled — it always
//! bypasses the relay, overriding process- and destination-based tunnel rules.
//!
//! Because packet routing happens at the IP layer (we can't see the URL/SNI of
//! an outbound packet cheaply), the configured URLs/domains are resolved to
//! IPv4 addresses at connect time and stored in a global set. The classifier
//! checks the packet's destination IP against that set.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{OnceLock, RwLock};

static EXCLUDED_IPS: OnceLock<RwLock<HashMap<Ipv4Addr, String>>> = OnceLock::new();

fn excluded_ips() -> &'static RwLock<HashMap<Ipv4Addr, String>> {
    EXCLUDED_IPS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Whether `ip` belongs to a user-excluded URL/host. Hot path: returns early
/// when no exclusions are configured.
#[inline]
pub fn is_excluded_ip(ip: Ipv4Addr) -> bool {
    excluded_ips()
        .read()
        .map(|s| !s.is_empty() && s.contains_key(&ip))
        .unwrap_or(false)
}

/// The excluded hostname an IP was resolved from, if any (for the URL log).
pub fn host_for_ip(ip: Ipv4Addr) -> Option<String> {
    excluded_ips().read().ok().and_then(|m| m.get(&ip).cloned())
}

fn set_excluded_ips(ips: HashMap<Ipv4Addr, String>) {
    if let Ok(mut guard) = excluded_ips().write() {
        *guard = ips;
    }
}

/// Clear all exclusions (called on disconnect).
pub fn clear() {
    if let Ok(mut guard) = excluded_ips().write() {
        guard.clear();
    }
}

/// Extract the bare host from a URL or `host[:port]` string.
///
/// Accepts `example.com`, `https://example.com/path?x=1`, `example.com:443`,
/// and raw IP literals. Returns lowercase host, or `None` if empty.
pub fn extract_host(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    // Strip scheme (e.g. "https://").
    if let Some(idx) = s.find("://") {
        s = &s[idx + 3..];
    }
    // Strip userinfo (e.g. "user@host").
    if let Some(idx) = s.find('@') {
        s = &s[idx + 1..];
    }
    // Cut at the first path / query / fragment separator.
    s = s
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    // Strip a trailing ":port" (but keep bare IPv6-less hosts intact).
    if let Some(idx) = s.rfind(':') {
        // Only treat as port if everything after ':' is digits.
        if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) && idx + 1 < s.len() {
            s = &s[..idx];
        }
    }
    let host = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Glob match: `*` matches any (possibly empty) run of characters. Used for
/// wildcard host patterns like `*.roblox.com` or `presence.*`.
pub fn glob_match(text: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return text == pattern;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    // Anchor the leading literal (empty if pattern starts with '*').
    if !text.starts_with(parts[0]) {
        return false;
    }
    let mut pos = parts[0].len();
    for part in &parts[1..parts.len() - 1] {
        match text[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    // Anchor the trailing literal (empty if pattern ends with '*').
    let last = parts[parts.len() - 1];
    text[pos..].ends_with(last)
}

/// Resolve a single concrete host (or IP literal) into IPv4 addresses, mapping
/// each resolved IP to `display` (the original URL/pattern the user entered, so
/// the URL log can show the full path).
async fn resolve_host_into(host: &str, display: &str, ips: &mut HashMap<Ipv4Addr, String>) {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        ips.insert(ip, display.to_string());
        return;
    }
    match tokio::net::lookup_host(format!("{host}:0")).await {
        Ok(addrs) => {
            let mut found = 0usize;
            for addr in addrs {
                if let IpAddr::V4(v4) = addr.ip() {
                    ips.insert(v4, display.to_string());
                    found += 1;
                }
            }
            if found == 0 {
                log::warn!("exclusions: '{}' resolved to no IPv4 addresses", host);
            }
        }
        Err(e) => log::warn!("exclusions: failed to resolve '{}': {}", host, e),
    }
}

/// Resolve the given URLs/hosts to IPv4 addresses and publish them as the
/// active exclusion set. Best-effort: unresolvable entries are logged and
/// skipped. Returns the number of IPs published.
///
/// Each entry may be:
/// - a concrete host/URL: `presence.roblox.com`, `https://presence.roblox.com/*`
/// - an IPv4 literal: `1.2.3.4`
/// - a wildcard host: `*.roblox.com`, `presence.*` — since arbitrary subdomains
///   can't be enumerated, wildcards are expanded against the known Roblox host
///   list and any concrete hosts also present in `urls`, then resolved.
pub async fn resolve_and_set(urls: &[String]) -> usize {
    if urls.is_empty() {
        clear();
        return 0;
    }

    // Build the candidate universe used to expand wildcard patterns: the known
    // Roblox bootstrap hosts plus any concrete (non-wildcard) hosts the caller
    // listed (so `*.roblox.com` + `presence.roblox.com` both contribute).
    let mut candidate_hosts: Vec<String> = crate::roblox_proxy::hosts::ROBLOX_BOOTSTRAP_DOMAINS
        .iter()
        .map(|d| d.to_string())
        .collect();
    for raw in urls {
        if let Some(h) = extract_host(raw) {
            if !h.contains('*') && !candidate_hosts.contains(&h) {
                candidate_hosts.push(h);
            }
        }
    }

    let mut ips: HashMap<Ipv4Addr, String> = HashMap::new();
    // host -> display URL (original pattern the user entered, kept for the log).
    let mut hosts_to_resolve: HashMap<String, String> = HashMap::new();

    for raw in urls {
        let display = raw.trim().to_string();
        let Some(host) = extract_host(raw) else {
            continue;
        };

        if host.contains('*') {
            // Wildcard: expand against the candidate host universe.
            let mut matched = 0usize;
            for cand in &candidate_hosts {
                if !cand.contains('*') && glob_match(cand, &host) {
                    hosts_to_resolve
                        .entry(cand.clone())
                        .or_insert_with(|| display.clone());
                    matched += 1;
                }
            }
            if matched == 0 {
                log::warn!(
                    "exclusions: wildcard '{}' matched no known hosts (only known Roblox hosts and listed hosts can be expanded)",
                    host
                );
            }
        } else {
            hosts_to_resolve.entry(host).or_insert(display);
        }
    }

    for (host, display) in &hosts_to_resolve {
        resolve_host_into(host, display, &mut ips).await;
    }

    let count = ips.len();
    log::info!(
        "exclusions: {} URL(s) -> {} host(s) -> {} excluded IP(s)",
        urls.len(),
        hosts_to_resolve.len(),
        count
    );
    set_excluded_ips(ips);
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_variants() {
        assert_eq!(extract_host("example.com").as_deref(), Some("example.com"));
        assert_eq!(
            extract_host("https://Example.com/path?q=1").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_host("http://user@host.test:8080/x").as_deref(),
            Some("host.test")
        );
        assert_eq!(extract_host("1.2.3.4:443").as_deref(), Some("1.2.3.4"));
        assert_eq!(extract_host("  discord.com.  ").as_deref(), Some("discord.com"));
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("https://"), None);
    }

    #[test]
    fn extract_host_keeps_wildcards() {
        assert_eq!(extract_host("*.roblox.com").as_deref(), Some("*.roblox.com"));
        assert_eq!(
            extract_host("https://presence.roblox.com/*").as_deref(),
            Some("presence.roblox.com")
        );
        assert_eq!(extract_host("presence.*").as_deref(), Some("presence.*"));
    }

    #[test]
    fn glob_match_patterns() {
        assert!(glob_match("presence.roblox.com", "*.roblox.com"));
        assert!(glob_match("chat.roblox.com", "*.roblox.com"));
        assert!(!glob_match("roblox.com.evil.test", "*.roblox.com"));
        assert!(glob_match("presence.roblox.com", "presence.*"));
        assert!(glob_match("presence.roblox.com", "*roblox*"));
        assert!(glob_match("presence.roblox.com", "presence.roblox.com"));
        assert!(!glob_match("games.roblox.com", "presence.*"));
    }

    #[test]
    fn excluded_ip_roundtrip() {
        let ip = Ipv4Addr::new(9, 9, 9, 9);
        set_excluded_ips([(ip, "example.com".to_string())].into_iter().collect());
        assert!(is_excluded_ip(ip));
        assert_eq!(host_for_ip(ip).as_deref(), Some("example.com"));
        assert!(!is_excluded_ip(Ipv4Addr::new(9, 9, 9, 10)));
        clear();
        assert!(!is_excluded_ip(ip));
    }
}
