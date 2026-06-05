//! Asset-relay routing set.
//!
//! Traffic to these hosts is forwarded through a *separate* relay (a different
//! exit IP) than gameplay. This exists to dodge Roblox's per-IP rate limit
//! (HTTP 429) on `assetdelivery.roblox.com`: when many users share one gameplay
//! relay IP, asset requests get throttled. Sending asset traffic out a
//! dedicated/less-shared exit IP keeps it under the limit.
//!
//! Like [`crate::exclusions`], hosts are resolved to IPv4 at connect time and
//! the classifier matches the packet's destination IP.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{OnceLock, RwLock};

use crate::exclusions::{extract_host, glob_match};

/// Candidate hosts used to expand wildcard asset patterns (e.g. `*.rbxcdn.com`),
/// since arbitrary CDN subdomains can't be enumerated from DNS.
const ASSET_CANDIDATE_HOSTS: &[&str] = &[
    "assetdelivery.roblox.com",
    "assetgame.roblox.com",
    "c0.rbxcdn.com",
    "c1.rbxcdn.com",
    "c2.rbxcdn.com",
    "c3.rbxcdn.com",
    "c4.rbxcdn.com",
    "c5.rbxcdn.com",
    "c6.rbxcdn.com",
    "c7.rbxcdn.com",
    "t0.rbxcdn.com",
    "t1.rbxcdn.com",
    "t2.rbxcdn.com",
    "t3.rbxcdn.com",
    "t4.rbxcdn.com",
    "t5.rbxcdn.com",
    "t6.rbxcdn.com",
    "t7.rbxcdn.com",
];

static ASSET_IPS: OnceLock<RwLock<HashMap<Ipv4Addr, String>>> = OnceLock::new();

fn asset_ips() -> &'static RwLock<HashMap<Ipv4Addr, String>> {
    ASSET_IPS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Whether `ip` should be routed through the asset relay. Hot path: returns
/// early when no asset routing is configured.
#[inline]
pub fn is_asset_ip(ip: Ipv4Addr) -> bool {
    asset_ips()
        .read()
        .map(|m| !m.is_empty() && m.contains_key(&ip))
        .unwrap_or(false)
}

/// The asset host an IP was resolved from, if any (for the URL log).
pub fn host_for_ip(ip: Ipv4Addr) -> Option<String> {
    asset_ips().read().ok().and_then(|m| m.get(&ip).cloned())
}

/// Clear the asset routing set (on disconnect).
pub fn clear() {
    if let Ok(mut g) = asset_ips().write() {
        g.clear();
    }
}

fn set_asset_ips(ips: HashMap<Ipv4Addr, String>) {
    if let Ok(mut g) = asset_ips().write() {
        *g = ips;
    }
}

async fn resolve_host_into(host: &str, display: &str, ips: &mut HashMap<Ipv4Addr, String>) {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        ips.insert(ip, display.to_string());
        return;
    }
    match tokio::net::lookup_host(format!("{host}:0")).await {
        Ok(addrs) => {
            for addr in addrs {
                if let IpAddr::V4(v4) = addr.ip() {
                    ips.insert(v4, display.to_string());
                }
            }
        }
        Err(e) => log::warn!("asset_route: failed to resolve '{}': {}", host, e),
    }
}

/// Resolve the given asset URLs/hosts to IPv4 and publish them as the asset
/// routing set. Wildcards (`*.rbxcdn.com`) expand against the known asset CDN
/// host list. Returns the number of IPs published.
pub async fn resolve_and_set(urls: &[String]) -> usize {
    if urls.is_empty() {
        clear();
        return 0;
    }

    let mut candidates: Vec<String> = ASSET_CANDIDATE_HOSTS.iter().map(|s| s.to_string()).collect();
    for raw in urls {
        if let Some(h) = extract_host(raw) {
            if !h.contains('*') && !candidates.contains(&h) {
                candidates.push(h);
            }
        }
    }

    let mut ips: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut hosts_to_resolve: HashMap<String, String> = HashMap::new();

    for raw in urls {
        let display = raw.trim().to_string();
        let Some(host) = extract_host(raw) else {
            continue;
        };
        if host.contains('*') {
            let mut matched = 0usize;
            for cand in &candidates {
                if !cand.contains('*') && glob_match(cand, &host) {
                    hosts_to_resolve
                        .entry(cand.clone())
                        .or_insert_with(|| display.clone());
                    matched += 1;
                }
            }
            if matched == 0 {
                log::warn!("asset_route: wildcard '{}' matched no known asset hosts", host);
            }
        } else {
            hosts_to_resolve.entry(host).or_insert(display);
        }
    }

    let _seen: HashSet<&String> = hosts_to_resolve.keys().collect();
    for (host, display) in &hosts_to_resolve {
        resolve_host_into(host, display, &mut ips).await;
    }

    let count = ips.len();
    log::info!(
        "asset_route: {} URL(s) -> {} host(s) -> {} asset IP(s)",
        urls.len(),
        hosts_to_resolve.len(),
        count
    );
    set_asset_ips(ips);
    count
}
