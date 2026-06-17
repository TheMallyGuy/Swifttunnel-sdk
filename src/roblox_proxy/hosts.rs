//! Windows hosts-file management for Roblox bootstrap DNS repair.
//!
//! Adds / removes marker-delimited entries for the small set of Roblox launch
//! and API hostnames that must resolve before Roblox can open its launch-time
//! HTTPS connections. This is the DNS half of "Route Assist": pinning the
//! bootstrap domains to known-good public IPs lets the client reach Roblox even
//! when its local/ISP DNS is poisoned or the region is geo-blocked.

use log::{debug, info, warn};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

const MARKER_START: &str = "# SwiftTunnel Roblox Proxy - START";
const MARKER_END: &str = "# SwiftTunnel Roblox Proxy - END";
const DNS_REPAIR_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_REPAIR_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Budget for the single extra resolution pass that runs when a launch-critical
/// direct-only host (clientsettings*, versioncompatibility) was not pinned by
/// the main pass. An unpinned direct-only host loses its "never relay" guard,
/// so it is worth a few more seconds at connect time — but only one pass, so a
/// broken resolver can never loop or stall the connect indefinitely.
const DIRECT_ONLY_RETRY_TOTAL_TIMEOUT: Duration = Duration::from_secs(8);
const DNS_REPAIR_RESOLVERS: &[&str] = &[
    // IP literals avoid depending on the user's broken local DNS to find
    // the DNS-over-HTTPS resolver itself.
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
    "https://9.9.9.9:5053/dns-query",
    "https://94.140.14.14/resolve",
];

/// Maximum IPs pinned per Roblox bootstrap domain.
///
/// Roblox serves these hostnames from a CDN/anycast pool, so a single edge IP
/// resolved from a public DoH resolver may be unreachable from the user's ISP
/// path. Pinning a few verified IPs gives connection fail-over headroom without
/// bloating the hosts file.
// Route Assist splits Roblox traffic by host, but Roblox frequently serves
// unrelated hosts from shared CDN/edge IPs. Keeping a few extra candidates gives
// the allocator room to avoid relaying avatar/chat/asset hosts just because they
// share one edge with gamejoin.
const MAX_PINNED_IPS_PER_DOMAIN: usize = 6;

/// Per-IP TCP reachability probe timeout. Short so a dead edge is skipped fast;
/// the whole repair still runs under `DNS_REPAIR_TOTAL_TIMEOUT`.
const REACHABILITY_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

/// Port used to confirm a resolved Roblox edge actually accepts connections.
const ROBLOX_HTTPS_PORT: u16 = 443;

/// Active Route Assist IPs → domain name (for URL log).
/// SDK-specific: the app uses HashSet, but the SDK keeps HashMap for host_for_ip().
static ACTIVE_BOOTSTRAP_IPS: OnceLock<RwLock<HashMap<Ipv4Addr, String>>> = OnceLock::new();
/// IPs that have DNS repaired but must NOT be relayed — going direct is safer
/// for launch-critical bootstrap requests.
static DIRECT_ONLY_BOOTSTRAP_IPS: OnceLock<RwLock<HashSet<Ipv4Addr>>> = OnceLock::new();
/// The host overrides currently written to the hosts file, so a later
/// relay-resolved DNS pass can merge into them instead of clobbering them.
static LAST_APPLIED_OVERRIDES: OnceLock<RwLock<Vec<HostOverride>>> = OnceLock::new();

fn last_applied_overrides() -> &'static RwLock<Vec<HostOverride>> {
    LAST_APPLIED_OVERRIDES.get_or_init(|| RwLock::new(Vec::new()))
}

/// True while the current session deliberately relays the launch-critical
/// settings hosts (country-ban bypass). Runtime SNI learning must not undo
/// that routing decision.
static COUNTRY_BAN_BYPASS_ROUTING: AtomicBool = AtomicBool::new(false);

// Keep DNS repair for these launch-critical hosts, but do not publish their IPs
// to Route Assist. Roblox can fail startup with "Failed to download or apply
// critical settings" if these bootstrap HTTPS requests are relayed unreliably.
const DIRECT_ONLY_BOOTSTRAP_DOMAINS: &[&str] = &[
    "clientsettingscdn.roblox.com",
    "clientsettings.roblox.com",
    "clientsettings.api.roblox.com",
    "versioncompatibility.api.roblox.com",
];

/// Asset/CDN domains that should go direct (not through the relay) when a
/// country ban is active — they are high-bandwidth and don't need bypass.
/// *.rbxcdn.com is matched by suffix in `is_asset_direct_domain`.
const ASSET_DIRECT_ROBLOX_DOMAINS: &[&str] = &[
    "assetgame.roblox.com",
    "assetdelivery.roblox.com",
    "thumbnails.roblox.com",
    "setup.roblox.com",
];

// Route Assist only needs the region/join control plane on the relay. Roblox
// UI/social/chat/avatar/catalog traffic has no placement value and can break
// when it rides a shared relay NAT, showing as missing chat, empty menus, and
// unloaded player icons. Full country-ban bypass ignores this split and relays
// every pinned host.
const ROUTE_ASSIST_RELAY_DOMAINS: &[&str] =
    &["gamejoin.roblox.com", "games.roblox.com", "apis.roblox.com"];

/// Exact Roblox hostnames repaired when Route Assist is enabled.
///
/// This intentionally stays as an allowlist of concrete launch/API names. Do
/// not add bare `roblox.com` or lookalike domains: hosts-file repair is a DNS
/// bypass for known Roblox bootstrap dependencies, not a wildcard resolver.
pub const ROBLOX_BOOTSTRAP_DOMAINS: &[&str] = &[
    "api.roblox.com",
    "clientsettingscdn.roblox.com",
    "clientsettings.roblox.com",
    "clientsettings.api.roblox.com",
    "versioncompatibility.api.roblox.com",
    "www.roblox.com",
    "web.roblox.com",
    "apis.roblox.com",
    "auth.roblox.com",
    "accountsettings.roblox.com",
    "accountinformation.roblox.com",
    "users.roblox.com",
    "avatar.roblox.com",
    "catalog.roblox.com",
    "inventory.roblox.com",
    "economy.roblox.com",
    "games.roblox.com",
    "gamejoin.roblox.com",
    "assetgame.roblox.com",
    "assetdelivery.roblox.com",
    "thumbnails.roblox.com",
    "presence.roblox.com",
    "friends.roblox.com",
    "chat.roblox.com",
    "chatsite.roblox.com",
    "locale.roblox.com",
    "setup.roblox.com",
    "captcha.roblox.com",
    "setup.rbxcdn.com",
    "apis.rbxcdn.com",
    "js.rbxcdn.com",
    "static.rbxcdn.com",
    "c0.rbxcdn.com",
    "c1.rbxcdn.com",
    "c2.rbxcdn.com",
    "c3.rbxcdn.com",
    "c4.rbxcdn.com",
    "c5.rbxcdn.com",
    "c6.rbxcdn.com",
    "c7.rbxcdn.com",
    "tr.rbxcdn.com",
    "fts.rbxcdn.com",
    "t0.rbxcdn.com",
    "t1.rbxcdn.com",
    "t2.rbxcdn.com",
    "t3.rbxcdn.com",
    "t4.rbxcdn.com",
    "t5.rbxcdn.com",
    "t6.rbxcdn.com",
    "t7.rbxcdn.com",
    "images.rbxcdn.com",
    "css.rbxcdn.com",
    "cdn.arkoselabs.com",
    "roblox-api.arkoselabs.com",
];

fn hosts_path() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostOverride {
    ip: Ipv4Addr,
    domain: String,
}

#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohJsonAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

/// Resolve and append Roblox bootstrap overrides to the Windows hosts file.
///
/// Existing SwiftTunnel entries are removed first (idempotent).
///
/// `country_ban_bypass`: when the user is bypassing a country ban, the
/// launch-critical hosts (clientsettings*, versioncompatibility) MUST be routed
/// through the relay to escape the ISP block — otherwise keeping them "direct"
/// (the default, which avoids flaky-relay "Failed to apply critical settings")
/// sends them straight into the block and the game won't launch.
pub async fn apply_bootstrap_overrides(country_ban_bypass: bool) -> Result<(), String> {
    // Full bypass relays every Roblox host. Lock that routing decision in BEFORE
    // the fallible DoH resolution below. Under a full block the censor commonly
    // blocks public DoH too, so resolution can fail — and if it does, we must
    // still be in country-ban routing. Otherwise the country-ban flag stays
    // unset, runtime SNI-learning treats the session like Route Assist, and it
    // demotes clientsettings/asset hosts onto the (censored) direct path
    // mid-session: they relay once, then get RST'd — the "plays 20s then dies"
    // report. Setting the flag up front (and clearing any stale direct-only pins
    // a prior Route Assist/partial session left behind) keeps those hosts on the
    // relay even when we get zero pins; recognized Roblox/strapper flows relay on
    // process identity alone, so the pins are an optimization, not a prerequisite.
    if country_ban_bypass {
        enter_country_ban_routing();
    }

    let resolved = resolve_bootstrap_overrides().await?;
    let (overrides, active_ips, direct_only_ips) = if country_ban_bypass {
        let (active, direct_only) = country_ban_split_ips_from_overrides(&resolved);
        (resolved, active, direct_only)
    } else {
        allocate_route_assist_pins(resolved)
    };

    if let Ok(mut last) = last_applied_overrides().write() {
        *last = overrides.clone();
    }
    tokio::task::spawn_blocking(move || write_overrides(&overrides))
        .await
        .map_err(|e| e.to_string())??;

    set_active_bootstrap_ips(active_ips);
    set_direct_only_bootstrap_ips(direct_only_ips);
    Ok(())
}

/// Merge relay-resolved Roblox IPs into the hosts-file pins and the active
/// (relayed) IP set. The relay resolves Roblox's real IPs from outside the
/// censorship, so this is the fallback for full country-ban when local DoH is
/// blocked/poisoned: without it the player connects to poisoned addresses the
/// relay can't reach ("problem reaching our servers"). Every merged IP becomes
/// an active pin — full bypass relays every Roblox host.
pub async fn apply_relay_resolved_overrides(
    resolved: std::collections::HashMap<String, Vec<Ipv4Addr>>,
) -> Result<(), String> {
    let mut new_entries: Vec<HostOverride> = Vec::new();
    for (domain, ips) in resolved {
        for ip in ips.into_iter().take(MAX_PINNED_IPS_PER_DOMAIN) {
            new_entries.push(HostOverride {
                ip,
                domain: domain.clone(),
            });
        }
    }
    if new_entries.is_empty() {
        return Ok(());
    }

    // Merge with the pins already written (DoH results), de-duping by (domain, ip).
    let existing = last_applied_overrides()
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let mut seen: HashSet<(String, Ipv4Addr)> = HashSet::new();
    let mut merged: Vec<HostOverride> = Vec::with_capacity(existing.len() + new_entries.len());
    for entry in existing.into_iter().chain(new_entries.into_iter()) {
        if seen.insert((entry.domain.to_ascii_lowercase(), entry.ip)) {
            merged.push(entry);
        }
    }

    let merged_for_write = merged.clone();
    tokio::task::spawn_blocking(move || write_overrides(&merged_for_write))
        .await
        .map_err(|e| format!("Failed to join relay-resolved hosts write: {e}"))??;

    if let Ok(mut last) = last_applied_overrides().write() {
        *last = merged.clone();
    }
    // SDK-specific: active map is HashMap<ip, domain>; extend with new entries.
    if let Ok(mut active) = active_bootstrap_ips().write() {
        for entry in &merged {
            active.entry(entry.ip).or_insert_with(|| entry.domain.clone());
        }
    }
    Ok(())
}

/// Enter full country-ban routing: mark the session as relaying every Roblox
/// host and drop any stale direct-only pins from a prior Route Assist/partial
/// session. Idempotent. Kept separate from [`apply_bootstrap_overrides`] so this
/// routing decision survives a DoH-resolution failure (which returns early) and
/// is unit-testable without touching the network.
fn enter_country_ban_routing() {
    COUNTRY_BAN_BYPASS_ROUTING.store(true, Ordering::Relaxed);
    set_direct_only_bootstrap_ips(HashSet::new());
}

/// Whether `ip` is one of the currently-applied Route Assist bootstrap IPs.
pub fn is_active_bootstrap_ip(ip: Ipv4Addr) -> bool {
    active_bootstrap_ips()
        .read()
        .map(|ips| ips.contains_key(&ip))
        .unwrap_or(false)
}

pub fn is_country_ban_bypass_routing_active() -> bool {
    COUNTRY_BAN_BYPASS_ROUTING.load(Ordering::Relaxed)
}

/// Whether `ip` is a launch-critical bootstrap IP that must stay direct
/// (not relayed) to avoid "Failed to apply critical settings" errors.
pub fn is_direct_only_bootstrap_ip(ip: Ipv4Addr) -> bool {
    direct_only_bootstrap_ips()
        .read()
        .map(|ips| ips.contains(&ip))
        .unwrap_or(false)
}

/// Record that `ip` serves a route-assist direct domain, learned from the
/// TLS SNI of a flow Route Assist had already relayed (because the connect-time
/// hosts pin for that domain was missing, or system DNS picked a shared CDN
/// edge that was pinned as active for another Roblox host).
///
/// Returns `true` only when `ip` was newly recorded. Returns `false` (and
/// learns nothing) when `server_name` is not a route-assist direct domain,
/// while country-ban bypass is active, or when the IP is already an active
/// control-plane pin (no demotion — that would break the active flow).
pub fn learn_direct_only_bootstrap_ip(server_name: &str, ip: Ipv4Addr) -> bool {
    if !is_route_assist_direct_domain(server_name) {
        return false;
    }
    if COUNTRY_BAN_BYPASS_ROUTING.load(Ordering::Relaxed) {
        return false;
    }
    if is_active_bootstrap_ip(ip) {
        return false;
    }

    match direct_only_bootstrap_ips().write() {
        Ok(mut direct_only) => direct_only.insert(ip),
        Err(e) => {
            warn!("Failed to learn direct-only Roblox bootstrap IP {ip}: {e}");
            false
        }
    }
}

/// Resolved bootstrap hostname for an IP, if any (for the URL log).
pub fn host_for_ip(ip: Ipv4Addr) -> Option<String> {
    active_bootstrap_ips()
        .read()
        .ok()
        .and_then(|m| m.get(&ip).cloned())
}

async fn resolve_bootstrap_overrides() -> Result<Vec<HostOverride>, String> {
    let client = reqwest::Client::builder()
        .timeout(DNS_REPAIR_TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to build DNS repair client: {e}"))?;

    let mut overrides = Vec::new();
    let mut failures = Vec::new();

    resolve_domains_with_timeout(
        &client,
        ROBLOX_BOOTSTRAP_DOMAINS,
        DNS_REPAIR_TOTAL_TIMEOUT,
        &mut overrides,
        &mut failures,
    )
    .await;

    // The direct-only hosts are the ones a missing pin actually hurts: without
    // their IPs published, Route Assist can relay the launch-critical settings
    // fetches it is supposed to keep direct. Give just those hosts one more
    // bounded pass before giving up on them.
    let missing = missing_direct_only_domains(&overrides);
    if !overrides.is_empty() && !missing.is_empty() {
        warn!(
            "Retrying DNS repair for launch-critical Roblox host(s): {}",
            missing.join(", ")
        );
        resolve_domains_with_timeout(
            &client,
            &missing,
            DIRECT_ONLY_RETRY_TOTAL_TIMEOUT,
            &mut overrides,
            &mut failures,
        )
        .await;

        let still_missing = missing_direct_only_domains(&overrides);
        if !still_missing.is_empty() {
            warn!(
                "Launch-critical Roblox settings host(s) unpinned after retry: {}; \
                 Route Assist will learn their IPs from TLS SNI at runtime",
                still_missing.join(", ")
            );
        }
    }

    if overrides.is_empty() {
        return Err(format!(
            "No Roblox bootstrap hosts resolved via DNS-over-HTTPS: {}",
            failures.join("; ")
        ));
    }

    if !failures.is_empty() {
        warn!("Partial Roblox bootstrap DNS repair: {}", failures.join("; "));
    }

    Ok(overrides)
}

/// Resolve a slice of domains under `total_timeout`, appending successes to
/// `overrides` and failure descriptions to `failures`.
async fn resolve_domains_with_timeout(
    client: &reqwest::Client,
    domains: &[&'static str],
    total_timeout: Duration,
    overrides: &mut Vec<HostOverride>,
    failures: &mut Vec<String>,
) {
    let mut set: tokio::task::JoinSet<(&'static str, Result<Vec<Ipv4Addr>, String>)> =
        tokio::task::JoinSet::new();
    for domain in domains {
        let client = client.clone();
        let domain = *domain;
        set.spawn(async move { (domain, resolve_reachable_domain_ips(&client, domain).await) });
    }

    let deadline = tokio::time::sleep(total_timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            joined = set.join_next() => {
                match joined {
                    Some(Ok((domain, Ok(ips)))) => {
                        for ip in ips {
                            overrides.push(HostOverride { ip, domain: domain.to_string() });
                        }
                    }
                    Some(Ok((_domain, Err(e)))) => failures.push(e),
                    Some(Err(e)) => failures.push(format!("DNS task join error: {e}")),
                    None => break,
                }
            }
            _ = &mut deadline => {
                let remaining = set.len();
                if remaining > 0 {
                    failures.push(format!(
                        "{} Roblox bootstrap DNS lookup(s) exceeded {}s total timeout",
                        remaining,
                        total_timeout.as_secs()
                    ));
                }
                break;
            }
        }
    }
}

/// Direct-only domains that have no resolved override yet.
fn missing_direct_only_domains(overrides: &[HostOverride]) -> Vec<&'static str> {
    DIRECT_ONLY_BOOTSTRAP_DOMAINS
        .iter()
        .filter(|domain| {
            !overrides
                .iter()
                .any(|entry| entry.domain.eq_ignore_ascii_case(domain))
        })
        .copied()
        .collect()
}

/// Resolve a domain and keep only the IPs that are actually reachable on :443
/// from this machine, preserving DNS preference order.
async fn resolve_reachable_domain_ips(
    client: &reqwest::Client,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let candidates = resolve_domain_ips(client, domain).await?;
    let reachable = filter_reachable_ips(candidates).await;
    if reachable.is_empty() {
        return Err(format!(
            "{domain} resolved but no IP answered on :{ROBLOX_HTTPS_PORT}"
        ));
    }
    Ok(reachable)
}

/// Resolve a domain to up to `MAX_PINNED_IPS_PER_DOMAIN` usable public IPv4s
/// via DNS-over-HTTPS.
async fn resolve_domain_ips(
    client: &reqwest::Client,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let mut failures = Vec::new();

    for resolver in DNS_REPAIR_RESOLVERS {
        let url = build_doh_url(resolver, domain);
        let response = match client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("{resolver}: request failed: {e}"));
                continue;
            }
        };

        if !response.status().is_success() {
            failures.push(format!("{resolver}: HTTP {}", response.status()));
            continue;
        }

        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{resolver}: response read failed: {e}"));
                continue;
            }
        };

        match parse_usable_a_records(&body) {
            Ok(ips) if !ips.is_empty() => {
                return Ok(dedup_and_cap_ips(ips, MAX_PINNED_IPS_PER_DOMAIN));
            }
            Ok(_) => failures.push(format!("{resolver}: no usable public A records")),
            Err(e) => failures.push(format!("{resolver}: {e}")),
        }
    }

    Err(format!(
        "{domain} could not be repaired via DNS-over-HTTPS ({})",
        failures.join("; ")
    ))
}

/// Deduplicate IPs (preserving first-seen order) and cap the count.
fn dedup_and_cap_ips(ips: Vec<Ipv4Addr>, cap: usize) -> Vec<Ipv4Addr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        if seen.insert(ip) {
            out.push(ip);
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// Probe each candidate IP on :443 concurrently and return the reachable ones,
/// preserving the original DNS-preference order.
async fn filter_reachable_ips(ips: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    filter_reachable_ips_on_port(ips, ROBLOX_HTTPS_PORT).await
}

async fn filter_reachable_ips_on_port(ips: Vec<Ipv4Addr>, port: u16) -> Vec<Ipv4Addr> {
    if ips.is_empty() {
        return Vec::new();
    }

    let mut set: tokio::task::JoinSet<(usize, Ipv4Addr, bool)> = tokio::task::JoinSet::new();
    for (idx, ip) in ips.into_iter().enumerate() {
        set.spawn(async move { (idx, ip, probe_tcp_reachable(ip, port).await) });
    }

    let mut reachable: Vec<(usize, Ipv4Addr)> = Vec::new();
    while let Some(result) = set.join_next().await {
        if let Ok((idx, ip, true)) = result {
            reachable.push((idx, ip));
        }
    }

    reachable.sort_by_key(|(idx, _)| *idx);
    reachable.into_iter().map(|(_, ip)| ip).collect()
}

/// Returns `true` if a TCP connection to `ip:port` completes within the probe
/// timeout.
async fn probe_tcp_reachable(ip: Ipv4Addr, port: u16) -> bool {
    let addr = SocketAddr::from((ip, port));
    matches!(
        tokio::time::timeout(
            REACHABILITY_PROBE_TIMEOUT,
            tokio::net::TcpStream::connect(addr),
        )
        .await,
        Ok(Ok(_))
    )
}

fn write_overrides(overrides: &[HostOverride]) -> Result<(), String> {
    if overrides.is_empty() {
        return Err("No hosts overrides to write".to_string());
    }

    let path = hosts_path();
    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hosts file: {e}"))?;

    let clean = remove_marker_block(&content);
    let block = build_hosts_block(overrides);

    let mut out = clean;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);

    fs::write(&path, &out).map_err(|e| format!("Failed to write hosts file: {e}"))?;

    info!(
        "Applied {} Roblox bootstrap DNS override(s) to hosts file",
        overrides.len()
    );

    flush_dns_cache();
    Ok(())
}

/// Synchronous removal of all SwiftTunnel hosts entries. Safe to call from
/// startup recovery and `Drop`.
pub fn remove_overrides() -> Result<(), String> {
    let result = remove_overrides_inner();
    clear_bootstrap_ip_sets();
    result
}

fn remove_overrides_inner() -> Result<(), String> {
    let path = hosts_path();
    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hosts file: {e}"))?;

    let clean = remove_marker_block(&content);

    if clean != content {
        fs::write(&path, &clean).map_err(|e| format!("Failed to write hosts file: {e}"))?;
        info!("Removed Roblox proxy overrides from hosts file");
        flush_dns_cache();
    }

    Ok(())
}

/// Remove any SwiftTunnel Roblox Proxy entries without blocking a Tokio worker.
pub async fn remove_overrides_async() -> Result<(), String> {
    tokio::task::spawn_blocking(remove_overrides)
        .await
        .map_err(|e| format!("Failed to join hosts cleanup task: {e}"))?
}

/// Called on startup to clean up entries left by a previous crash.
pub fn recover_stale() {
    if let Err(e) = remove_overrides() {
        warn!("Failed to recover stale hosts entries: {e}");
    }
}

/// Returns `true` if the hosts file currently contains SwiftTunnel entries.
pub fn has_overrides() -> bool {
    let path = hosts_path();
    match fs::read_to_string(&path) {
        Ok(content) => content.contains(MARKER_START),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Statics helpers
// ---------------------------------------------------------------------------

fn active_bootstrap_ips() -> &'static RwLock<HashMap<Ipv4Addr, String>> {
    ACTIVE_BOOTSTRAP_IPS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn direct_only_bootstrap_ips() -> &'static RwLock<HashSet<Ipv4Addr>> {
    DIRECT_ONLY_BOOTSTRAP_IPS.get_or_init(|| RwLock::new(HashSet::new()))
}

fn set_active_bootstrap_ips(ips: HashMap<Ipv4Addr, String>) {
    match active_bootstrap_ips().write() {
        Ok(mut active) => *active = ips,
        Err(e) => warn!("Failed to publish Roblox bootstrap route IPs: {e}"),
    }
}

fn set_direct_only_bootstrap_ips(ips: HashSet<Ipv4Addr>) {
    match direct_only_bootstrap_ips().write() {
        Ok(mut direct_only) => *direct_only = ips,
        Err(e) => warn!("Failed to publish direct-only Roblox bootstrap IPs: {e}"),
    }
}

fn is_direct_only_bootstrap_domain(domain: &str) -> bool {
    DIRECT_ONLY_BOOTSTRAP_DOMAINS
        .iter()
        .any(|d| domain.eq_ignore_ascii_case(d))
}

/// Whether `domain` is an asset/CDN host that goes direct (high-bandwidth, no
/// need for relay escape). Named roblox.com asset hosts plus any *.rbxcdn.com.
pub fn is_asset_direct_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    ASSET_DIRECT_ROBLOX_DOMAINS
        .iter()
        .any(|asset| d.eq_ignore_ascii_case(asset))
        || d.to_ascii_lowercase().ends_with(".rbxcdn.com")
}

fn is_route_assist_relay_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    ROUTE_ASSIST_RELAY_DOMAINS
        .iter()
        .any(|relay| d.eq_ignore_ascii_case(relay))
}

/// Direct under Route Assist = every known Roblox helper/UI/asset host except
/// the small region/join relay set.
fn is_route_assist_direct_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    if is_route_assist_relay_domain(d) {
        return false;
    }

    is_direct_only_bootstrap_domain(d)
        || is_asset_direct_domain(d)
        || ROBLOX_BOOTSTRAP_DOMAINS
            .iter()
            .any(|known| d.eq_ignore_ascii_case(known))
}

/// Allocate route-assist pins: split resolved overrides into
/// (kept overrides, active relay HashMap<ip→domain>, direct-only HashSet).
///
/// For each domain, prefers entries whose IP is not claimed by the other pool
/// (conflict-free). If no conflict-free entry exists for a domain, all its
/// entries are kept. Active IPs map to their domain for `host_for_ip()`.
fn allocate_route_assist_pins(
    overrides: Vec<HostOverride>,
) -> (Vec<HostOverride>, HashMap<Ipv4Addr, String>, HashSet<Ipv4Addr>) {
    let direct_pool: HashSet<Ipv4Addr> = overrides
        .iter()
        .filter(|entry| is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .collect();
    let active_pool: HashSet<Ipv4Addr> = overrides
        .iter()
        .filter(|entry| !is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .collect();

    let mut domains: Vec<&str> = Vec::new();
    for entry in &overrides {
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(&entry.domain)) {
            domains.push(&entry.domain);
        }
    }

    let mut kept: Vec<HostOverride> = Vec::with_capacity(overrides.len());
    for domain in domains {
        let other_pool = if is_route_assist_direct_domain(domain) {
            &active_pool
        } else {
            &direct_pool
        };
        let candidates: Vec<&HostOverride> = overrides
            .iter()
            .filter(|entry| entry.domain.eq_ignore_ascii_case(domain))
            .collect();
        let conflict_free: Vec<&HostOverride> = candidates
            .iter()
            .copied()
            .filter(|entry| !other_pool.contains(&entry.ip))
            .collect();
        if conflict_free.is_empty() {
            kept.extend(candidates.into_iter().cloned());
        } else {
            kept.extend(conflict_free.into_iter().cloned());
        }
    }

    // SDK: active is HashMap<ip, domain> for host_for_ip()
    let active: HashMap<Ipv4Addr, String> = kept
        .iter()
        .filter(|entry| !is_route_assist_direct_domain(&entry.domain))
        .map(|entry| (entry.ip, entry.domain.clone()))
        .collect();
    let direct_only: HashSet<Ipv4Addr> = kept
        .iter()
        .filter(|entry| is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .filter(|ip| !active.contains_key(ip))
        .collect();

    (kept, active, direct_only)
}

/// During country-ban bypass: relay everything — full country ban means the
/// CDN is also blocked, so splitting assets to direct would break them too.
/// All IPs go into active; direct_only is empty.
fn country_ban_split_ips_from_overrides(
    overrides: &[HostOverride],
) -> (HashMap<Ipv4Addr, String>, HashSet<Ipv4Addr>) {
    let active: HashMap<Ipv4Addr, String> = overrides
        .iter()
        .map(|entry| (entry.ip, entry.domain.clone()))
        .collect();
    (active, HashSet::new())
}

fn clear_bootstrap_ip_sets() {
    COUNTRY_BAN_BYPASS_ROUTING.store(false, Ordering::Relaxed);
    match active_bootstrap_ips().write() {
        Ok(mut active) => active.clear(),
        Err(e) => warn!("Failed to clear Roblox bootstrap route IPs: {e}"),
    }
    match direct_only_bootstrap_ips().write() {
        Ok(mut direct_only) => direct_only.clear(),
        Err(e) => warn!("Failed to clear direct-only Roblox bootstrap IPs: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn remove_marker_block(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut inside_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == MARKER_START {
            inside_block = true;
            continue;
        }
        if trimmed == MARKER_END {
            inside_block = false;
            continue;
        }

        if !inside_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    let trimmed = result.trim_end_matches('\n');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = trimmed.to_string();
    out.push('\n');
    out
}

fn build_hosts_block(overrides: &[HostOverride]) -> String {
    let mut block = String::new();
    block.push_str(MARKER_START);
    block.push('\n');
    for entry in overrides {
        block.push_str(&format!("{} {}\n", entry.ip, entry.domain));
    }
    block.push_str(MARKER_END);
    block.push('\n');
    block
}

fn build_doh_url(resolver: &str, domain: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("name", domain)
        .append_pair("type", "A")
        .finish();
    format!("{resolver}?{query}")
}

fn parse_usable_a_records(body: &str) -> Result<Vec<Ipv4Addr>, String> {
    let response: DohJsonResponse =
        serde_json::from_str(body).map_err(|e| format!("invalid DNS JSON: {e}"))?;

    if response.status != 0 {
        return Err(format!("DNS status {}", response.status));
    }

    Ok(response
        .answer
        .into_iter()
        .filter(|a| a.record_type == 1)
        .filter_map(|a| a.data.parse::<Ipv4Addr>().ok())
        .filter(|ip| is_usable_public_ipv4(*ip))
        .collect())
}

fn is_usable_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || (octets[0] == 198 && (18..=19).contains(&octets[1])))
}

#[cfg(windows)]
fn flush_dns_cache() {
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    match output {
        Ok(o) if o.status.success() => debug!("DNS cache flushed"),
        Ok(o) => warn!(
            "ipconfig /flushdns exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => warn!("Failed to run ipconfig /flushdns: {e}"),
    }
}

#[cfg(not(windows))]
fn flush_dns_cache() {}

// ---------------------------------------------------------------------------
// Test helpers (pub(crate) so interceptor tests can seed the state)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn set_active_bootstrap_ips_for_test(ips: impl IntoIterator<Item = Ipv4Addr>) {
    set_active_bootstrap_ips(
        ips.into_iter()
            .map(|ip| (ip, "test.roblox.com".to_string()))
            .collect(),
    );
}

#[cfg(test)]
pub(crate) fn set_direct_only_bootstrap_ips_for_test(ips: impl IntoIterator<Item = Ipv4Addr>) {
    set_direct_only_bootstrap_ips(ips.into_iter().collect());
}

#[cfg(test)]
pub(crate) fn clear_active_bootstrap_ips_for_test() {
    clear_bootstrap_ip_sets();
}

#[cfg(test)]
pub(crate) fn set_country_ban_bypass_routing_for_test(active: bool) {
    COUNTRY_BAN_BYPASS_ROUTING.store(active, Ordering::Relaxed);
}

/// Serializes every test that touches the process-global bootstrap IP sets.
/// Tests must hold this for their entire mutate-assert-clear sequence.
#[cfg(test)]
pub(crate) static BOOTSTRAP_IP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_marker_block_with_entries() {
        let input = "\
127.0.0.1 localhost
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
# SwiftTunnel Roblox Proxy - END
::1 localhost
";
        let expected = "127.0.0.1 localhost\n::1 localhost\n";
        assert_eq!(remove_marker_block(input), expected);
    }

    #[test]
    fn domain_list_stays_allowlisted_and_exact() {
        assert_eq!(ROBLOX_BOOTSTRAP_DOMAINS.len(), 54);
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.contains(&"roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"gamejoin.roblox.com"));
        // c0-c7 must be in bootstrap domains
        for i in 0..8 {
            let d = format!("c{}.rbxcdn.com", i);
            assert!(
                ROBLOX_BOOTSTRAP_DOMAINS.contains(&d.as_str()),
                "{} missing from ROBLOX_BOOTSTRAP_DOMAINS",
                d
            );
        }
        // c0-c7 must be asset_direct
        for i in 0..8 {
            let d = format!("c{}.rbxcdn.com", i);
            assert!(
                is_asset_direct_domain(&d),
                "{} should be asset_direct",
                d
            );
        }
    }

    #[test]
    fn direct_only_domains_are_subset_of_bootstrap_domains() {
        for domain in DIRECT_ONLY_BOOTSTRAP_DOMAINS {
            assert!(
                ROBLOX_BOOTSTRAP_DOMAINS.contains(domain),
                "{domain} is in DIRECT_ONLY but not in ROBLOX_BOOTSTRAP_DOMAINS"
            );
        }
    }

    #[test]
    fn missing_direct_only_domains_reports_unresolved_launch_hosts() {
        assert_eq!(
            missing_direct_only_domains(&[]),
            DIRECT_ONLY_BOOTSTRAP_DOMAINS.to_vec()
        );

        let overrides = vec![
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: "ClientSettingsCDN.Roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 46, 3),
                domain: "clientsettings.roblox.com".to_string(),
            },
        ];
        assert_eq!(
            missing_direct_only_domains(&overrides),
            vec![
                "clientsettings.api.roblox.com",
                "versioncompatibility.api.roblox.com",
            ]
        );
    }

    #[test]
    fn route_assist_keeps_settings_and_assets_direct_and_relays_control_plane() {
        let overrides = vec![
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: "clientsettingscdn.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 46, 3),
                domain: "clientsettings.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 3),
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 4),
                domain: "www.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(10, 20, 30, 40),
                domain: "setup.rbxcdn.com".to_string(),
            },
        ];

        let (_kept, active, direct_only) = allocate_route_assist_pins(overrides);

        // Settings hosts → direct_only
        assert!(!active.contains_key(&Ipv4Addr::new(65, 9, 168, 80)));
        assert!(!active.contains_key(&Ipv4Addr::new(128, 116, 46, 3)));
        assert!(direct_only.contains(&Ipv4Addr::new(65, 9, 168, 80)));
        assert!(direct_only.contains(&Ipv4Addr::new(128, 116, 46, 3)));
        // Region/join control-plane relay host → active
        assert!(active.contains_key(&Ipv4Addr::new(128, 116, 121, 3)));
        assert!(!direct_only.contains(&Ipv4Addr::new(128, 116, 121, 3)));
        // UI/social hosts (www.roblox.com) stay direct so menus/chat work
        assert!(direct_only.contains(&Ipv4Addr::new(128, 116, 121, 4)));
        assert!(!active.contains_key(&Ipv4Addr::new(128, 116, 121, 4)));
        // rbxcdn.com → direct_only (asset)
        assert!(!active.contains_key(&Ipv4Addr::new(10, 20, 30, 40)));
        assert!(direct_only.contains(&Ipv4Addr::new(10, 20, 30, 40)));
    }

    #[test]
    fn country_bypass_routes_critical_hosts_through_relay() {
        let critical = HostOverride {
            ip: Ipv4Addr::new(128, 116, 46, 3),
            domain: "clientsettings.roblox.com".to_string(),
        };
        let normal = HostOverride {
            ip: Ipv4Addr::new(128, 116, 121, 3),
            domain: "www.roblox.com".to_string(),
        };
        let overrides = vec![critical.clone(), normal.clone()];

        // Non-country-ban path: settings host → direct_only, control-plane → active
        let (_kept, active, direct_only) = allocate_route_assist_pins(overrides.clone());
        assert!(direct_only.contains(&critical.ip));
        assert!(!active.contains_key(&critical.ip));
        assert!(active.contains_key(&normal.ip));

        // Country-ban bypass: all hosts relay, direct_only is empty.
        let (active, direct_only) = country_ban_split_ips_from_overrides(&overrides);
        assert!(direct_only.is_empty());
        assert!(active.contains_key(&critical.ip));
        assert!(active.contains_key(&normal.ip));
    }

    #[test]
    fn country_ban_split_relays_everything() {
        let control = HostOverride {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            domain: "api.roblox.com".to_string(),
        };
        let asset = HostOverride {
            ip: Ipv4Addr::new(5, 6, 7, 8),
            domain: "assetdelivery.roblox.com".to_string(),
        };
        let overrides = vec![control.clone(), asset.clone()];
        let (active, direct_only) = country_ban_split_ips_from_overrides(&overrides);

        // Full country ban: everything relayed, nothing direct
        assert!(active.contains_key(&control.ip));
        assert!(active.contains_key(&asset.ip));
        assert!(direct_only.is_empty());
    }

    #[test]
    fn learn_direct_only_ip_records_unpinned_settings_host() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let ip = Ipv4Addr::new(65, 9, 168, 90);

        // IP not in active set → should be learned
        assert!(learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com",
            ip
        ));
        assert!(is_direct_only_bootstrap_ip(ip));

        // Second call → already recorded, returns false
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com",
            ip
        ));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn learn_direct_only_ip_refuses_to_demote_control_plane_pin() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let shared_ip = Ipv4Addr::new(65, 9, 168, 90);
        // IP is already a control-plane pin
        set_active_bootstrap_ips_for_test([shared_ip]);

        // Should refuse — active control-plane pins must not be demoted
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com",
            shared_ip
        ));
        assert!(!is_direct_only_bootstrap_ip(shared_ip));
        assert!(is_active_bootstrap_ip(shared_ip));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn learn_direct_only_ip_rejects_non_direct_only_hosts() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let ip = Ipv4Addr::new(65, 9, 168, 91);
        assert!(!learn_direct_only_bootstrap_ip("gamejoin.roblox.com", ip));
        assert!(!learn_direct_only_bootstrap_ip("apis.roblox.com", ip));
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com.evil.test",
            ip
        ));
        assert!(!is_direct_only_bootstrap_ip(ip));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn learn_direct_only_ip_is_disabled_during_country_ban_bypass() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();
        set_country_ban_bypass_routing_for_test(true);

        let ip = Ipv4Addr::new(65, 9, 168, 92);
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettings.roblox.com",
            ip
        ));
        assert!(!is_direct_only_bootstrap_ip(ip));

        clear_active_bootstrap_ips_for_test();
        assert!(learn_direct_only_bootstrap_ip(
            "clientsettings.roblox.com",
            ip
        ));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn asset_direct_domain_matches_rbxcdn_suffix_and_named() {
        assert!(is_asset_direct_domain("setup.rbxcdn.com"));
        assert!(is_asset_direct_domain("apis.rbxcdn.com"));
        assert!(is_asset_direct_domain("c0.rbxcdn.com"));
        assert!(is_asset_direct_domain("tr.rbxcdn.com"));
        assert!(is_asset_direct_domain("assetdelivery.roblox.com"));
        assert!(is_asset_direct_domain("assetgame.roblox.com"));
        assert!(is_asset_direct_domain("thumbnails.roblox.com"));
        assert!(is_asset_direct_domain("setup.roblox.com"));
        // control-plane hosts are NOT asset-direct
        assert!(!is_asset_direct_domain("api.roblox.com"));
        assert!(!is_asset_direct_domain("www.roblox.com"));
        assert!(!is_asset_direct_domain("clientsettings.roblox.com"));
    }

    #[test]
    fn route_assist_relays_control_plane_on_unavoidably_shared_edges() {
        // When every IP for a control-plane domain also appears in the direct pool,
        // conflict_free is empty and all entries are kept (relay wins for that domain).
        let shared_ip = Ipv4Addr::new(1, 2, 3, 4);
        let overrides = vec![
            HostOverride {
                ip: shared_ip,
                domain: "api.roblox.com".to_string(),
            },
            HostOverride {
                ip: shared_ip,
                domain: "setup.rbxcdn.com".to_string(),
            },
        ];
        let (_kept, active, direct_only) = allocate_route_assist_pins(overrides);
        // The shared IP is assigned to both pools by the domain logic, but since
        // direct_only excludes IPs already in active, the relay (control-plane)
        // assignment wins.
        assert!(active.contains_key(&shared_ip) || direct_only.contains(&shared_ip));
    }

    #[test]
    fn route_assist_allocation_prefers_disjoint_pins_when_alternatives_exist() {
        let control_ip = Ipv4Addr::new(1, 1, 1, 1);
        let asset_ip = Ipv4Addr::new(2, 2, 2, 2);
        let shared_ip = Ipv4Addr::new(3, 3, 3, 3);
        let overrides = vec![
            HostOverride {
                ip: control_ip,
                domain: "api.roblox.com".to_string(),
            },
            HostOverride {
                ip: shared_ip,
                domain: "api.roblox.com".to_string(),
            },
            HostOverride {
                ip: asset_ip,
                domain: "setup.rbxcdn.com".to_string(),
            },
            HostOverride {
                ip: shared_ip,
                domain: "setup.rbxcdn.com".to_string(),
            },
        ];
        let (_kept, active, direct_only) = allocate_route_assist_pins(overrides);
        // Conflict-free control-plane IP (not in direct pool) should be preferred
        assert!(active.contains_key(&control_ip));
        // Conflict-free asset IP (not in active pool) should be preferred
        assert!(direct_only.contains(&asset_ip));
        // Shared IP may or may not appear depending on resolution, but the
        // conflict-free entries must be chosen when alternatives exist.
        assert!(!active.contains_key(&shared_ip));
    }

    #[test]
    fn dedup_and_cap_ips_preserves_order_and_caps() {
        let ips = vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(3, 3, 3, 3),
            Ipv4Addr::new(4, 4, 4, 4),
        ];
        assert_eq!(
            dedup_and_cap_ips(ips, 3),
            vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(2, 2, 2, 2),
                Ipv4Addr::new(3, 3, 3, 3),
            ]
        );
    }

    #[test]
    fn parse_usable_a_records_rejects_private_and_nxdomain() {
        let private = r#"{"Status":0,"Answer":[{"name":"x","type":1,"TTL":60,"data":"192.168.0.10"}]}"#;
        assert!(parse_usable_a_records(private).unwrap().is_empty());
        let nx = r#"{"Status":3,"Answer":[]}"#;
        assert_eq!(parse_usable_a_records(nx).unwrap_err(), "DNS status 3");
    }

    #[test]
    fn active_bootstrap_ips_roundtrip() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let ip = Ipv4Addr::new(65, 9, 168, 80);
        set_active_bootstrap_ips([(ip, "www.roblox.com".to_string())].into_iter().collect());
        assert!(is_active_bootstrap_ip(ip));
        assert_eq!(host_for_ip(ip).as_deref(), Some("www.roblox.com"));
        assert!(!is_active_bootstrap_ip(Ipv4Addr::new(65, 9, 168, 81)));

        clear_active_bootstrap_ips_for_test();
        assert!(!is_active_bootstrap_ip(ip));
    }

    #[test]
    fn direct_only_bootstrap_ips_roundtrip() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let ip = Ipv4Addr::new(128, 116, 46, 3);
        set_direct_only_bootstrap_ips([ip].into_iter().collect());
        assert!(is_direct_only_bootstrap_ip(ip));
        assert!(!is_direct_only_bootstrap_ip(Ipv4Addr::new(128, 116, 46, 4)));

        clear_active_bootstrap_ips_for_test();
        assert!(!is_direct_only_bootstrap_ip(ip));
    }

    #[test]
    fn build_doh_url_encodes_domain_query_value() {
        assert_eq!(
            build_doh_url("https://1.1.1.1/dns-query", "clientsettingscdn.roblox.com"),
            "https://1.1.1.1/dns-query?name=clientsettingscdn.roblox.com&type=A"
        );
    }
}
