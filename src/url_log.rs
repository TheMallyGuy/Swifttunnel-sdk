//! Destination ("URL") logger.
//!
//! The packet interceptor routes at the IP layer, so it can't see a URL/SNI per
//! packet. To still give a human-readable picture of what the tunnel app talks
//! to (so users can choose what to put in `excluded_urls`), this module records
//! every *distinct* destination reached by tunnel-app traffic to a dedicated log
//! file, annotated with a hostname whenever we know one (from Route Assist's DNS
//! repair map and from resolved exclusions).
//!
//! Log file: `%TEMP%\swifttunnel_urls.log`.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};

struct UrlLogState {
    file: Option<File>,
    /// Dedup key set: packed (ip, port, proto) already written this session.
    seen: HashSet<u64>,
}

fn state() -> &'static Mutex<UrlLogState> {
    static STATE: OnceLock<Mutex<UrlLogState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(UrlLogState {
            file: None,
            seen: HashSet::new(),
        })
    })
}

fn log_path() -> std::path::PathBuf {
    std::env::temp_dir().join("swifttunnel_urls.log")
}

#[inline]
fn key(ip: Ipv4Addr, port: u16, proto: u8) -> u64 {
    ((u32::from(ip) as u64) << 24) | ((port as u64) << 8) | (proto as u64)
}

fn proto_str(proto: u8) -> &'static str {
    match proto {
        6 => "TCP",
        17 => "UDP",
        _ => "?",
    }
}

/// Build a display URL from a hostname hint (or IP) + port + protocol.
///
/// - If the hint already looks like a URL (`scheme://…`, possibly with a path),
///   it is shown verbatim (this is the user's original `excluded_urls` entry).
/// - Otherwise a `scheme://host` is synthesised from the port: 443→https,
///   80→http, UDP→udp, else tcp.
fn build_url(dst_ip: Ipv4Addr, dst_port: u16, proto: u8, host: Option<&str>) -> String {
    if let Some(h) = host {
        if h.contains("://") {
            return h.to_string();
        }
    }
    let scheme = match (proto, dst_port) {
        (17, _) => "udp",
        (6, 443) => "https",
        (6, 80) => "http",
        (6, _) => "tcp",
        _ => "ip",
    };
    let authority = host.map(|h| h.to_string()).unwrap_or_else(|| dst_ip.to_string());
    // Append :port for non-default ports so the destination stays unambiguous.
    let default_port = matches!((proto, dst_port), (6, 443) | (6, 80));
    if default_port {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}:{dst_port}")
    }
}

/// Start a fresh logging session: (re)open the file in append mode, clear the
/// per-session dedup set, and write a header. Called on each connect.
pub fn begin_session(region: &str, route_assist: bool) {
    let mut st = match state().lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    if st.file.is_none() {
        match OpenOptions::new().create(true).append(true).open(log_path()) {
            Ok(f) => st.file = Some(f),
            Err(e) => {
                log::warn!("url_log: cannot open {}: {}", log_path().display(), e);
                return;
            }
        }
    }

    st.seen.clear();

    if let Some(f) = st.file.as_mut() {
        let ts = now_string();
        let _ = writeln!(
            f,
            "\n===== session {} region={} route_assist={} =====",
            ts, region, route_assist
        );
        let _ = f.flush();
    }
}

/// Record a destination reached by tunnel-app traffic. Deduplicated per session,
/// so each distinct (ip, port, proto) is written at most once.
///
/// - `host`: optional resolved hostname / original URL hint.
/// - `relay_addr`: the relay a tunneled packet is routed through (for the route
///   column); ignored for bypassed packets (shown as `direct`).
pub fn record(
    dst_ip: Ipv4Addr,
    dst_port: u16,
    proto: u8,
    tunneled: bool,
    host: Option<&str>,
    relay_addr: Option<SocketAddr>,
) {
    let k = key(dst_ip, dst_port, proto);

    let mut st = match state().lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    if !st.seen.insert(k) {
        return; // already logged this destination this session
    }

    if let Some(f) = st.file.as_mut() {
        let action = if tunneled { "TUNNEL" } else { "BYPASS" };
        let url = build_url(dst_ip, dst_port, proto, host);
        let route = if tunneled {
            match relay_addr {
                Some(a) => format!("relay {}", a),
                None => "relay ?".to_string(),
            }
        } else {
            "direct".to_string()
        };
        let _ = writeln!(
            f,
            "{} {:<6} {:<4} {:<21} {:<48} -> {}",
            now_string(),
            action,
            proto_str(proto),
            format!("{}:{}", dst_ip, dst_port),
            url,
            route
        );
        let _ = f.flush();
    }
}

fn now_string() -> String {
    use chrono::Utc;
    Utc::now().format("%H:%M:%S").to_string()
}
