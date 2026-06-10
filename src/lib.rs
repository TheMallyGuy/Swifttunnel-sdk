//! SwiftTunnel SDK — C FFI entry point
//!
//! Exposes 31 `extern "C"` functions for consumption by C#, Python, and other
//! languages via `cdylib`.  All async work is dispatched through the global
//! Tokio runtime (`runtime().block_on()`).

mod asset_route;
mod auth;
mod callbacks;
mod error;
mod exclusions;
mod roblox_proxy;
mod runtime;
mod split_tunnel;
mod url_log;
mod vpn;

use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_void};
use std::ptr;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Deserialize;

use auth::AuthManager;
use callbacks::{
    register_auto_routing_callback, register_error_callback, register_process_callback,
    register_state_callback,
};
use error::{
    clear_error, last_error_code, set_error, set_sdk_error, take_last_error, SdkError,
    ERROR_NOT_INITIALIZED, SUCCESS,
};
use runtime::runtime;
use vpn::connection::{ConnectionState, VpnConnection};
use vpn::servers::ServerList;

// ── Global SDK state ────────────────────────────────────────────────────────

struct SdkState {
    auth: AuthManager,
    servers: ServerList,
    vpn: VpnConnection,
}

static SDK: Lazy<Mutex<Option<SdkState>>> = Lazy::new(|| Mutex::new(None));

#[derive(Debug, Deserialize)]
struct ConnectExOptions {
    region: String,
    #[serde(default)]
    apps: Vec<String>,
    #[serde(default)]
    auto_routing: AutoRoutingOptions,
    /// Override the relay server endpoint (disables auto-routing when set)
    #[serde(default)]
    custom_relay_server: Option<String>,
    /// Per-region forced server overrides: region_id → server_id
    #[serde(default)]
    forced_servers: std::collections::HashMap<String, String>,
    /// Route Assist: tunnel Roblox TCP API/bootstrap traffic and repair its
    /// bootstrap DNS (helps bypass network/country bans).
    #[serde(default)]
    enable_api_tunneling: bool,
    /// Bypass Country Bans: launch GoodbyeDPI and route ALL Roblox bootstrap
    /// traffic (including the launch-critical hosts normally kept direct)
    /// through Route Assist so geo-blocked connections can escape the ISP block.
    /// Implicitly enables `enable_api_tunneling`.
    #[serde(default)]
    enable_country_ban: bool,
    /// URLs/hosts to never tunnel. Each is resolved to IPs at connect time and
    /// any traffic to those IPs always bypasses the relay.
    #[serde(default)]
    excluded_urls: Vec<String>,
    /// Dedicated relay endpoint (`ip:port` or `host:port`) for asset traffic.
    /// When set together with `asset_urls`, matching traffic is forwarded
    /// through this relay (a different exit IP) to dodge Roblox's per-IP 429.
    #[serde(default)]
    asset_relay_server: Option<String>,
    /// URLs/hosts whose traffic should ride the asset relay (e.g.
    /// `assetdelivery.roblox.com`, `*.rbxcdn.com`).
    #[serde(default)]
    asset_urls: Vec<String>,
    /// Number of far-region relays in the asset pool (0 = default of 3).
    #[serde(default)]
    asset_relay_count: usize,
}

#[derive(Debug, Default, Deserialize)]
struct AutoRoutingOptions {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    whitelisted_regions: Vec<String>,
}

/// Convenience: run `body` while holding the SDK lock.
/// Returns `ERROR_NOT_INITIALIZED` (and sets the last-error) when the SDK has
/// not been initialised yet.
fn with_sdk<F, R>(body: F) -> R
where
    F: FnOnce(&mut SdkState) -> R,
    R: From<i32>,
{
    let mut guard = SDK.lock();
    match guard.as_mut() {
        Some(state) => body(state),
        None => {
            let err = SdkError::NotInitialized;
            set_sdk_error(&err);
            R::from(ERROR_NOT_INITIALIZED)
        }
    }
}

/// Allocate a C string on the heap.  Caller frees via `swifttunnel_free_string`.
fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Read a `*const c_char` into a `&str`, returning `None` on null or invalid UTF-8.
unsafe fn from_c_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

fn load_available_servers_for_auto_routing(
    state: &mut SdkState,
) -> Vec<(String, SocketAddr, Option<u32>)> {
    if state.servers.is_empty() {
        if let Ok((servers, regions, source)) = runtime().block_on(vpn::servers::load_server_list())
        {
            state.servers.update(servers, regions, source);
        }
    }

    state
        .servers
        .servers()
        .iter()
        .filter(|s| s.relay_available)
        .filter_map(|s| {
            let addr: SocketAddr = format!("{}:{}", s.ip, s.effective_relay_port()).parse().ok()?;
            let latency = state.servers.get_latency(&s.region);
            Some((s.region.clone(), addr, latency))
        })
        .collect()
}

fn connect_with_options(state: &mut SdkState, options: ConnectExOptions) -> i32 {
    let token = match runtime().block_on(state.auth.get_access_token()) {
        Ok(t) => t,
        Err(e) => {
            set_sdk_error(&e);
            return e.code();
        }
    };

    let available_servers = load_available_servers_for_auto_routing(state);

    match runtime().block_on(state.vpn.connect_ex(
        &token,
        &options.region,
        options.apps,
        options.auto_routing.enabled,
        available_servers,
        options.auto_routing.whitelisted_regions,
        options.enable_api_tunneling || options.enable_country_ban,
        options.excluded_urls,
        options.asset_relay_server,
        options.asset_urls,
        options.asset_relay_count,
        options.enable_country_ban,
    )) {
        Ok(()) => SUCCESS,
        Err(e) => {
            set_sdk_error(&e);
            e.code()
        }
    }
}

fn parse_apps_json(raw: Option<&str>) -> Result<Vec<String>, SdkError> {
    match raw {
        Some(s) => serde_json::from_str(s)
            .map_err(|e| SdkError::InvalidParam(format!("Invalid apps_json: {}", e))),
        None => Ok(Vec::new()),
    }
}

fn default_auto_routing_json() -> serde_json::Value {
    serde_json::json!({
        "enabled": false,
        "current_region": null,
        "game_region": null,
        "bypassed": false,
        "pending_lookups": 0,
        "events": [],
    })
}

// ═══════════════════════════════════════════════════════════════════════════
//  Core (4)
// ═══════════════════════════════════════════════════════════════════════════

/// Initialise the SDK: create runtime, logger, and global state.
/// Returns 0 on success, negative on error.
#[no_mangle]
pub extern "C" fn swifttunnel_init() -> i32 {
    clear_error();

    let mut guard = SDK.lock();
    if guard.is_some() {
        return SUCCESS; // already initialised
    }

    // Initialise logger — write to a file so logs are visible even without a console.
    let log_path = std::env::temp_dir().join("swifttunnel_sdk.log");
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let _ = env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .target(env_logger::Target::Pipe(Box::new(file)))
            .try_init();
    } else {
        let _ = env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .try_init();
    }

    log::info!(
        "SwiftTunnel SDK v{} initialising",
        env!("CARGO_PKG_VERSION")
    );

    let auth = match AuthManager::new() {
        Ok(a) => a,
        Err(e) => {
            set_sdk_error(&e);
            return e.code();
        }
    };

    *guard = Some(SdkState {
        auth,
        servers: ServerList::new_empty(),
        vpn: VpnConnection::new(),
    });

    log::info!("SwiftTunnel SDK initialised");
    SUCCESS
}

/// Tear down the SDK: disconnect if connected, drop all state.
#[no_mangle]
pub extern "C" fn swifttunnel_cleanup() {
    clear_error();

    let mut guard = SDK.lock();
    if let Some(mut state) = guard.take() {
        // Best-effort disconnect
        let connected = runtime().block_on(async { state.vpn.state().await.is_connected() });
        if connected {
            let _ = runtime().block_on(state.vpn.disconnect());
        }
        log::info!("SwiftTunnel SDK cleaned up");
    }
}

/// Return the SDK version string.  Caller must free with `swifttunnel_free_string`.
#[no_mangle]
pub extern "C" fn swifttunnel_version() -> *mut c_char {
    to_c_string(env!("CARGO_PKG_VERSION"))
}

/// Free a string previously returned by the SDK.
#[no_mangle]
pub unsafe extern "C" fn swifttunnel_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Auth (8)
// ═══════════════════════════════════════════════════════════════════════════

/// Sign in with email and password.  Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn swifttunnel_auth_sign_in(
    email: *const c_char,
    password: *const c_char,
) -> i32 {
    clear_error();

    let email = match from_c_str(email) {
        Some(s) => s,
        None => {
            let e = SdkError::InvalidParam("email is null or invalid".into());
            set_sdk_error(&e);
            return e.code();
        }
    };
    let password = match from_c_str(password) {
        Some(s) => s,
        None => {
            let e = SdkError::InvalidParam("password is null or invalid".into());
            set_sdk_error(&e);
            return e.code();
        }
    };

    // Copy to owned strings so we can move into the closure
    let email = email.to_string();
    let password = password.to_string();

    with_sdk(
        |state| match runtime().block_on(state.auth.sign_in(&email, &password)) {
            Ok(()) => SUCCESS,
            Err(e) => {
                set_sdk_error(&e);
                e.code()
            }
        },
    )
}

/// Start Google OAuth flow.  Returns the URL to open in a browser.
/// Caller must free the returned string.  Returns null on error.
#[no_mangle]
pub extern "C" fn swifttunnel_auth_start_oauth() -> *mut c_char {
    clear_error();

    let mut guard = SDK.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    match state.auth.start_google_sign_in() {
        Ok((url, _state)) => to_c_string(&url),
        Err(e) => {
            set_sdk_error(&e);
            ptr::null_mut()
        }
    }
}

/// Poll for OAuth callback.
/// Returns 1 if complete (logged in), 0 if still waiting, -1 on error.
#[no_mangle]
pub extern "C" fn swifttunnel_auth_poll_oauth() -> i32 {
    clear_error();

    let mut guard = SDK.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return -1;
        }
    };

    if !state.auth.is_awaiting_oauth() {
        // Already logged in or not in OAuth flow
        if state.auth.is_logged_in() {
            return 1;
        }
        return -1;
    }

    match state.auth.poll_oauth_callback() {
        Some(callback_data) => {
            // Got callback data, complete the exchange
            let token = callback_data.token.clone();
            let cb_state = callback_data.state.clone();
            match runtime().block_on(state.auth.complete_oauth_callback(&token, &cb_state)) {
                Ok(()) => 1,
                Err(e) => {
                    set_sdk_error(&e);
                    -1
                }
            }
        }
        None => 0, // still waiting
    }
}

/// Cancel an in-progress OAuth flow.
#[no_mangle]
pub extern "C" fn swifttunnel_auth_cancel_oauth() {
    clear_error();

    let mut guard = SDK.lock();
    if let Some(state) = guard.as_mut() {
        state.auth.cancel_oauth();
    }
}

/// Refresh the access token.  Returns 0 on success.
#[no_mangle]
pub extern "C" fn swifttunnel_auth_refresh() -> i32 {
    clear_error();

    with_sdk(
        |state| match runtime().block_on(state.auth.refresh_if_needed()) {
            Ok(()) => SUCCESS,
            Err(e) => {
                set_sdk_error(&e);
                e.code()
            }
        },
    )
}

/// Sign out and clear stored credentials.
#[no_mangle]
pub extern "C" fn swifttunnel_auth_sign_out() {
    clear_error();

    let mut guard = SDK.lock();
    if let Some(state) = guard.as_mut() {
        if let Err(e) = state.auth.logout() {
            set_sdk_error(&e);
        }
    }
}

/// Check if a user is currently logged in.  Returns 1 or 0.
#[no_mangle]
pub extern "C" fn swifttunnel_auth_is_logged_in() -> i32 {
    let guard = SDK.lock();
    match guard.as_ref() {
        Some(state) => {
            if state.auth.is_logged_in() {
                1
            } else {
                0
            }
        }
        None => 0,
    }
}

/// Get user info as JSON.  Returns null if not logged in.
/// Caller must free the returned string.
///
/// JSON shape: `{"id":"...","email":"...","is_tester":false,"is_banned":false,"banned_reason":null,"banned_at":null}`
#[no_mangle]
pub extern "C" fn swifttunnel_auth_get_user_json() -> *mut c_char {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    match state.auth.get_user() {
        Some(user) => match serde_json::to_string(&user) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_error(format!("JSON serialization failed: {}", e));
                ptr::null_mut()
            }
        },
        None => ptr::null_mut(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Servers (3)
// ═══════════════════════════════════════════════════════════════════════════

/// Fetch the server list from the API (or cache).  Returns 0 on success.
#[no_mangle]
pub extern "C" fn swifttunnel_servers_fetch() -> i32 {
    clear_error();

    with_sdk(
        |state| match runtime().block_on(vpn::servers::load_server_list()) {
            Ok((servers, regions, source)) => {
                state.servers.update(servers, regions, source);
                SUCCESS
            }
            Err(e) => {
                set_sdk_error(&e);
                e.code()
            }
        },
    )
}

/// Get the cached server list as JSON.  Returns null if not fetched yet.
/// Caller must free the returned string.
///
/// JSON shape: `{"servers":[...],"regions":[...]}`
#[no_mangle]
pub extern "C" fn swifttunnel_servers_get_json() -> *mut c_char {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    if state.servers.is_empty() {
        return ptr::null_mut();
    }

    let json_val = serde_json::json!({
        "servers": state.servers.servers(),
        "regions": state.servers.regions(),
        "source": state.servers.source.to_string(),
    });

    match serde_json::to_string(&json_val) {
        Ok(json) => to_c_string(&json),
        Err(e) => {
            set_error(format!("JSON serialization failed: {}", e));
            ptr::null_mut()
        }
    }
}

/// Ping a server region and return latency in ms.  Returns -1 on error.
#[no_mangle]
pub unsafe extern "C" fn swifttunnel_servers_ping(region: *const c_char) -> i32 {
    clear_error();

    let region = match from_c_str(region) {
        Some(s) => s.to_string(),
        None => {
            set_sdk_error(&SdkError::InvalidParam("region is null or invalid".into()));
            return -1;
        }
    };

    let mut guard = SDK.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return -1;
        }
    };

    let server = match state.servers.get_server(&region) {
        Some(s) => s.clone(),
        None => {
            set_error(format!("Server not found for region: {}", region));
            return -1;
        }
    };

    let endpoint = format!("{}:{}", server.ip, server.port);

    match runtime().block_on(vpn::servers::measure_latency(&endpoint)) {
        Some(ms) => {
            state.servers.set_latency(&region, Some(ms));
            ms as i32
        }
        None => {
            state.servers.set_latency(&region, None);
            -1
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Connection (5)
// ═══════════════════════════════════════════════════════════════════════════

/// Connect to a VPN server (legacy API, auto-routing disabled).
#[no_mangle]
pub unsafe extern "C" fn swifttunnel_connect(
    region: *const c_char,
    apps_json: *const c_char,
) -> i32 {
    clear_error();

    let region = match from_c_str(region) {
        Some(s) => s.to_string(),
        None => {
            let e = SdkError::InvalidParam("region is null or invalid".into());
            set_sdk_error(&e);
            return e.code();
        }
    };

    let apps: Vec<String> = match parse_apps_json(from_c_str(apps_json)) {
        Ok(v) => v,
        Err(err) => {
            set_sdk_error(&err);
            return err.code();
        }
    };

    let options = ConnectExOptions {
        region,
        apps,
        auto_routing: AutoRoutingOptions::default(),
        custom_relay_server: None,
        forced_servers: std::collections::HashMap::new(),
        enable_api_tunneling: false,
        excluded_urls: Vec::new(),
        asset_relay_server: None,
        asset_urls: Vec::new(),
        asset_relay_count: 0,
        enable_country_ban: false,
    };

    let mut guard = SDK.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ERROR_NOT_INITIALIZED;
        }
    };
    connect_with_options(state, options)
}

/// Connect using JSON options.
///
/// JSON contract:
/// `{ \"region\": \"singapore\", \"apps\": [\"RobloxPlayerBeta.exe\"], \"auto_routing\": { \"enabled\": true, \"whitelisted_regions\": [\"US East\"] } }`
#[no_mangle]
pub unsafe extern "C" fn swifttunnel_connect_ex(options_json: *const c_char) -> i32 {
    clear_error();

    let raw = match from_c_str(options_json) {
        Some(s) => s,
        None => {
            let e = SdkError::InvalidParam("options_json is null or invalid".into());
            set_sdk_error(&e);
            return e.code();
        }
    };

    let options: ConnectExOptions = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            let err = SdkError::InvalidParam(format!("Invalid options_json: {}", e));
            set_sdk_error(&err);
            return err.code();
        }
    };

    if options.region.trim().is_empty() {
        let err = SdkError::InvalidParam("region must not be empty".into());
        set_sdk_error(&err);
        return err.code();
    }

    let mut guard = SDK.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ERROR_NOT_INITIALIZED;
        }
    };

    connect_with_options(state, options)
}

/// Disconnect from the VPN.  Returns 0 on success.
#[no_mangle]
pub extern "C" fn swifttunnel_disconnect() -> i32 {
    clear_error();

    let mut guard = SDK.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ERROR_NOT_INITIALIZED;
        }
    };

    match runtime().block_on(state.vpn.disconnect()) {
        Ok(()) => SUCCESS,
        Err(e) => {
            set_sdk_error(&e);
            e.code()
        }
    }
}

/// Get the current connection state as an integer code.
///
/// | Code | State                    |
/// |------|--------------------------|
/// |  0   | Disconnected             |
/// |  1   | FetchingConfig           |
/// |  2   | Connecting               |
/// |  3   | ConfiguringSplitTunnel   |
/// |  4   | Connected                |
/// |  5   | Disconnecting            |
/// | -1   | Error                    |
/// | -2   | SDK not initialised      |
#[no_mangle]
pub extern "C" fn swifttunnel_get_state() -> i32 {
    let guard = SDK.lock();
    match guard.as_ref() {
        Some(state) => {
            let conn_state = runtime().block_on(state.vpn.state());
            conn_state.as_code()
        }
        None => ERROR_NOT_INITIALIZED,
    }
}

/// Get detailed connection state as JSON.  Returns null if SDK not initialised.
/// Caller must free the returned string.
///
/// JSON shape:
/// ```json
/// {
///   "state": "Connected",
///   "code": 4,
///   "region": "singapore",
///   "endpoint": "1.2.3.4:51821",
///   "split_tunnel_active": true,
///   "tunneled_processes": ["RobloxPlayerBeta.exe"],
///   "error": null
/// }
/// ```
#[no_mangle]
pub extern "C" fn swifttunnel_get_state_json() -> *mut c_char {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    let conn_state = runtime().block_on(state.vpn.state());

    let json_val = match &conn_state {
        ConnectionState::Connected {
            server_region,
            server_endpoint,
            assigned_ip,
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
            relay_status,
            ..
        } => serde_json::json!({
            "state": "Connected",
            "code": conn_state.as_code(),
            "region": server_region,
            "endpoint": server_endpoint,
            "assigned_ip": assigned_ip,
            "relay_auth_mode": relay_auth_mode,
            "split_tunnel_active": split_tunnel_active,
            "tunneled_processes": tunneled_processes,
            "relay_status": relay_status,
            "auto_routing": state
                .vpn
                .auto_routing_snapshot()
                .unwrap_or_else(default_auto_routing_json),
            "error": null,
        }),
        ConnectionState::Error(msg) => serde_json::json!({
            "state": "Error",
            "code": conn_state.as_code(),
            "region": null,
            "endpoint": null,
            "split_tunnel_active": false,
            "tunneled_processes": [],
            "auto_routing": state
                .vpn
                .auto_routing_snapshot()
                .unwrap_or_else(default_auto_routing_json),
            "error": msg,
        }),
        other => serde_json::json!({
            "state": other.status_text(),
            "code": other.as_code(),
            "region": null,
            "endpoint": null,
            "split_tunnel_active": false,
            "tunneled_processes": [],
            "auto_routing": state
                .vpn
                .auto_routing_snapshot()
                .unwrap_or_else(default_auto_routing_json),
            "error": null,
        }),
    };

    match serde_json::to_string(&json_val) {
        Ok(json) => to_c_string(&json),
        Err(e) => {
            set_error(format!("JSON serialization failed: {}", e));
            ptr::null_mut()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Split Tunnel (4)
// ═══════════════════════════════════════════════════════════════════════════

/// Get currently tunnelled process names as a JSON array.
/// Returns null if not connected or SDK not initialised.
/// Caller must free the returned string.
#[no_mangle]
pub extern "C" fn swifttunnel_get_tunneled_processes() -> *mut c_char {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    let conn_state = runtime().block_on(state.vpn.state());
    match &conn_state {
        ConnectionState::Connected {
            tunneled_processes, ..
        } => match serde_json::to_string(tunneled_processes) {
            Ok(json) => to_c_string(&json),
            Err(e) => {
                set_error(format!("JSON serialization failed: {}", e));
                ptr::null_mut()
            }
        },
        _ => to_c_string("[]"),
    }
}

/// Get relay packet statistics as JSON.
/// Returns null if not connected.
/// Caller must free the returned string.
///
/// JSON shape: `{"packets_sent":123,"packets_recv":456}`
#[no_mangle]
pub extern "C" fn swifttunnel_get_stats_json() -> *mut c_char {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    match state.vpn.relay_stats() {
        Some((sent, recv)) => {
            let json = serde_json::json!({
                "packets_sent": sent,
                "packets_recv": recv,
            });
            match serde_json::to_string(&json) {
                Ok(s) => to_c_string(&s),
                Err(e) => {
                    set_error(format!("JSON serialization failed: {}", e));
                    ptr::null_mut()
                }
            }
        }
        None => ptr::null_mut(),
    }
}

/// Get auto-routing state as JSON.
/// Caller must free the returned string.
#[no_mangle]
pub extern "C" fn swifttunnel_get_auto_routing_json() -> *mut c_char {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ptr::null_mut();
        }
    };

    let payload = state
        .vpn
        .auto_routing_snapshot()
        .unwrap_or_else(default_auto_routing_json);

    match serde_json::to_string(&payload) {
        Ok(s) => to_c_string(&s),
        Err(e) => {
            set_error(format!("JSON serialization failed: {}", e));
            ptr::null_mut()
        }
    }
}

/// Trigger an immediate re-scan of tunnelled processes.
/// Returns 0 on success, negative on error.
#[no_mangle]
pub extern "C" fn swifttunnel_refresh_processes() -> i32 {
    clear_error();

    let guard = SDK.lock();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => {
            set_sdk_error(&SdkError::NotInitialized);
            return ERROR_NOT_INITIALIZED;
        }
    };

    let conn_state = runtime().block_on(state.vpn.state());
    if !conn_state.is_connected() {
        let e = SdkError::NotConnected;
        set_sdk_error(&e);
        return e.code();
    }

    // The process monitor in VpnConnection handles refresh automatically.
    // This is a hint to the caller that the state will update on next poll.
    SUCCESS
}

// ═══════════════════════════════════════════════════════════════════════════
//  Callbacks (4)
// ═══════════════════════════════════════════════════════════════════════════

/// Register a callback for VPN state changes.
///
/// Signature: `fn(state_code: i32, user_context: *mut c_void)`
#[no_mangle]
pub extern "C" fn swifttunnel_on_state_change(
    cb: Option<unsafe extern "C" fn(i32, *mut c_void)>,
    ctx: *mut c_void,
) {
    register_state_callback(cb, ctx);
}

/// Register a callback for errors.
///
/// Signature: `fn(error_code: i32, message: *const c_char, user_context: *mut c_void)`
#[no_mangle]
pub extern "C" fn swifttunnel_on_error(
    cb: Option<unsafe extern "C" fn(i32, *const i8, *mut c_void)>,
    ctx: *mut c_void,
) {
    register_error_callback(cb, ctx);
}

/// Register a callback for process detection events.
///
/// Signature: `fn(process_name: *const c_char, added: i32, user_context: *mut c_void)`
#[no_mangle]
pub extern "C" fn swifttunnel_on_process_detected(
    cb: Option<unsafe extern "C" fn(*const i8, i32, *mut c_void)>,
    ctx: *mut c_void,
) {
    register_process_callback(cb, ctx);
}

/// Register a callback for auto-routing events.
///
/// Signature: `fn(event_json: *const c_char, user_context: *mut c_void)`
#[no_mangle]
pub extern "C" fn swifttunnel_on_auto_routing_event(
    cb: Option<unsafe extern "C" fn(*const i8, *mut c_void)>,
    ctx: *mut c_void,
) {
    register_auto_routing_callback(cb, ctx);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Error (3)
// ═══════════════════════════════════════════════════════════════════════════

/// Get the last error message.  Returns null if no error.
/// Caller must free the returned string.
#[no_mangle]
pub extern "C" fn swifttunnel_get_last_error() -> *mut c_char {
    match take_last_error() {
        Some(msg) => to_c_string(&msg),
        None => ptr::null_mut(),
    }
}

/// Get the last error code.  Returns 0 (`SUCCESS`) if no error.
#[no_mangle]
pub extern "C" fn swifttunnel_get_last_error_code() -> i32 {
    last_error_code()
}

/// Clear the stored error state.
#[no_mangle]
pub extern "C" fn swifttunnel_clear_error() {
    clear_error();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_ex_defaults_when_optional_fields_are_omitted() {
        let parsed: ConnectExOptions =
            serde_json::from_str(r#"{"region":"singapore"}"#).expect("valid json");

        assert_eq!(parsed.region, "singapore");
        assert!(parsed.apps.is_empty());
        assert!(!parsed.auto_routing.enabled);
        assert!(parsed.auto_routing.whitelisted_regions.is_empty());
    }

    #[test]
    fn connect_ex_parses_full_contract() {
        let parsed: ConnectExOptions = serde_json::from_str(
            r#"{
                "region":"singapore",
                "apps":["RobloxPlayerBeta.exe"],
                "auto_routing":{"enabled":true,"whitelisted_regions":["US East","Tokyo"]}
            }"#,
        )
        .expect("valid json");

        assert_eq!(parsed.region, "singapore");
        assert_eq!(parsed.apps, vec!["RobloxPlayerBeta.exe"]);
        assert!(parsed.auto_routing.enabled);
        assert_eq!(
            parsed.auto_routing.whitelisted_regions,
            vec!["US East", "Tokyo"]
        );
    }

    #[test]
    fn connect_ex_rejects_invalid_json() {
        let parsed: Result<ConnectExOptions, _> = serde_json::from_str("{not-json}");
        assert!(parsed.is_err());
    }

    #[test]
    fn legacy_connect_apps_json_defaults_and_parsing() {
        let empty = parse_apps_json(None).expect("None should default");
        assert!(empty.is_empty());

        let parsed =
            parse_apps_json(Some(r#"["RobloxPlayerBeta.exe","Game.exe"]"#)).expect("valid array");
        assert_eq!(parsed, vec!["RobloxPlayerBeta.exe", "Game.exe"]);

        let invalid = parse_apps_json(Some(r#"{"apps":["bad"]}"#));
        assert!(invalid.is_err());
    }
}
