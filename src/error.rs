//! SDK error types, error codes, and thread-local last-error storage.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use thiserror::Error;

// ── Error codes (match old swifttunnel-vpn-native crate) ────────────────────

pub const SUCCESS: i32 = 0;
pub const ERROR_INVALID_PARAM: i32 = -1;
pub const ERROR_NOT_INITIALIZED: i32 = -2;
pub const ERROR_ALREADY_CONNECTED: i32 = -3;
pub const ERROR_NOT_CONNECTED: i32 = -4;
pub const ERROR_INTERNAL: i32 = -5;
pub const ERROR_AUTH: i32 = -6;
pub const ERROR_NETWORK: i32 = -7;
pub const ERROR_CONFIG: i32 = -8;
pub const ERROR_SPLIT_TUNNEL: i32 = -9;
pub const ERROR_VPN: i32 = -10;
pub const ERROR_USER_BANNED: i32 = -11;

// ── SdkError enum ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Split tunnel error: {0}")]
    SplitTunnel(String),

    #[error("VPN error: {0}")]
    Vpn(String),

    #[error("Invalid parameter: {0}")]
    InvalidParam(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Already connected")]
    AlreadyConnected,

    #[error("Not connected")]
    NotConnected,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Account banned: {0}")]
    UserBanned(String),
}

impl SdkError {
    /// Map this error to its integer error code for the C API.
    pub fn code(&self) -> i32 {
        match self {
            SdkError::Auth(_) => ERROR_AUTH,
            SdkError::Network(_) => ERROR_NETWORK,
            SdkError::Config(_) => ERROR_CONFIG,
            SdkError::SplitTunnel(_) => ERROR_SPLIT_TUNNEL,
            SdkError::Vpn(_) => ERROR_VPN,
            SdkError::InvalidParam(_) => ERROR_INVALID_PARAM,
            SdkError::NotInitialized => ERROR_NOT_INITIALIZED,
            SdkError::AlreadyConnected => ERROR_ALREADY_CONNECTED,
            SdkError::NotConnected => ERROR_NOT_CONNECTED,
            SdkError::Internal(_) => ERROR_INTERNAL,
            SdkError::Storage(_) => ERROR_INTERNAL,
            SdkError::UserBanned(_) => ERROR_USER_BANNED,
        }
    }
}

// ── Last-error storage ──────────────────────────────────────────────────────

static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));
static LAST_ERROR_CODE: Lazy<Mutex<i32>> = Lazy::new(|| Mutex::new(SUCCESS));

/// Store an error message (and its code) so it can be retrieved by the FFI caller.
pub fn set_error(msg: impl Into<String>) {
    *LAST_ERROR.lock() = Some(msg.into());
}

/// Store an `SdkError`, recording both the message and code.
pub fn set_sdk_error(err: &SdkError) {
    *LAST_ERROR_CODE.lock() = err.code();
    *LAST_ERROR.lock() = Some(err.to_string());
}

/// Clear the stored error.
pub fn clear_error() {
    *LAST_ERROR.lock() = None;
    *LAST_ERROR_CODE.lock() = SUCCESS;
}

/// Take the last error message, leaving `None` behind.
pub fn take_last_error() -> Option<String> {
    LAST_ERROR.lock().take()
}

/// Return the last error code without clearing it.
pub fn last_error_code() -> i32 {
    *LAST_ERROR_CODE.lock()
}
