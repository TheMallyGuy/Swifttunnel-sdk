pub const ROBLOX_PROCESS_NAMES: &[&str] = &[
    "robloxplayerbeta.exe",
    "robloxplayerlauncher.exe",
    "robloxcrashhandler.exe",
    "robloxstudiolauncher.exe",
    "robloxstudioinstaller.exe",
    "robloxplayerinstaller.exe",
];

pub const STRAPPER_PROCESS_NAMES: &[&str] = &[
    "bloxstrap.exe",
    "fishstrap.exe",
    "froststrap.exe",
    "bubblestrap.exe",
];

/// True for Roblox Studio and its launcher/installer (everything whose name
/// stems from `robloxstudio`).
///
/// Studio is a developer tool, not a game client — it never joins the game
/// servers Route Assist optimizes for. Relaying it adds nothing and breaks
/// Team Create, whose place-sync TCP exceeds the relay's forward buffer
/// ("connectToTeamCreateSession: no response"). So it is dropped from the relay
/// set outside country-ban bypass (where Studio still needs the relay just to
/// reach a blocked Roblox). It stays in `ROBLOX_PROCESS_NAMES` for detection.
pub fn is_roblox_studio_process_name(process_name: &str) -> bool {
    let file_name = std::path::Path::new(process_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(process_name);
    file_name.to_ascii_lowercase().starts_with("robloxstudio")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn studio_processes_are_recognized_and_players_are_not() {
        for studio in [
            "RobloxStudioBeta.exe",
            "robloxstudio.exe",
            "RobloxStudioLauncherBeta.exe",
            "RobloxStudioInstaller.exe",
            r"C:\Users\me\AppData\Local\Roblox\Versions\v1\RobloxStudioBeta.exe",
        ] {
            assert!(
                is_roblox_studio_process_name(studio),
                "expected {studio} to be recognized as Studio"
            );
        }
        for not_studio in [
            "RobloxPlayerBeta.exe",
            "robloxplayer.exe",
            "robloxplayerlauncher.exe",
            "chrome.exe",
        ] {
            assert!(
                !is_roblox_studio_process_name(not_studio),
                "expected {not_studio} NOT to be Studio"
            );
        }
    }
}
