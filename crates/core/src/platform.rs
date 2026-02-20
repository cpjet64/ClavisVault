use std::path::PathBuf;

use anyhow::{Result, anyhow};

pub trait Platform {
    fn data_dir() -> PathBuf;
    fn config_dir() -> PathBuf;
    fn set_autostart(enabled: bool, minimized: bool) -> Result<()>;
    fn create_tray_icon(icon_name: &str) -> Result<()>;
}

pub struct WindowsPlatform;
pub struct MacOsPlatform;
pub struct LinuxPlatform;

impl Platform for WindowsPlatform {
    fn data_dir() -> PathBuf {
        dirs::data_local_dir().unwrap_or_else(std::env::temp_dir)
    }

    fn config_dir() -> PathBuf {
        dirs::config_dir().unwrap_or_else(std::env::temp_dir)
    }

    fn set_autostart(enabled: bool, minimized: bool) -> Result<()> {
        write_autostart_state("windows", enabled, minimized)
    }

    fn create_tray_icon(icon_name: &str) -> Result<()> {
        validate_icon_name(icon_name)
    }
}

impl Platform for MacOsPlatform {
    fn data_dir() -> PathBuf {
        dirs::data_local_dir().unwrap_or_else(std::env::temp_dir)
    }

    fn config_dir() -> PathBuf {
        dirs::config_dir().unwrap_or_else(std::env::temp_dir)
    }

    fn set_autostart(enabled: bool, minimized: bool) -> Result<()> {
        write_autostart_state("macos", enabled, minimized)
    }

    fn create_tray_icon(icon_name: &str) -> Result<()> {
        validate_icon_name(icon_name)
    }
}

impl Platform for LinuxPlatform {
    fn data_dir() -> PathBuf {
        dirs::data_local_dir().unwrap_or_else(std::env::temp_dir)
    }

    fn config_dir() -> PathBuf {
        dirs::config_dir().unwrap_or_else(std::env::temp_dir)
    }

    fn set_autostart(enabled: bool, minimized: bool) -> Result<()> {
        write_autostart_state("linux", enabled, minimized)
    }

    fn create_tray_icon(icon_name: &str) -> Result<()> {
        validate_icon_name(icon_name)
    }
}

pub fn current_platform_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        return WindowsPlatform::data_dir();
    }
    #[cfg(target_os = "macos")]
    {
        return MacOsPlatform::data_dir();
    }
    #[cfg(target_os = "linux")]
    {
        return LinuxPlatform::data_dir();
    }
    #[allow(unreachable_code)]
    std::env::temp_dir()
}

pub fn current_platform_config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        return WindowsPlatform::config_dir();
    }
    #[cfg(target_os = "macos")]
    {
        return MacOsPlatform::config_dir();
    }
    #[cfg(target_os = "linux")]
    {
        return LinuxPlatform::config_dir();
    }
    #[allow(unreachable_code)]
    std::env::temp_dir()
}

fn validate_icon_name(icon_name: &str) -> Result<()> {
    if icon_name.trim().is_empty() {
        return Err(anyhow!("icon name must not be empty"));
    }
    Ok(())
}

fn write_autostart_state(platform: &str, enabled: bool, minimized: bool) -> Result<()> {
    let dir = current_platform_config_dir().join("clavisvault");
    std::fs::create_dir_all(&dir)?;
    let state = serde_json::json!({
        "platform": platform,
        "enabled": enabled,
        "minimized": minimized,
    });
    let rendered = serde_json::to_vec_pretty(&state)?;
    std::fs::write(dir.join("autostart.json"), rendered)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_dirs_resolve() {
        assert!(WindowsPlatform::data_dir().exists());
        assert!(MacOsPlatform::config_dir().exists());
        assert!(LinuxPlatform::data_dir().exists());
    }

    #[test]
    fn macos_data_dir_and_linux_config_dir_are_resolved() {
        assert!(MacOsPlatform::data_dir().exists());
        assert!(LinuxPlatform::config_dir().exists());
    }

    #[test]
    fn icon_validation_rejects_empty() {
        assert!(WindowsPlatform::create_tray_icon("").is_err());
        assert!(WindowsPlatform::create_tray_icon("clavis").is_ok());
    }

    #[test]
    fn autostart_state_write_works() {
        LinuxPlatform::set_autostart(true, true).expect("autostart write should work");
    }

    #[test]
    fn all_platform_helpers_are_callable() {
        WindowsPlatform::set_autostart(false, false).expect("windows autostart write should work");
        MacOsPlatform::set_autostart(false, true).expect("macos autostart write should work");
        LinuxPlatform::set_autostart(true, false).expect("linux autostart write should work");

        assert!(MacOsPlatform::create_tray_icon("tray").is_ok());
        assert!(LinuxPlatform::create_tray_icon("tray").is_ok());

        let data_dir = current_platform_data_dir();
        let config_dir = current_platform_config_dir();
        assert!(data_dir.exists());
        assert!(config_dir.exists());
    }
}
