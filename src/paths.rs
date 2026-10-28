//! Private per-user locations for configuration and state.
//!
//! Paths are always derived from the running user's environment, never from the
//! build machine. macOS keeps its Application Support directory; Linux follows
//! the XDG base directory specification.
use std::path::{Path, PathBuf};

fn home() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| anyhow::anyhow!("Home directory unavailable"))
}

/// Empty or relative XDG values count as unset, per the base directory rules.
fn absolute(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

#[cfg(target_os = "macos")]
fn support() -> anyhow::Result<PathBuf> {
    Ok(home()?.join("Library/Application Support/MiClip"))
}

pub fn config_dir() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        support()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(absolute(std::env::var_os("XDG_CONFIG_HOME"))
            .unwrap_or(home()?.join(".config"))
            .join("mi-clip"))
    }
}

pub fn state_dir() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        support()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(absolute(std::env::var_os("XDG_STATE_HOME"))
            .unwrap_or(home()?.join(".local/state"))
            .join("mi-clip"))
    }
}

pub fn default_config() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

/// Incoming phone shares land in the user's Downloads directory unless the
/// account configuration names another directory.
pub fn receive_dir() -> anyhow::Result<PathBuf> {
    Ok(home()?.join("Downloads"))
}

/// Create a directory readable by this user only.
pub fn ensure_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_absolute_xdg_values_are_used() {
        assert_eq!(absolute(None), None);
        assert_eq!(absolute(Some("".into())), None);
        assert_eq!(absolute(Some("relative/place".into())), None);
        assert_eq!(
            absolute(Some("/synthetic/xdg".into())),
            Some(PathBuf::from("/synthetic/xdg"))
        );
        if let Ok(home) = home() {
            assert!(home.is_absolute());
        }
    }
}
