use std::path::Path;
use crate::error::HajizError;
use super::schema::Profile;

/// Loads a TOML profile from a file
pub fn load_profile(path: &Path) -> Result<Profile, HajizError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        HajizError::Config(format!(
            "unable to read profile '{}': {e}",
            path.display()
        ))
    })?;

    toml::from_str(&content).map_err(|e| {
        HajizError::Config(format!(
            "invalid profile '{}': {e}",
            path.display()
        ))
    })
}