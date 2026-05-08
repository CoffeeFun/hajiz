use std::path::Path;
use crate::error::HajizError;
use super::schema::Profile;

/// Charge un profil TOML depuis un fichier
pub fn load_profile(path: &Path) -> Result<Profile, HajizError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        HajizError::Config(format!(
            "impossible de lire le profil '{}': {e}",
            path.display()
        ))
    })?;

    toml::from_str(&content).map_err(|e| {
        HajizError::Config(format!(
            "profil invalide '{}': {e}",
            path.display()
        ))
    })
}