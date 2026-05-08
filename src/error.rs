use thiserror::Error;

#[derive(Debug, Error)]
pub enum HajizError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("isolation error: {0}")]
    Isolation(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
