use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("WireGuard parse error in section [{section}], field '{field}': {message}")]
    WgParseError {
        section: String,
        field: String,
        message: String,
    },

    #[error("Configuration validation error: {0}")]
    ValidationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Command execution failed for '{cmd}': {message}")]
    CommandError {
        cmd: String,
        message: String,
    },

    #[error("Transaction failed ({stage}): {message}")]
    TransactionError {
        stage: String,
        message: String,
    },

    #[error("sing-box error: {0}")]
    SingBoxError(String),

    #[error("System error: {0}")]
    SystemError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ChainError>;
