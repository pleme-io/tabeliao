use thiserror::Error;

#[derive(Debug, Error)]
pub enum TabeliaoError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("yaml parse error in {path}: {source}")]
    Yaml {
        path: String,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("cartorio admit failed: {status} {message}")]
    AdmitRejected { status: u16, message: String },

    #[error("lacre push failed: {status} {message}")]
    PushRejected { status: u16, message: String },

    #[error("network error talking to {target}: {source}")]
    Network {
        target: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, TabeliaoError>;
