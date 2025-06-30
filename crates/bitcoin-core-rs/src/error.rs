use thiserror::Error;

#[derive(Error, Debug)]
pub enum BitcoinError {
    #[error("Failed to compute next work required")]
    WorkRequirementError,
}

pub type Result<T> = std::result::Result<T, BitcoinError>;
