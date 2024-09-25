use crate::chains::VerifierChains;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use eth_proofs::error::{BlockhashProofGenerationError, SszStorageProofGenerationError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofRequestError {
    #[error(transparent)]
    SszStorageProofGenerationFailed(#[from] SszStorageProofGenerationError),
    #[error(transparent)]
    BlockhashProofGenerationFailed(#[from] BlockhashProofGenerationError),
    #[error("OPStack client not initialized")]
    OPStackClientNotInitialized { chain: VerifierChains },
    #[error("Failed to jsonify. Unsupported hardfork")]
    JsonifyUnsupportedHardfork,
}

impl IntoResponse for ProofRequestError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ProofRequestError::SszStorageProofGenerationFailed(ref e) => match e {
                SszStorageProofGenerationError::StorageProof => {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("{}.", self))
                }
                SszStorageProofGenerationError::RlpEncoding => {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("{}.", self))
                }
                SszStorageProofGenerationError::BlockHeaderFetch => {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("{}.", self))
                }
                SszStorageProofGenerationError::SszProof(e_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}. {}.", self, e_),
                ),
                SszStorageProofGenerationError::FailedRpcCall(e_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}. {:?}.", self, e_),
                ),
            },
            ProofRequestError::BlockhashProofGenerationFailed(ref e) => match e {
                BlockhashProofGenerationError::TimestampBeforeEcotoneHardfork => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}. {}.", self, e),
                ),
                BlockhashProofGenerationError::InvalidTimestamp => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}. {}.", self, e),
                ),
                BlockhashProofGenerationError::FailedToFetchProof { slot, path } => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to fetch proof for slot: {}, path: {:?}", slot, path),
                ),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}.", self)),
            },
            ProofRequestError::OPStackClientNotInitialized { ref chain } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {:?}", self, chain),
            ),
            ProofRequestError::JsonifyUnsupportedHardfork => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{}.", self))
            }
        };

        (status, error_message).into_response()
    }
}
