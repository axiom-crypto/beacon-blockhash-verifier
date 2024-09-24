use alloy_transport::TransportError;
use ssz_rs::PathElement;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockhashProofGenerationError {
    #[error("Failed to convert block number to slot")]
    FailedToConvertBlockNumberToSlot,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Timestamp before ecotone hardfork")]
    TimestampBeforeEcotoneHardfork,
    #[error("Prove slot is greater than ssz root slot")]
    ProveSlotGreaterThanSszRootSlot,
    #[error("Failed to get state")]
    FailedToGetState,
    #[error("Failed to generate proof")]
    FailedToGenerateProof,
    #[error("Failed to fetch proof {slot} {:?}", path)]
    FailedToFetchProof { slot: u64, path: Vec<PathElement> },
    #[error("Failed to fetch block header during blockhash proof")]
    BlockHeaderFetch,
    #[error("Unsupported hardfork")]
    UnsupportedHardfork,
    #[error(transparent)]
    FailedRpcCall(#[from] TransportError),
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid blockhash")]
    InvalidBlockhash,
    #[error("Invalid historical state root")]
    InvalidHistoricalStateRoot,
    #[error("Invalid summary root")]
    InvalidSummaryRoot,
    #[error("Invalid current state root")]
    InvalidCurrentStateRoot,
    #[error("Disconnected proofs")]
    DisconnectedProofs,
}

#[derive(Debug, Error)]
pub enum SszStorageProofGenerationError {
    #[error("Failed to generate storage proof")]
    StorageProof,
    #[error("Failed to fetch block header during storage proof")]
    BlockHeaderFetch,
    #[error("Failed to rlp encode block header")]
    RlpEncoding,
    #[error(transparent)]
    FailedRpcCall(#[from] TransportError),
    #[error(transparent)]
    SszProof(#[from] BlockhashProofGenerationError),
}
