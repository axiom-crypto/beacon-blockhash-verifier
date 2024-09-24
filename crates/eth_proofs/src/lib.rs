pub mod config;
pub mod error;
pub mod lighthouse_prover_client;
pub mod proofs;
pub mod types;
pub mod utils;

pub use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId};

#[cfg(test)]
pub mod test;
