use alloy_provider::{Identity, Provider, ProviderBuilder, RootProvider};
use alloy_rpc_client::{BuiltInConnectionString, ClientBuilder};
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use eth_proof_backend::{
    chains::VerifierChains, error::ProofRequestError, utils::generate_ssz_proof_json,
};
use eth_proofs::{
    config::Mainnet,
    lighthouse_prover_client::LighthouseProverClient,
    proofs::{generate_blockhash_proof_from_blocks, generate_eip4788_blockhash_proof},
    types::{Eip4788BlockhashProof, OpStackProvider, VerifyingChain},
    BeaconApiClient,
};
use op_alloy_network::Optimism;
use serde::Deserialize;
use serde_json::json;
use std::{env::var, sync::Arc};
use url::Url;

#[cfg(feature = "ssz-storage")]
mod ssz_storage_imports {
    pub use alloy_primitives::{Address, B256};
    pub use eth_proofs::{
        proofs::{generate_eip4788_ssz_storage_proof, generate_ssz_storage_proof},
        types::{Eip4788SszStorageProof, SszStorageProof},
        utils::l1_block_to_beacon_slot,
    };
}

#[cfg(feature = "ssz-storage")]
pub use ssz_storage_imports::*;

struct ServerState<P, O>
where
    O: OpStackProvider,
{
    beacon_api_client: BeaconApiClient,
    lighthouse_prover_client: LighthouseProverClient,
    el_client: P,
    optimism_client: Option<O>,
}

#[derive(Deserialize)]
struct BlockhashProofQueryParams {
    /// The L1 block whose SSZ root should be proven into
    prove_into_block: u64,

    /// The L1 block number to prove the blockhash for
    prove_from_block: u64,
}

#[derive(Deserialize)]
struct Eip4788BlockhashProofQueryParams {
    /// The timestamp of the EIP-4788 block
    eip4788_timestamp: Option<u64>,

    /// The L1 block number to prove the blockhash for
    prove_from_block: u64,

    verifier_chain: VerifierChains,
}

#[cfg(feature = "ssz-storage")]
#[derive(Deserialize)]
struct ProofQueryParams {
    /// The L1 block number of the SSZ root
    beacon_root_block_number: u64,

    /// The L1 block number at which to prove the storage slot
    storage_block_number: u64,

    /// The address of the storage slot
    address: Address,

    /// The key of the storage slot
    slot: B256,
}

#[cfg(feature = "ssz-storage")]
#[derive(Deserialize)]
struct Eip4788ProofQueryParams {
    eip4788_timestamp: Option<u64>,

    /// The L1 block number at which to prove the storage slot
    storage_block_number: u64,

    /// The address of the storage slot
    address: Address,

    /// The key of the storage slot
    storage_slot: B256,

    verifier_chain: VerifierChains,
}

#[tokio::main]
async fn main() {
    let beacon_rpc = &var("BEACON_URL").expect("BEACON_URL not set");
    let beacon_api_client = BeaconApiClient::new(Url::parse(beacon_rpc).unwrap());

    let el_rpc = &var("RPC_URL").expect("RPC_URL not set");
    let el_client = ProviderBuilder::new()
        .on_builtin(el_rpc)
        .await
        .expect("Failed to create provider");

    let lighthouse_prover_rpc =
        &var("LIGHTHOUSE_PROVER_RPC_URL").expect("LIGHTHOUSE_PROVER_RPC_URL not set");
    let lighthouse_prover_client = LighthouseProverClient::new(lighthouse_prover_rpc);

    let optimism_client = match &var("OPTIMISM_RPC_URL") {
        Ok(optimism_rpc) => {
            let connect: BuiltInConnectionString = optimism_rpc.parse().unwrap();
            let client = ClientBuilder::default()
                .connect_boxed(connect)
                .await
                .unwrap();
            let optimism_client = ProviderBuilder::<Identity, Identity, Optimism>::default()
                .on_provider(RootProvider::new(client));

            Some(optimism_client)
        }
        Err(_) => None,
    };

    let state = Arc::new(ServerState {
        beacon_api_client,
        lighthouse_prover_client,
        el_client: Box::new(el_client),
        optimism_client,
    });

    #[cfg(not(feature = "ssz-storage"))]
    let app = Router::new()
        .route(
            "/generate_blockhash_proof",
            get(handle_blockhash_proof_request),
        )
        .route(
            "/generate_fixed_blockhash_proof",
            get(handle_eip4788_blockhash_proof_request),
        )
        .with_state(state);

    #[cfg(feature = "ssz-storage")]
    let app = Router::new()
        .route("/generate_proof", get(handle_proof_request))
        .route("/generate_eip4788_proof", get(handle_eip4788_proof_request))
        .route(
            "/generate_blockhash_proof",
            get(handle_blockhash_proof_request),
        )
        .route(
            "/generate_fixed_blockhash_proof",
            get(handle_eip4788_blockhash_proof_request),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn handle_blockhash_proof_request<P: Provider, O: OpStackProvider>(
    State(state): State<Arc<ServerState<P, O>>>,
    Query(params): Query<BlockhashProofQueryParams>,
) -> Result<Json<serde_json::Value>, ProofRequestError> {
    let ssz_proof = generate_blockhash_proof_from_blocks::<Mainnet>(
        &state.el_client,
        &state.beacon_api_client,
        &state.lighthouse_prover_client,
        params.prove_into_block,
        params.prove_from_block,
    )
    .await?;

    Ok(Json(json!({
        "ssz_proof": generate_ssz_proof_json(&ssz_proof),
    })))
}

async fn handle_eip4788_blockhash_proof_request<P: Provider, O: OpStackProvider>(
    State(state): State<Arc<ServerState<P, O>>>,
    Query(params): Query<Eip4788BlockhashProofQueryParams>,
) -> Result<Json<serde_json::Value>, ProofRequestError> {
    let verifier_chain = match params.verifier_chain {
        VerifierChains::Mainnet => VerifyingChain::Mainnet,
        VerifierChains::Optimism => VerifyingChain::OpStack {
            op_stack_client: state.optimism_client.as_ref().ok_or(
                ProofRequestError::OPStackClientNotInitialized {
                    chain: VerifierChains::Optimism,
                },
            )?,
        },
    };

    let Eip4788BlockhashProof {
        blockhash_proof,
        eip4788_timestamp,
    } = generate_eip4788_blockhash_proof::<Mainnet, O>(
        &state.el_client,
        &state.beacon_api_client,
        &state.lighthouse_prover_client,
        params.eip4788_timestamp,
        params.prove_from_block,
        verifier_chain,
    )
    .await?;

    Ok(Json(json!({
        "ssz_proof": generate_ssz_proof_json(&blockhash_proof),
        "eip4788_timestamp": eip4788_timestamp,
    })))
}

#[cfg(feature = "ssz-storage")]
async fn handle_proof_request<P: Provider, O: OpStackProvider>(
    State(state): State<Arc<ServerState<P, O>>>,
    Query(params): Query<ProofQueryParams>,
) -> Result<Json<serde_json::Value>, ProofRequestError> {
    let ssz_root_beacon_slot =
        l1_block_to_beacon_slot::<Mainnet>(&state.el_client, params.beacon_root_block_number)
            .await?;

    let storage_slot_proof: SszStorageProof = generate_ssz_storage_proof::<Mainnet>(
        &state.el_client,
        &state.lighthouse_prover_client,
        &state.beacon_api_client,
        ssz_root_beacon_slot,
        params.storage_block_number,
        &params.address,
        &params.slot,
    )
    .await?;

    let ssz_proof = generate_ssz_proof_json(&storage_slot_proof.ssz_proof)
        .ok_or(ProofRequestError::JsonifyUnsupportedHardfork)?;

    Ok(Json(json!(
        {
            "beacon_root_block_number": params.beacon_root_block_number,
            "storage_block_number": params.storage_block_number,
            "rlp_block_header": storage_slot_proof.rlp_block_header,
            "storage_proof": storage_slot_proof.storage_proof,
            "ssz_proof": ssz_proof,
        }
    )))
}

#[cfg(feature = "ssz-storage")]
async fn handle_eip4788_proof_request<P: Provider, O: OpStackProvider>(
    State(state): State<Arc<ServerState<P, O>>>,
    Query(params): Query<Eip4788ProofQueryParams>,
) -> Result<Json<serde_json::Value>, ProofRequestError> {
    let verifier_chain = match params.verifier_chain {
        VerifierChains::Mainnet => VerifyingChain::Mainnet,
        VerifierChains::Optimism => VerifyingChain::OpStack {
            op_stack_client: state.optimism_client.as_ref().ok_or(
                ProofRequestError::OPStackClientNotInitialized {
                    chain: VerifierChains::Optimism,
                },
            )?,
        },
    };

    let Eip4788SszStorageProof {
        ssz_storage_proof,
        eip4788_timestamp,
    } = generate_eip4788_ssz_storage_proof::<_, Mainnet>(
        &state.el_client,
        &state.lighthouse_prover_client,
        &state.beacon_api_client,
        params.eip4788_timestamp,
        params.storage_block_number,
        &params.address,
        &params.storage_slot,
        verifier_chain,
    )
    .await?;

    let ssz_proof = generate_ssz_proof_json(&ssz_storage_proof.ssz_proof)
        .ok_or(ProofRequestError::JsonifyUnsupportedHardfork)?;

    Ok(Json(json!({
        "storage_block_number": params.storage_block_number,
        "rlp_block_header": ssz_storage_proof.rlp_block_header,
        "storage_proof": ssz_storage_proof.storage_proof,
        "ssz_proof": ssz_proof,
        "eip4788_timestamp": eip4788_timestamp,
    })))
}
