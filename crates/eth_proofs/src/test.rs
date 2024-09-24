use crate::config::Mainnet;
use crate::lighthouse_prover_client::LighthouseProverClient;
use crate::proofs::{
    generate_blockhash_proof, generate_blockhash_proof_from_blocks,
    generate_eip4788_blockhash_proof, generate_storage_proof, verify_blockhash_proof,
};
use crate::types::{Eip4788BlockhashProof, L1Provider, SszProof, VerifyingChain};
use alloy_primitives::{Address, FixedBytes, B256};
use alloy_provider::{Identity, Provider, ProviderBuilder, RootProvider};
use alloy_rpc_client::{BuiltInConnectionString, ClientBuilder};
use alloy_rpc_types_eth::{BlockId, TransactionRequest};
use alloy_transport::BoxTransport;
use beacon_api_client::{mainnet::MainnetClientTypes, Client};
use url::Url;
use op_alloy_network::Optimism;
use std::env::var;
use std::str::FromStr;

struct TestState<P>
where
    P: L1Provider,
{
    el_client: P,
    beacon_api_client: Client<MainnetClientTypes>,
    lighthouse_prover_client: LighthouseProverClient,
}

async fn setup() -> TestState<impl L1Provider> {
    let el_rpc = &var("RPC_URL_1").expect("RPC_URL_1 not set");
    let el_client = ProviderBuilder::new()
        .on_builtin(el_rpc)
        .await
        .expect("Failed to create provider");

    let rpc = &var("BEACON_URL_1").expect("BEACON_URL_1 not set");
    let beacon_api_client = Client::new(Url::parse(rpc).unwrap());
    let lighthouse_prover_client = LighthouseProverClient::new(
        &var("LIGHTHOUSE_PROVER_RPC_URL").expect("LIGHTHOUSE_PROVER_RPC_URL not set"),
    );

    TestState {
        el_client,
        beacon_api_client,
        lighthouse_prover_client,
    }
}

#[ignore]
#[tokio::test]
async fn test_storage_proof() {
    let el_rpc = &var("RPC_URL_1").expect("RPC_URL_1 not set");
    let el_provider = ProviderBuilder::new()
        .on_builtin(el_rpc)
        .await
        .expect("Failed to create provider");

    generate_storage_proof(
        &el_provider,
        &Address::parse_checksummed("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640", None).unwrap(),
        &<B256 as FromStr>::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        &BlockId::Hash(
            B256::from_str("0x7fcbd769d0814eba701225bb961fd18011b275109f57db3706058aaa4831df80")
                .unwrap()
                .into(),
        ),
    )
    .await
    .unwrap();
}

#[ignore]
#[tokio::test]
async fn test_current_block_proof() {
    let state = setup().await;
    let beacon_api_client = state.beacon_api_client;

    let proof = generate_blockhash_proof::<Mainnet>(
        &beacon_api_client,
        &state.lighthouse_prover_client,
        9568224,
        9568224,
    )
    .await
    .unwrap();

    verify_blockhash_proof(&proof).expect("Failed to verify blockhash proof");

    assert!(matches!(proof, SszProof::CurrentBlock { .. }));
}

#[ignore]
#[tokio::test]
async fn test_recent_historical_block_proof() {
    let state = setup().await;
    let beacon_api_client = state.beacon_api_client;

    let proof = generate_blockhash_proof::<Mainnet>(
        &beacon_api_client,
        &state.lighthouse_prover_client,
        9568224,
        9568000,
    )
    .await
    .unwrap();

    verify_blockhash_proof(&proof).expect("Failed to verify blockhash proof");

    assert!(matches!(proof, SszProof::RecentHistoricalBlock { .. }));
}

#[ignore]
#[tokio::test]
async fn test_historical_block_proof() {
    let state = setup().await;
    let beacon_api_client = state.beacon_api_client;

    let proof = generate_blockhash_proof::<Mainnet>(
        &beacon_api_client,
        &state.lighthouse_prover_client,
        9568224,
        9560000,
    )
    .await
    .unwrap();

    verify_blockhash_proof(&proof).expect("Failed to verify blockhash proof");

    assert!(matches!(proof, SszProof::HistoricalBlock { .. }));
}

#[ignore = "lighthouse node is down"]
#[tokio::test]
async fn test_blockhash_proof_from_blocks() {
    let state = setup().await;
    let el_client = state.el_client;
    let beacon_api_client = state.beacon_api_client;
    let lighthouse_prover_client = state.lighthouse_prover_client;

    let proof = generate_blockhash_proof_from_blocks::<Mainnet>(
        &el_client,
        &beacon_api_client,
        &lighthouse_prover_client,
        20361359,
        20361359,
    )
    .await
    .unwrap();

    verify_blockhash_proof(&proof).expect("Failed to verify blockhash proof");
}

#[ignore]
#[tokio::test]
async fn test_eip4788_blockhash_proof_mainnet() {
    let state = setup().await;
    let el_client = state.el_client;
    let beacon_api_client = state.beacon_api_client;
    let lighthouse_prover_client = state.lighthouse_prover_client;

    let Eip4788BlockhashProof {
        blockhash_proof,
        eip4788_timestamp,
    } = generate_eip4788_blockhash_proof::<Mainnet, RootProvider<BoxTransport, Optimism>>(
        &el_client,
        &beacon_api_client,
        &lighthouse_prover_client,
        None,
        20361359,
        VerifyingChain::Mainnet,
    )
    .await
    .expect("Failed to generate blockhash proof");

    verify_blockhash_proof(&blockhash_proof).expect("Failed to verify blockhash proof");

    let beacon_roots_contract =
        Address::from_str("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").unwrap();

    let mut calldata = vec![0u8; 24];
    calldata.append(eip4788_timestamp.to_be_bytes().to_vec().as_mut());
    let tx = TransactionRequest::default()
        .to(beacon_roots_contract)
        .input(calldata.into());

    let returndata = el_client.call(&tx).await.expect("Failed to call contract");

    let root = returndata.to_vec();
    let root = <FixedBytes<32> as TryFrom<&[u8]>>::try_from(root.as_slice())
        .expect("Failed to parse root");

    let proof_root = match blockhash_proof {
        SszProof::CurrentBlock {
            curr_state_root_proof,
            ..
        } => curr_state_root_proof.witness,
        SszProof::RecentHistoricalBlock {
            curr_state_root_proof,
            ..
        } => curr_state_root_proof.witness,
        SszProof::HistoricalBlock {
            curr_state_root_proof,
            ..
        } => curr_state_root_proof.witness,
        _ => panic!("Should never be a pre merge block"),
    };

    assert_eq!(root, proof_root);
}

#[ignore]
#[tokio::test]
async fn test_eip4788_blockhash_proof_optimism() {
    let optimism_rpc = &var("RPC_URL_10").expect("RPC_URL_10 not set");
    let connect: BuiltInConnectionString = optimism_rpc.parse().unwrap();
    let client = ClientBuilder::default()
        .connect_boxed(connect)
        .await
        .unwrap();
    let optimism_client = ProviderBuilder::<Identity, Identity, Optimism>::default()
        .on_provider(RootProvider::new(client));

    let state = setup().await;
    let el_client = state.el_client;
    let beacon_api_client = state.beacon_api_client;
    let lighthouse_prover_client = state.lighthouse_prover_client;

    let Eip4788BlockhashProof {
        blockhash_proof,
        eip4788_timestamp,
    } = generate_eip4788_blockhash_proof::<Mainnet, RootProvider<BoxTransport, Optimism>>(
        &el_client,
        &beacon_api_client,
        &lighthouse_prover_client,
        None,
        20361359,
        VerifyingChain::OpStack {
            op_stack_client: &optimism_client,
        },
    )
    .await
    .expect("Failed to generate blockhash proof");

    verify_blockhash_proof(&blockhash_proof).expect("Failed to verify blockhash proof");

    let beacon_roots_contract =
        Address::from_str("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").unwrap();

    let mut calldata = vec![0u8; 24];
    calldata.append(eip4788_timestamp.to_be_bytes().to_vec().as_mut());
    let tx = TransactionRequest::default()
        .to(beacon_roots_contract)
        .input(calldata.into());

    let returndata = optimism_client
        .call(&tx)
        .await
        .expect("Failed to call contract");

    let root = returndata.to_vec();
    let root = <FixedBytes<32> as TryFrom<&[u8]>>::try_from(root.as_slice())
        .expect("Failed to parse root");

    let proof_root = match blockhash_proof {
        SszProof::CurrentBlock {
            curr_state_root_proof,
            ..
        } => curr_state_root_proof.witness,
        SszProof::RecentHistoricalBlock {
            curr_state_root_proof,
            ..
        } => curr_state_root_proof.witness,
        SszProof::HistoricalBlock {
            curr_state_root_proof,
            ..
        } => curr_state_root_proof.witness,
        _ => panic!("Should never be a pre merge block"),
    };

    assert_eq!(root, proof_root);
}
