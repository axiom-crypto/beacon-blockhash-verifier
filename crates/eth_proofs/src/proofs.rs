use crate::error::SszStorageProofGenerationError;
use crate::types::{
    Eip4788BlockhashProof, Eip4788SszStorageProof, L1Provider, OpStackProvider, OutputAtBlock,
    SszProof, SszProofSegment, SszStorageProof, VerifyingChain,
};
use crate::utils::{l1_block_to_beacon_slot, l1_timestamp_to_beacon_slot};
use crate::{
    config::{ChainConfig, Mainnet},
    error::{BlockhashProofGenerationError, VerificationError},
};
use alloy_json_rpc::RpcError;
use alloy_primitives::{hex, Address, B256};
use alloy_rpc_types_eth::{
    Block, BlockId as AlloyBlockId, BlockTransactionsKind, EIP1186AccountProofResponse,
};
use alloy_transport::TransportErrorKind;
use beacon_api_client::StateId;
use beacon_api_client::{mainnet::Client, BlockId as BeaconBlockId};
use ethereum_consensus::deneb::mainnet::SLOTS_PER_HISTORICAL_ROOT;
use ethereum_consensus::types::{mainnet::SignedBeaconBlock, BeaconState};
use ssz_rs::{PathElement, Prove};
use tokio::try_join;

/// * `client` - the beacon API client
/// * `ssz_root_slot` - the slot of the state root that is available
///    on-chain
/// * `prove_slot` - the slot of the blockhash whose proof will be generated
pub async fn generate_blockhash_proof<C: ChainConfig>(
    client: &Client,
    ssz_root_slot: u64,
    prove_slot: u64,
) -> Result<SszProof, BlockhashProofGenerationError> {
    if prove_slot > ssz_root_slot {
        return Err(BlockhashProofGenerationError::ProveSlotGreaterThanSszRootSlot);
    }
    if ssz_root_slot < C::DENEB_INIT_SLOT {
        return Err(BlockhashProofGenerationError::UnsupportedHardfork);
    }

    let beacon_block = client
        .get_beacon_block(BeaconBlockId::Slot(ssz_root_slot))
        .await
        .map_err(|_| BlockhashProofGenerationError::FailedToGetState)?;

    let beacon_block = beacon_block
        .deneb()
        .ok_or(BlockhashProofGenerationError::UnsupportedHardfork)?;

    let beacon_root_path = &[PathElement::Field("state_root".to_owned())];

    let curr_state_root_proof: SszProofSegment = beacon_block
        .message
        .prove(beacon_root_path)
        .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
        .into();

    let state = client
        .get_state(StateId::Slot(ssz_root_slot))
        .await
        .map_err(|_| BlockhashProofGenerationError::FailedToGetState)?;

    match state {
        BeaconState::Deneb(state) => {
            assert!(ssz_root_slot == state.slot);

            if prove_slot == ssz_root_slot {
                let execution_payload_path = &[PathElement::Field(
                    "latest_execution_payload_header".to_owned(),
                )];

                let execution_payload_proof = state
                    .prove(execution_payload_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let block_number_path = &[PathElement::Field("block_number".to_owned())];

                let block_number_proof = state
                    .latest_execution_payload_header
                    .prove(block_number_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let blockhash_path = &[PathElement::Field("block_hash".to_owned())];

                let blockhash_proof = state
                    .latest_execution_payload_header
                    .prove(blockhash_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                Ok(SszProof::CurrentBlock {
                    curr_state_root_proof,
                    execution_payload_proof,
                    block_number_proof,
                    blockhash_proof,
                })
            }
            // prove_slot is within `state_roots` (within the last 8192 slots of `ssz_root_slot`)
            else if prove_slot >= ssz_root_slot - SLOTS_PER_HISTORICAL_ROOT as u64 {
                // Path from `state_root` of `prove_slot` to `state_root` of `ssz_root_slot`
                let path1 = &[
                    PathElement::Field("state_roots".to_owned()),
                    PathElement::Index((prove_slot % (SLOTS_PER_HISTORICAL_ROOT as u64)) as usize),
                ];

                let hist_state_root_proof = state
                    .prove(path1)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let prove_slot_state = client
                    .get_state(StateId::Slot(prove_slot))
                    .await
                    .map_err(|_| BlockhashProofGenerationError::FailedToGetState)?;

                let prove_slot_state = prove_slot_state
                    .deneb()
                    .ok_or(BlockhashProofGenerationError::UnsupportedHardfork)?;

                let execution_payload_path = &[PathElement::Field(
                    "latest_execution_payload_header".to_owned(),
                )];

                let execution_payload_proof = prove_slot_state
                    .prove(execution_payload_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let block_number_path = &[PathElement::Field("block_number".to_owned())];

                let block_number_proof = prove_slot_state
                    .latest_execution_payload_header
                    .prove(block_number_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let blockhash_path = &[PathElement::Field("block_hash".to_owned())];

                let blockhash_proof = prove_slot_state
                    .latest_execution_payload_header
                    .prove(blockhash_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                Ok(SszProof::RecentHistoricalBlock {
                    curr_state_root_proof,
                    hist_state_root_proof,
                    execution_payload_proof,
                    block_number_proof,
                    blockhash_proof,
                })
            }
            // next_slot is within `historical_summaries`
            else {
                // We expect CAPELLA_INIT_SLOT to be divisible by SLOTS_PER_HISTORICAL_ROOT (8192) here.
                let summary_root_index =
                    (prove_slot - C::CAPELLA_INIT_SLOT) / (SLOTS_PER_HISTORICAL_ROOT as u64);

                // Prove from historical summary root to available ssz_root
                let path1 = &[
                    PathElement::Field("historical_summaries".to_owned()),
                    PathElement::Index((summary_root_index) as usize),
                    PathElement::Field("state_summary_root".to_owned()),
                ];

                let summary_root_proof = state
                    .prove(path1)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                // Prove from historical state_root to historical summary root
                //
                // We add 1 here because merkleization takes place at the
                // beginning of the next 8192-slot range.
                let merkleization_slot = (summary_root_index + 1)
                    * (SLOTS_PER_HISTORICAL_ROOT as u64)
                    + C::CAPELLA_INIT_SLOT;
                let merkleization_slot_state = client
                    .get_state(StateId::Slot(merkleization_slot))
                    .await
                    .map_err(|_| BlockhashProofGenerationError::FailedToGetState)?;

                let merkleization_slot_state = merkleization_slot_state
                    .deneb()
                    .ok_or(BlockhashProofGenerationError::UnsupportedHardfork)?;
                let state_root_index = prove_slot % (SLOTS_PER_HISTORICAL_ROOT as u64);

                let path2 = &[PathElement::Index((state_root_index) as usize)];

                let hist_state_root_proof = merkleization_slot_state
                    .state_roots
                    .prove(path2)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let prove_slot_state = client
                    .get_state(StateId::Slot(prove_slot))
                    .await
                    .map_err(|_| BlockhashProofGenerationError::FailedToGetState)?;

                let prove_slot_state = prove_slot_state
                    .deneb()
                    .ok_or(BlockhashProofGenerationError::UnsupportedHardfork)?;

                let execution_payload_path = &[PathElement::Field(
                    "latest_execution_payload_header".to_owned(),
                )];

                let execution_payload_proof = prove_slot_state
                    .prove(execution_payload_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let block_number_path = &[PathElement::Field("block_number".to_owned())];

                let block_number_proof = prove_slot_state
                    .latest_execution_payload_header
                    .prove(block_number_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                let blockhash_path = &[PathElement::Field("block_hash".to_owned())];

                let blockhash_proof = prove_slot_state
                    .latest_execution_payload_header
                    .prove(blockhash_path)
                    .map_err(|_| BlockhashProofGenerationError::FailedToGenerateProof)?
                    .into();

                Ok(SszProof::HistoricalBlock {
                    curr_state_root_proof,
                    summary_root_proof,
                    hist_state_root_proof,
                    execution_payload_proof,
                    block_number_proof,
                    blockhash_proof,
                })
            }
        }
        // BeaconState::Electra(state) => todo!(),
        _ => Err(BlockhashProofGenerationError::UnsupportedHardfork),
    }
}

pub async fn generate_blockhash_proof_from_blocks<C: ChainConfig>(
    el_client: &impl L1Provider,
    beacon_api_client: &Client,
    prove_from_block: u64,
    prove_into_block: u64,
) -> Result<SszProof, BlockhashProofGenerationError> {
    let (ssz_root_slot, prove_slot) = try_join!(
        async {
            l1_block_to_beacon_slot::<C>(&el_client, prove_from_block)
                .await
                .map_err(|_| BlockhashProofGenerationError::FailedToConvertBlockNumberToSlot)
        },
        async {
            l1_block_to_beacon_slot::<C>(&el_client, prove_into_block)
                .await
                .map_err(|_| BlockhashProofGenerationError::FailedToConvertBlockNumberToSlot)
        },
    )?;

    generate_blockhash_proof::<C>(beacon_api_client, ssz_root_slot, prove_slot).await
}

pub async fn generate_eip4788_blockhash_proof<'a, C: ChainConfig, O: OpStackProvider>(
    el_client: &impl L1Provider,
    beacon_api_client: &Client,
    eip4788_timestamp: Option<u64>,
    prove_from_block: u64,
    verifier_chain: VerifyingChain<'a, O>,
) -> Result<Eip4788BlockhashProof, BlockhashProofGenerationError> {
    let ((eip4788_timestamp, ssz_root_beacon_slot), prove_slot) = try_join!(
        async {
            derive_timestamp_for_chain::<O, C>(
                el_client,
                beacon_api_client,
                eip4788_timestamp,
                verifier_chain,
            )
            .await
        },
        async {
            l1_block_to_beacon_slot::<C>(el_client, prove_from_block)
                .await
                .map_err(|_| BlockhashProofGenerationError::FailedToConvertBlockNumberToSlot)
        }
    )?;

    let blockhash_proof =
        generate_blockhash_proof::<C>(beacon_api_client, ssz_root_beacon_slot, prove_slot).await?;

    Ok(Eip4788BlockhashProof {
        blockhash_proof,
        eip4788_timestamp,
    })
}

pub fn verify_blockhash_proof(proof: &SszProof) -> Result<(), VerificationError> {
    match proof {
        SszProof::CurrentBlock {
            curr_state_root_proof,
            execution_payload_proof,
            block_number_proof,
            blockhash_proof,
        } => {
            let SszProofSegment {
                proof: curr_state_root_proof,
                witness: beacon_block_root,
                ..
            } = curr_state_root_proof;
            curr_state_root_proof
                .verify(*beacon_block_root)
                .map_err(|_| VerificationError::InvalidCurrentStateRoot)?;

            let SszProofSegment {
                proof: execution_payload_proof,
                witness: curr_state_root,
                ..
            } = execution_payload_proof;

            if *curr_state_root != curr_state_root_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            execution_payload_proof
                .verify(*curr_state_root)
                .map_err(|_| VerificationError::DisconnectedProofs)?;

            let SszProofSegment {
                proof: block_number_proof,
                witness: execution_payload_root,
                ..
            } = block_number_proof;

            if *execution_payload_root != execution_payload_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            block_number_proof
                .verify(*execution_payload_root)
                .map_err(|_| VerificationError::DisconnectedProofs)?;

            let SszProofSegment {
                proof: blockhash_proof,
                witness: execution_payload_root,
                ..
            } = blockhash_proof;

            if *execution_payload_root != execution_payload_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            blockhash_proof
                .verify(*execution_payload_root)
                .map_err(|_| VerificationError::InvalidBlockhash)?;

            Ok(())
        }
        SszProof::RecentHistoricalBlock {
            curr_state_root_proof,
            hist_state_root_proof,
            execution_payload_proof,
            block_number_proof,
            blockhash_proof,
        } => {
            let SszProofSegment {
                proof: curr_state_root_proof,
                witness: beacon_block_root,
                ..
            } = curr_state_root_proof;
            curr_state_root_proof
                .verify(*beacon_block_root)
                .map_err(|_| VerificationError::InvalidCurrentStateRoot)?;

            let SszProofSegment {
                proof: hist_state_root_proof,
                witness: curr_state_root,
                ..
            } = hist_state_root_proof;

            if *curr_state_root != curr_state_root_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            hist_state_root_proof
                .verify(*curr_state_root)
                .map_err(|_| VerificationError::InvalidHistoricalStateRoot)?;

            let SszProofSegment {
                proof: execution_payload_proof,
                witness: recent_historical_state_root,
                ..
            } = execution_payload_proof;

            if *recent_historical_state_root != hist_state_root_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }
            execution_payload_proof
                .verify(*recent_historical_state_root)
                .map_err(|_| VerificationError::DisconnectedProofs)?;

            let SszProofSegment {
                proof: block_number_proof,
                witness: execution_payload_root,
                ..
            } = block_number_proof;

            if *execution_payload_root != execution_payload_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            block_number_proof
                .verify(*execution_payload_root)
                .map_err(|_| VerificationError::DisconnectedProofs)?;

            let SszProofSegment {
                proof: blockhash_proof,
                witness: execution_payload_root,
                ..
            } = blockhash_proof;

            if *execution_payload_root != execution_payload_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            blockhash_proof
                .verify(*execution_payload_root)
                .map_err(|_| VerificationError::InvalidBlockhash)?;

            Ok(())
        }
        SszProof::HistoricalBlock {
            curr_state_root_proof,
            summary_root_proof,
            hist_state_root_proof,
            execution_payload_proof,
            block_number_proof,
            blockhash_proof,
        } => {
            let SszProofSegment {
                proof: curr_state_root_proof,
                witness: beacon_block_root,
                ..
            } = curr_state_root_proof;
            curr_state_root_proof
                .verify(*beacon_block_root)
                .map_err(|_| VerificationError::InvalidCurrentStateRoot)?;

            let SszProofSegment {
                proof: summary_root_proof,
                witness: curr_state_root,
                ..
            } = summary_root_proof;

            if *curr_state_root != curr_state_root_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            summary_root_proof
                .verify(*curr_state_root)
                .map_err(|_| VerificationError::InvalidSummaryRoot)?;

            let SszProofSegment {
                proof: hist_state_root_proof,
                witness: summary_root,
                ..
            } = hist_state_root_proof;

            if *summary_root != summary_root_proof.leaf {
                return Err(VerificationError::InvalidSummaryRoot);
            }

            hist_state_root_proof
                .verify(*summary_root)
                .map_err(|_| VerificationError::InvalidHistoricalStateRoot)?;

            let SszProofSegment {
                proof: execution_payload_proof,
                witness: hist_state_root,
                ..
            } = execution_payload_proof;

            if *hist_state_root != hist_state_root_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }
            execution_payload_proof
                .verify(*hist_state_root)
                .map_err(|_| VerificationError::DisconnectedProofs)?;

            let SszProofSegment {
                proof: block_number_proof,
                witness: execution_payload_root,
                ..
            } = block_number_proof;

            if *execution_payload_root != execution_payload_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            block_number_proof
                .verify(*execution_payload_root)
                .map_err(|_| VerificationError::DisconnectedProofs)?;

            let SszProofSegment {
                proof: blockhash_proof,
                witness: execution_payload_root,
                ..
            } = blockhash_proof;

            if *execution_payload_root != execution_payload_proof.leaf {
                return Err(VerificationError::DisconnectedProofs);
            }

            blockhash_proof
                .verify(*execution_payload_root)
                .map_err(|_| VerificationError::InvalidBlockhash)?;

            Ok(())
        }
        SszProof::PreMergeBlock {} => todo!(),
    }
}

pub async fn generate_storage_proof(
    client: &impl L1Provider,
    address: &Address,
    storage_slot: &B256,
    block_id: &AlloyBlockId,
) -> Result<EIP1186AccountProofResponse, RpcError<TransportErrorKind>> {
    client
        .get_proof(*address, vec![*storage_slot])
        .block_id(*block_id)
        .await
}

pub async fn generate_ssz_storage_proof<C: ChainConfig>(
    el_client: &impl L1Provider,
    beacon_api_client: &Client,
    ssz_root_beacon_slot: u64,
    storage_block_number: u64,
    address: &Address,
    storage_slot: &B256,
) -> Result<SszStorageProof, SszStorageProofGenerationError> {
    let storage_block_id: AlloyBlockId = <u64 as Into<AlloyBlockId>>::into(storage_block_number);

    let storage_block = el_client
        .get_block(storage_block_id, BlockTransactionsKind::Hashes)
        .await
        .map_err(|_| SszStorageProofGenerationError::BlockHeaderFetch)?
        .ok_or(SszStorageProofGenerationError::BlockHeaderFetch)?;

    let storage_block_header: alloy_consensus::Header = storage_block
        .header
        .try_into()
        .map_err(|_| SszStorageProofGenerationError::RlpEncoding)?;

    let rlp_block_header = hex::encode(alloy_rlp::encode(&storage_block_header));

    let storage_proof = generate_storage_proof(el_client, address, storage_slot, &storage_block_id)
        .await
        .map_err(|_| SszStorageProofGenerationError::StorageProof)?;

    // Should never panic
    let storage_beacon_slot =
        l1_timestamp_to_beacon_slot::<C>(storage_block_header.timestamp).unwrap();

    let ssz_proof = generate_blockhash_proof::<Mainnet>(
        beacon_api_client,
        ssz_root_beacon_slot,
        storage_beacon_slot,
    )
    .await?;

    Ok(SszStorageProof {
        rlp_block_header,
        storage_proof,
        ssz_proof,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn generate_eip4788_ssz_storage_proof<'a, O: OpStackProvider, C: ChainConfig>(
    el_client: &impl L1Provider,
    beacon_api_client: &Client,
    eip4788_timestamp: Option<u64>,
    storage_block_number: u64,
    address: &Address,
    storage_slot: &B256,
    verifier_chain: VerifyingChain<'a, O>,
) -> Result<Eip4788SszStorageProof, SszStorageProofGenerationError> {
    let (eip4788_timestamp, ssz_root_beacon_slot) = derive_timestamp_for_chain::<O, C>(
        el_client,
        beacon_api_client,
        eip4788_timestamp,
        verifier_chain,
    )
    .await?;

    let ssz_storage_proof = generate_ssz_storage_proof::<C>(
        el_client,
        beacon_api_client,
        ssz_root_beacon_slot,
        storage_block_number,
        address,
        storage_slot,
    )
    .await?;

    Ok(Eip4788SszStorageProof {
        ssz_storage_proof,
        eip4788_timestamp,
    })
}

async fn derive_timestamp_for_chain<'a, O: OpStackProvider, C: ChainConfig>(
    el_client: &impl L1Provider,
    beacon_api_client: &Client,
    eip4788_timestamp: Option<u64>,
    verifier_chain: VerifyingChain<'a, O>,
) -> Result<(u64, u64), BlockhashProofGenerationError> {
    let (eip4788_timestamp, ssz_root_beacon_slot) = match eip4788_timestamp {
        // Generate a proof using the provided timestamp
        Some(timestamp) => {
            match verifier_chain {
                VerifyingChain::Mainnet => {
                    let beacon_slot_of_timestamp: u64 = l1_timestamp_to_beacon_slot::<C>(timestamp)
                        .ok_or(BlockhashProofGenerationError::InvalidTimestamp)?;

                    let beacon_block_of_timestamp: SignedBeaconBlock = beacon_api_client
                        .get_beacon_block(BeaconBlockId::Slot(beacon_slot_of_timestamp))
                        .await
                        .map_err(|_| BlockhashProofGenerationError::InvalidTimestamp)?;

                    // Only supports Deneb
                    let beacon_block_of_timestamp = beacon_block_of_timestamp
                        .deneb()
                        .ok_or(BlockhashProofGenerationError::InvalidTimestamp)?;

                    let block_of_timestamp = beacon_block_of_timestamp
                        .message
                        .body
                        .execution_payload
                        .block_number;

                    let target_block = block_of_timestamp - 1;

                    let target_beacon_slot =
                        l1_block_to_beacon_slot::<C>(el_client, target_block).await?;

                    Ok::<(u64, u64), BlockhashProofGenerationError>((timestamp, target_beacon_slot))
                }
                VerifyingChain::OpStack { op_stack_client } => {
                    let seconds_from_ecotone = timestamp
                        .checked_sub(O::ECOTONE_HARDFORK_BLOCK_TIMESTAMP)
                        .ok_or(BlockhashProofGenerationError::TimestampBeforeEcotoneHardfork)?;

                    if seconds_from_ecotone % 2 != 0 {
                        return Err(BlockhashProofGenerationError::InvalidTimestamp);
                    }

                    let blocks_from_ecotone = seconds_from_ecotone / 2;

                    let l2_block_number = O::ECOTONE_HARDFORK_BLOCK + blocks_from_ecotone;

                    let output_at_block: OutputAtBlock =
                        op_stack_client.output_at_block(l2_block_number).await?;

                    // Fetch L1 origin of the L2 block
                    let l1_origin = output_at_block.block_ref.l1origin.number;

                    // The associated L2 timestamp will map to the ssz root of the L1
                    // Origin's *parent*. So we subtract 1 from L1 Origin.
                    let beacon_slot =
                        l1_block_to_beacon_slot::<C>(el_client, l1_origin - 1).await?;

                    Ok::<(u64, u64), BlockhashProofGenerationError>((timestamp, beacon_slot))
                }
            }?
        }
        // Generate a proof using the current block timestamp
        None => {
            match verifier_chain {
                VerifyingChain::Mainnet => {
                    // We'll go back by 32 blocks to decrease likelihood of re-org
                    let current_block_number = el_client.get_block_number().await? - 32;

                    // We will use the timestamp of the current block but the beacon
                    // block root it will map to via EIP4788 in the EVM is the one of
                    // its parent.
                    //
                    // Beacon slots that do not propose a block do not have associated
                    // block roots within EIP4788

                    let consensus_timestamp = el_client
                        .get_block(current_block_number.into(), BlockTransactionsKind::Hashes)
                        .await?
                        .ok_or(BlockhashProofGenerationError::BlockHeaderFetch)?
                        .header
                        .timestamp;

                    let beacon_slot: u64 =
                        l1_block_to_beacon_slot::<C>(el_client, current_block_number - 1).await?;

                    Ok::<(u64, u64), BlockhashProofGenerationError>((
                        consensus_timestamp,
                        beacon_slot,
                    ))
                }
                VerifyingChain::OpStack { op_stack_client } => {
                    // Going back by 32 * 6 blocks means we are doing by at least 32 L1 blocks
                    let current_block_number = op_stack_client.get_block_number().await? - 192;

                    let output_at_block: OutputAtBlock = op_stack_client
                        .output_at_block(current_block_number)
                        .await?;

                    // Fetch full L2 block header
                    let l2_block: Block = op_stack_client
                        .get_block(current_block_number.into(), BlockTransactionsKind::Hashes)
                        .await
                        .map_err(|_| BlockhashProofGenerationError::BlockHeaderFetch)?
                        .ok_or(BlockhashProofGenerationError::BlockHeaderFetch)?;

                    // Fetch L1 origin of the L2 block
                    let l1_origin = output_at_block.block_ref.l1origin.number;

                    // The associated L2 timestamp will map to the ssz root of the L1
                    // Origin's *parent*. So we subtract 1 from L1 Origin.
                    let beacon_slot =
                        l1_block_to_beacon_slot::<C>(el_client, l1_origin - 1).await?;

                    // The EIP 4788 timestamp will be of the L2 block
                    Ok::<(u64, u64), BlockhashProofGenerationError>((
                        l2_block.header.timestamp,
                        beacon_slot,
                    ))
                }
            }?
        }
    };

    Ok((eip4788_timestamp, ssz_root_beacon_slot))
}
