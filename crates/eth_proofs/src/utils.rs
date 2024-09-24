use alloy_rpc_types_eth::{BlockId, BlockTransactionsKind};

use crate::{config::ChainConfig, error::BlockhashProofGenerationError, types::L1Provider};

pub fn l1_timestamp_to_beacon_slot<C: ChainConfig>(execution_block_timestamp: u64) -> Option<u64> {
    if (execution_block_timestamp - C::FIRST_POS_SLOT_TIMESTAMP) % 12 != 0 {
        return None;
    }
    Some(C::FIRST_POS_SLOT + (execution_block_timestamp - C::FIRST_POS_SLOT_TIMESTAMP) / 12)
}

pub async fn l1_block_to_beacon_slot<C: ChainConfig>(
    client: &impl L1Provider,
    beacon_root_block_number: u64,
) -> Result<u64, BlockhashProofGenerationError> {
    let ssz_root_block_id: BlockId = <u64 as Into<BlockId>>::into(beacon_root_block_number);

    let ssz_root_block = client
        .get_block(ssz_root_block_id, BlockTransactionsKind::Hashes)
        .await
        .map_err(|_| BlockhashProofGenerationError::BlockHeaderFetch)?
        .ok_or(BlockhashProofGenerationError::BlockHeaderFetch)?;

    // Should never panic
    let ssz_root_beacon_slot =
        l1_timestamp_to_beacon_slot::<C>(ssz_root_block.header.timestamp).unwrap();

    Ok(ssz_root_beacon_slot)
}
