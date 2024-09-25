use alloy_network::Ethereum;
use alloy_primitives::B256;
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use alloy_transport::{BoxTransport, Transport, TransportResult};
use async_trait::async_trait;
use op_alloy_network::Optimism;
use serde::{Deserialize, Serialize};
use ssz_rs::{
    proofs::{get_subtree_index, Proof, ProofAndWitness},
    Node,
};

pub trait L1Provider<T: Transport + Clone = BoxTransport>: Provider<T, Ethereum> {}

impl<T: Transport + Clone, P: Provider<T, Ethereum>> L1Provider<T> for P {}

#[derive(Debug, PartialEq, Eq)]
pub struct SszProofSegment {
    pub proof: Proof,
    pub witness: Node,
    pub local_index: usize,
}

impl From<ProofAndWitness> for SszProofSegment {
    fn from(proof_and_witness: ProofAndWitness) -> Self {
        let (proof, witness) = proof_and_witness;
        let index = proof.index;

        Self {
            proof,
            witness,
            local_index: get_subtree_index(index).expect("Generalized index cannot be 0"),
        }
    }
}

#[derive(Debug)]
pub enum SszProof {
    CurrentBlock {
        curr_state_root_proof: SszProofSegment,
        blockhash_proof: SszProofSegment,
    },
    RecentHistoricalBlock {
        curr_state_root_proof: SszProofSegment,
        hist_state_root_proof: SszProofSegment,
        blockhash_proof: SszProofSegment,
    },
    HistoricalBlock {
        curr_state_root_proof: SszProofSegment,
        summary_root_proof: SszProofSegment,
        hist_state_root_proof: SszProofSegment,
        blockhash_proof: SszProofSegment,
    },
    PreMergeBlock {},
}

#[derive(Debug)]
pub struct Eip4788BlockhashProof {
    pub blockhash_proof: SszProof,

    /// The timestamp against which the ssz root in the proof can be queried on
    /// the `VerifyingChain`
    pub eip4788_timestamp: u64,
}

#[derive(Debug)]
pub struct SszStorageProof {
    /// The storage proof for proving the storage slot into the state root
    pub storage_proof: EIP1186AccountProofResponse,

    /// The RLP encoded block header for proving the state root into the
    /// blockhash
    pub rlp_block_header: String,

    /// The SSZ proof for verifying the blockhash into the beacon block root
    pub ssz_proof: SszProof,
}

#[derive(Debug)]
pub struct Eip4788SszStorageProof {
    pub ssz_storage_proof: SszStorageProof,

    /// The timestamp against which the ssz root in the proof can be queried on
    /// the `VerifyingChain`
    pub eip4788_timestamp: u64,
}

pub enum VerifyingChain<'a, O: OpStackProvider> {
    Mainnet,
    OpStack { op_stack_client: &'a O },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRef {
    pub hash: B256,
    pub number: u64,

    #[serde(rename = "parentHash")]
    pub parent_hash: B256,

    pub timestamp: u64,
    pub l1origin: L1Origin,

    #[serde(rename = "sequenceNumber")]
    pub sequence_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1Origin {
    pub hash: B256,
    pub number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub current_l1: L1Block,
    pub current_l1_finalized: L1Block,
    pub head_l1: L1Block,
    pub safe_l1: L1Block,
    pub finalized_l1: L1Block,
    pub unsafe_l2: L2Block,
    pub safe_l2: L2Block,
    pub finalized_l2: L2Block,
    pub pending_safe_l2: L2Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1Block {
    pub hash: B256,
    pub number: u64,

    #[serde(rename = "parentHash")]
    pub parent_hash: B256,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Block {
    pub hash: B256,
    pub number: u64,

    #[serde(rename = "parentHash")]
    pub parent_hash: B256,
    pub timestamp: u64,
    pub l1origin: L1Origin,

    #[serde(rename = "sequenceNumber")]
    pub sequence_number: u64,
}

// TODO: Use type directly from op-alloy:
// https://github.com/alloy-rs/op-alloy/issues/32
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputAtBlock {
    pub version: String,

    #[serde(rename = "outputRoot")]
    pub output_root: B256,

    #[serde(rename = "blockRef")]
    pub block_ref: BlockRef,

    #[serde(rename = "withdrawalStorageRoot")]
    pub withdrawal_storage_root: B256,

    #[serde(rename = "stateRoot")]
    pub state_root: B256,

    #[serde(rename = "syncStatus")]
    pub sync_status: SyncStatus,
}

#[async_trait]
pub trait OpStackProvider<T: Transport + Clone = BoxTransport>: Provider<T, Optimism> {
    const ECOTONE_HARDFORK_BLOCK: u64;
    const ECOTONE_HARDFORK_BLOCK_TIMESTAMP: u64;

    async fn output_at_block(&self, block_number: u64) -> TransportResult<OutputAtBlock> {
        let response = self
            .client()
            .request("optimism_outputAtBlock", (format!("0x{:x}", block_number),))
            .await?;

        Ok(response)
    }
}

impl<T: Transport + Clone> OpStackProvider<T> for RootProvider<T, Optimism> {
    const ECOTONE_HARDFORK_BLOCK: u64 = 117387812;
    const ECOTONE_HARDFORK_BLOCK_TIMESTAMP: u64 = 1710374401;
}
