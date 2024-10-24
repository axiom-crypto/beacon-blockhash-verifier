use eth_proofs::types::SszProof;
use serde_json::json;

pub fn generate_ssz_proof_json(ssz_proof: &SszProof) -> Option<serde_json::Value> {
    match ssz_proof {
        SszProof::CurrentBlock {
            curr_state_root_proof,
            execution_payload_proof,
            block_number_proof,
            blockhash_proof,
        } => Some(json!({
            "type": "CurrentBlock",
            "curr_state_root_proof": {
                "leaf": curr_state_root_proof.proof.leaf,
                "branch": curr_state_root_proof.proof.branch,
                "generalized_index": curr_state_root_proof.proof.index,
                "local_index": curr_state_root_proof.local_index,
                "root": curr_state_root_proof.witness
            },
            "execution_payload_proof": {
                "leaf": execution_payload_proof.proof.leaf,
                "branch": execution_payload_proof.proof.branch,
                "generalized_index": execution_payload_proof.proof.index,
                "local_index": execution_payload_proof.local_index,
                "root": execution_payload_proof.witness
            },
            "block_number_proof": {
                "leaf": block_number_proof.proof.leaf,
                "branch": block_number_proof.proof.branch,
                "generalized_index": block_number_proof.proof.index,
                "local_index": block_number_proof.local_index,
                "root": block_number_proof.witness
            },
            "blockhash_proof": {
                "leaf": blockhash_proof.proof.leaf,
                "branch": blockhash_proof.proof.branch,
                "generalized_index": blockhash_proof.proof.index,
                "local_index": blockhash_proof.local_index,
                "root": blockhash_proof.witness
            }
        })),
        SszProof::RecentHistoricalBlock {
            curr_state_root_proof,
            execution_payload_proof,
            block_number_proof,
            hist_state_root_proof,
            blockhash_proof,
        } => Some(json!({
            "type": "RecentHistoricalBlock",
            "curr_state_root_proof": {
                "leaf": curr_state_root_proof.proof.leaf,
                "branch": curr_state_root_proof.proof.branch,
                "generalized_index": curr_state_root_proof.proof.index,
                "local_index": curr_state_root_proof.local_index,
                "root": curr_state_root_proof.witness
            },
            "hist_state_root_proof": {
                "leaf": hist_state_root_proof.proof.leaf,
                "branch": hist_state_root_proof.proof.branch,
                "generalized_index": hist_state_root_proof.proof.index,
                "local_index": hist_state_root_proof.local_index,
                "root": hist_state_root_proof.witness
            },
            "execution_payload_proof": {
                "leaf": execution_payload_proof.proof.leaf,
                "branch": execution_payload_proof.proof.branch,
                "generalized_index": execution_payload_proof.proof.index,
                "local_index": execution_payload_proof.local_index,
                "root": execution_payload_proof.witness
            },
            "block_number_proof": {
                "leaf": block_number_proof.proof.leaf,
                "branch": block_number_proof.proof.branch,
                "generalized_index": block_number_proof.proof.index,
                "local_index": block_number_proof.local_index,
                "root": block_number_proof.witness
            },
            "blockhash_proof": {
                "leaf": blockhash_proof.proof.leaf,
                "branch": blockhash_proof.proof.branch,
                "generalized_index": blockhash_proof.proof.index,
                "local_index": blockhash_proof.local_index,
                "root": blockhash_proof.witness
            }
        })),
        SszProof::HistoricalBlock {
            curr_state_root_proof,
            execution_payload_proof,
            block_number_proof,
            summary_root_proof,
            hist_state_root_proof,
            blockhash_proof,
        } => Some(json!({
            "type": "HistoricalBlock",
            "curr_state_root_proof": {
                "leaf": curr_state_root_proof.proof.leaf,
                "branch": curr_state_root_proof.proof.branch,
                "generalized_index": curr_state_root_proof.proof.index,
                "local_index": curr_state_root_proof.local_index,
                "root": curr_state_root_proof.witness
            },
            "summary_root_proof": {
                "leaf": summary_root_proof.proof.leaf,
                "branch": summary_root_proof.proof.branch,
                "generalized_index": summary_root_proof.proof.index,
                "local_index": summary_root_proof.local_index,
                "root": summary_root_proof.witness
            },
            "hist_state_root_proof": {
                "leaf": hist_state_root_proof.proof.leaf,
                "branch": hist_state_root_proof.proof.branch,
                "generalized_index": hist_state_root_proof.proof.index,
                "local_index": hist_state_root_proof.local_index,
                "root": hist_state_root_proof.witness
            },
            "execution_payload_proof": {
                "leaf": execution_payload_proof.proof.leaf,
                "branch": execution_payload_proof.proof.branch,
                "generalized_index": execution_payload_proof.proof.index,
                "local_index": execution_payload_proof.local_index,
                "root": execution_payload_proof.witness
            },
            "block_number_proof": {
                "leaf": block_number_proof.proof.leaf,
                "branch": block_number_proof.proof.branch,
                "generalized_index": block_number_proof.proof.index,
                "local_index": block_number_proof.local_index,
                "root": block_number_proof.witness
            },
            "blockhash_proof": {
                "leaf": blockhash_proof.proof.leaf,
                "branch": blockhash_proof.proof.branch,
                "generalized_index": blockhash_proof.proof.index,
                "local_index": blockhash_proof.local_index,
                "root": blockhash_proof.witness
            }
        })),
        SszProof::PreMergeBlock { .. } => None,
    }
}
