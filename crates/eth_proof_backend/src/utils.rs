use eth_proofs::types::SszProof;
use serde_json::json;

pub fn generate_ssz_proof_json(ssz_proof: &SszProof) -> Option<serde_json::Value> {
    match ssz_proof {
        SszProof::CurrentBlock {
            curr_state_root_proof,
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
