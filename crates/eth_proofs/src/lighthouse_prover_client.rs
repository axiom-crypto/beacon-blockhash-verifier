use alloy_primitives::B256;
use reqwest::{Client, Error};
use serde::Deserialize;
use ssz_rs::{
    proofs::{Proof, ProofAndWitness},
    PathElement,
};

#[derive(Clone)]
pub struct LighthouseProverClient {
    base_url: String,
    client: Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InternalProof {
    leaf: B256,
    branch: Vec<B256>,
    index: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProofResponse {
    proof: InternalProof,
    witness: B256,
}

impl LighthouseProverClient {
    pub fn new(base_url: &str) -> Self {
        LighthouseProverClient {
            base_url: base_url.to_string(),
            client: Client::new(),
        }
    }

    pub async fn get_proof(
        &self,
        slot: u64,
        paths: &[PathElement],
        from_state_roots: bool,
    ) -> Result<ProofAndWitness, Error> {
        let url = format!("{}/{}", self.base_url, slot);

        let mut query_params: Vec<(&str, String)> = Vec::new();
        for path in paths {
            match path {
                PathElement::Field(field) => query_params.push(("path", field.to_string())),
                PathElement::Index(index) => query_params.push(("path", index.to_string())),
                _ => panic!("Unsupported path element"),
            };
        }

        query_params.push(("from_state_roots", from_state_roots.to_string()));

        let response = self.client.get(&url).query(&query_params).send().await?;

        let proof = response.json::<ProofResponse>().await?;

        let proof: ProofAndWitness = (
            Proof {
                leaf: proof.proof.leaf,
                branch: proof.proof.branch,
                index: proof.proof.index,
            },
            proof.witness,
        );

        Ok(proof)
    }
}
