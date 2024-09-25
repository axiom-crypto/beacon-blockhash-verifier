use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub enum VerifierChains {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "optimism")]
    Optimism,
}
