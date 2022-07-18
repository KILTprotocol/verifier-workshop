use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level structure of a credential
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Credential {
    #[serde(rename = "claim")]
    pub claim: Claim,
    #[serde(rename = "claimHashes")]
    pub claim_hashes: Vec<String>,
    #[serde(rename = "claimNonceMap")]
    pub claim_nonce_map: HashMap<String, String>,
    #[serde(rename = "claimerSignature")]
    pub claimer_signature: ClaimerSignature,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
}

/// The claim holds the actual data that is attested
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Claim {
    #[serde(rename = "cTypeHash")]
    pub ctype_hash: String,
    #[serde(rename = "contents")]
    pub contents: serde_json::Value,
    #[serde(rename = "owner")]
    pub owner: String,
}

/// The claimer signature proofs that the owner of the claim signed the claim
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ClaimerSignature {
    pub signature: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
}

#[cfg(test)]
mod test {
    use super::*;

    const EXAMPLE_CRED: &str = r#"
    {
        "claim": {
            "cTypeHash": "0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac",
            "contents": {
                "Email": "tino@kilt.io"
            },
            "owner": "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH"
        },
        "claimHashes": [
            "0x2192b61d3f3109920e8991952a3fad9b7158e4fcac96dcfb873d5e975ba057e4",
            "0x2ef47f014e20bb908595f71ff022a53d7d84b5370dfed18479d4eee0575483c9"
        ],
        "claimNonceMap": {
            "0x0e0d56f241309d5a06ddf94e01d97d946f9b004d4f847302f050e5accf429c83": "5f25a0d1-b68f-4e06-a003-26c391935540",
            "0x758777288cc6705af9fb1b65f00647da18f696458ccbc59c4de0d50873e2b19d": "c57e9c72-fa8a-4e4f-b60f-a20234317bda"
        },
        "legitimations": [],
        "delegationId": null,
        "rootHash": "0xf69ce26ca50b5d5f38cd32a99d031cd52fff42f17b9afb32895ffba260fb616a",
        "claimerSignature": {
            "keyId": "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH#0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d",
            "signature": "0x6243baecdfa9c752161f501597bafbb0242db1174bb8362c18d6e51bdbbdf041997fb736a07dcf56cb023687c4cc044ffba39e0dfcf01b7caa00f0f8b4fbbd81"
        }
    }
    "#;

    #[test]
    fn test_parse_claim() {
        let credential: Credential =
            serde_json::from_str(EXAMPLE_CRED).expect("Failed to parse claims");
        println!("{:#?}", credential);
    }

}
