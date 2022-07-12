use blake2::{digest::consts::U32, Blake2b, Digest};
use serde::{Deserialize, Serialize};
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
use std::collections::HashMap;
use subxt::sp_runtime::app_crypto::RuntimePublic;

use crate::{
    errors::Error,
    kilt::{
        runtime_types::did::did_details::{
            DidPublicKey::PublicVerificationKey, DidVerificationKey,
        },
        KiltRuntimeApi,
    },
    utils::{get_did_account_id, get_did_key_id},
};

type Blake2b256 = Blake2b<U32>;

// Top-level structure of a credential
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

// The claim holds the actual data that is attested
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Claim {
    #[serde(rename = "cTypeHash")]
    pub ctype_hash: String,
    #[serde(rename = "contents")]
    pub contents: serde_json::Value,
    #[serde(rename = "owner")]
    pub owner: String,
}

// The claimer signature proofs that the owner of the claim signed the claim
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ClaimerSignature {
    pub signature: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
}

impl Credential {
    // This will check all disclosed contents against the hashes given in the credential
    pub fn check_claim_contents(&self) -> Result<(), Error> {
        // We need to normalize the owner and the contents
        // First add owner field like `{"@id":"did:kilt:12345"}`
        let mut owner_map = serde_json::Map::new();
        owner_map.insert("@id".into(), self.claim.owner.clone().into());
        let mut normalized_parts = vec![serde_json::to_string(&owner_map)?];

        // Now add for every toplevel entry in the contents one object like this:
        // `{"kilt:ctype:12345#Email":"foo@bar.com"}`
        self.claim
            .contents
            .as_object()
            .ok_or(Error::InvalidClaimContents)?
            .iter()
            .try_for_each(|(key, value)| -> Result<(), Error> {
                let mut map = serde_json::Map::new();
                let key = format!("kilt:ctype:{}#{}", self.claim.ctype_hash, key);
                map.insert(key, value.clone());
                normalized_parts.push(serde_json::to_string(&map)?);
                Ok(())
            })?;

        // At this point we can calculate the hashes of the normalized statements using blake2b256
        let hashes = normalized_parts
            .iter()
            .map(|part| -> String {
                let part = part.as_str();
                let mut hasher = Blake2b256::new();
                hasher.update(part);
                let res = hex::encode(hasher.finalize().as_slice());
                format!("0x{}", res)
            })
            .collect::<Vec<String>>();

        // Each of these hashes should have a corresponding nonce in the nonce map
        // And the nonce hashed together with the hash should be listed in the claim_hashes of the credential
        hashes.iter().try_for_each(|hash| -> Result<(), Error> {
            let nonce = self
                .claim_nonce_map
                .get(hash)
                .ok_or(Error::InvalidClaimContents)?;
            let mut hasher = Blake2b256::new();
            hasher.update(nonce);
            hasher.update(hash);
            let hash = format!("0x{}", hex::encode(hasher.finalize().as_slice()));
            if !self.claim_hashes.contains(&hash) {
                Err(Error::InvalidClaimContents)
            } else {
                Ok(())
            }
        })?;

        // Claims are valid if we get here!
        Ok(())
    }

    // Hashing the claim-hashes together should result in the root hash of the credential
    pub fn check_root_hash(&self) -> Result<(), Error> {
        let mut hasher = Blake2b256::new();
        for hash in self.claim_hashes.iter() {
            let data = hex::decode(&hash[2..])?;
            hasher.update(&data);
        }

        let root_hash = format!("0x{}", hex::encode(hasher.finalize().as_slice()));
        if root_hash != self.root_hash {
            Err(Error::InvalidRootHash)
        } else {
            Ok(())
        }
    }

    // The signature of the credential is checked against the public key of the owner
    pub async fn check_signature(&self, cli: &KiltRuntimeApi) -> Result<(), Error> {
        let owner = get_did_account_id(self.claim.owner.as_str())?;

        // Lookup DID doc on chain
        let did_doc = cli
            .storage()
            .did()
            .did(&owner, None)
            .await?
            .ok_or(Error::DidNotFound)?;

        // Get the public verification key of the owner from the DID doc
        let did_key_id = get_did_key_id(&self.claimer_signature.key_id)?;
        let details = &did_doc
            .public_keys
            .0
            .iter()
            .find(|(key, _)| key.0 == did_key_id.0)
            .ok_or(Error::InvalidDid)?
            .1;

        // Make sure the public key is a sr25519 public verification key and check the signature
        match &details.key {
            PublicVerificationKey(DidVerificationKey::Sr25519(key)) => {
                let pub_key = subxt::sp_core::sr25519::Public::from_raw(key.0);
                let sig = subxt::sp_core::sr25519::Signature::from_raw(
                    hex::decode(&self.claimer_signature.signature.as_bytes()[2..])?
                        .try_into()
                        .map_err(|_| Error::InvalidHex(hex::FromHexError::OddLength))?,
                );
                let msg = hex::decode(&self.root_hash.as_bytes()[2..])?;

                if pub_key.verify(&msg, &sig) {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
            _ => Err(Error::InvalidDid),
        }
    }

    // Finally we need to check if the root hash is ok:
    // - it's written to chain
    // - the attestation is not revoked
    // - we trust the attester
    pub async fn check_attestation(
        &self,
        cli: &KiltRuntimeApi,
        allowed_issuers: &[&str],
    ) -> Result<(), Error> {
        // Get the raw root hash
        let hash = subxt::sp_core::H256(
            hex::decode(&self.root_hash.as_bytes()[2..])?
                .try_into()
                .map_err(|_| Error::InvalidHex(hex::FromHexError::OddLength))?,
        );

        // Retrieve the attestation from chain
        let attestation = cli
            .storage()
            .attestation()
            .attestations(&hash, None)
            .await?
            .ok_or(Error::AttestationNotFound)?;

        // Check if it has been revoked by the issuer
        if attestation.revoked {
            Err(Error::AttestationRevoked)
        } else {
            // Build the attester DID string to check against the allowed issuers
            let attester = format!(
                "did:kilt:{}",
                attestation
                    .attester
                    .to_ss58check_with_version(Ss58AddressFormat::custom(38))
            );
            if !allowed_issuers.contains(&attester.as_str()) {
                Err(Error::InvalidIssuer)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::kilt::connect;

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

    const ALLOWED_ISSUERS: [&str; 1] = [
        "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare", // socialkyc.io
    ];

    #[test]
    fn test_check_claim_contents() {
        let credential: Credential = serde_json::from_str(EXAMPLE_CRED).unwrap();
        let res = credential.check_claim_contents();
        assert!(res.is_ok());
    }

    #[test]
    fn test_check_root_hash() {
        let credential: Credential = serde_json::from_str(EXAMPLE_CRED).unwrap();
        let res = credential.check_root_hash();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_check_signature() {
        let credential: Credential = serde_json::from_str(EXAMPLE_CRED).unwrap();
        let cli = connect("wss://spiritnet.kilt.io:443").await.unwrap();
        let res = credential.check_signature(&cli).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_check_attestation() {
        let credential: Credential = serde_json::from_str(EXAMPLE_CRED).unwrap();
        let cli = connect("wss://spiritnet.kilt.io:443").await.unwrap();
        let res = credential.check_attestation(&cli, &ALLOWED_ISSUERS).await;
        assert!(res.is_ok());
    }
}
