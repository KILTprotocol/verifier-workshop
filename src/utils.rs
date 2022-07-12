use std::io::Read;
use subxt::{sp_core::crypto::Ss58Codec, sp_runtime::AccountId32};

use crate::{credential::Credential, errors::Error, kilt::runtime_types::primitive_types::H256};

// read a credential from stdin
pub fn read_credential() -> Result<Credential, Error> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    let claim = serde_json::from_str(s.as_str())?;
    Ok(claim)
}

// take a DID string and return the account id of it
pub fn get_did_account_id(did: &str) -> Result<AccountId32, Error> {
    let did_parts: Vec<&str> = did.split(':').collect();
    if did_parts.len() != 3 {
        return Err(Error::InvalidDid);
    }
    let parts: Vec<&str> = did_parts[2].split('#').collect();
    AccountId32::from_ss58check(parts[0]).map_err(|_| Error::InvalidDid)
}

// take a key uri string and return the key id of it
// i.e. "did:kilt:1234#0x1234" -> [1,2,3,4]
pub fn get_did_key_id(did: &str) -> Result<H256, Error> {
    let did_parts: Vec<&str> = did.split(':').collect();
    if did_parts.len() != 3 {
        return Err(Error::InvalidDid);
    }
    let parts: Vec<&str> = did_parts[2].split('#').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidDid);
    }
    let key_id = H256(
        hex::decode(&parts[1][2..])?
            .try_into()
            .map_err(|_| Error::InvalidDid)?,
    );
    Ok(key_id)
}
