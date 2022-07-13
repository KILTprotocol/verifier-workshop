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

// did should contain two colons `:` and one hashtag `#`
// i.e. "did:kilt:1234#0x1234"
fn get_did_parts(did: &str) -> Result<Vec<&str>, Error> {
    let did_parts: Vec<&str> = did.split(':').collect();
    if did_parts.len() != 3 {
        Err(Error::InvalidDid)
    } else {
        Ok(did_parts)
    }
}

// take a DID string and return the account id of it
pub fn get_did_account_id(did: &str) -> Result<AccountId32, Error> {
    let did_parts = get_did_parts(did)?;
    did_parts[2]
        .split('#').next()
        .map(AccountId32::from_ss58check)
        .expect("DID should contain # char")
        .map_err(|_| Error::InvalidDid)
}

// take a key uri string and return the key id of it
// i.e. "did:kilt:1234#0x1234" -> [1,2,3,4]
pub fn get_did_key_id(did: &str) -> Result<H256, Error> {
    let did_parts = get_did_parts(did)?;

    let parts: Vec<&str> = did_parts[2].split('#').collect();
    if parts.len() != 2 {
        Err(Error::InvalidDid)
    } else {
        Ok(H256(
            hex::decode(&parts[1][2..])?
                .try_into()
                .map_err(|_| Error::InvalidDid)?,
        ))
    }
}

pub fn hex_encode<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    format!("0x{}", hex::encode(data.as_ref()))
}

pub fn hex_decode<T>(data: T) -> Result<Vec<u8>, Error> 
where
    T: ToString,
{
    Ok(hex::decode(data.to_string().trim_start_matches("0x"))?.to_vec())
}
