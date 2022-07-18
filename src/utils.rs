use std::io::Read;
use subxt::{sp_core::crypto::Ss58Codec, sp_runtime::AccountId32};

use crate::{credential::Credential, errors::Error, kilt::runtime_types::primitive_types::H256};

// read a credential from stdin
pub fn read_credential(file: &str) -> Result<Credential, Error> {
    let mut s = String::new();
    if file == "stdin" {
        std::io::stdin().read_to_string(&mut s)?;
    } else {
        s = std::fs::read_to_string(file)?;
    }
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
        .split('#')
        .next()
        .ok_or(Error::InvalidDid)
        .map(AccountId32::from_ss58check)?
        .map_err(|_| Error::InvalidDid)
}

// take a key uri string and return the key id of it
// i.e. "did:kilt:1234#0x05060708" -> [5,6,7,8]
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

// hex encoding helper which adds '0x' as a prefix
pub fn hex_encode<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    format!("0x{}", hex::encode(data.as_ref()))
}

// hex decoding helper which strips '0x' as a prefix
pub fn hex_decode<T>(data: T) -> Result<Vec<u8>, Error>
where
    T: ToString,
{
    let s = data.to_string();
    let normalized = s.trim().trim_start_matches("0x");
    Ok(hex::decode(normalized)?.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_did_parts() {
        let did = "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH#0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d";
        let did_parts = get_did_parts(did).unwrap();
        assert_eq!(did_parts[0], "did");
        assert_eq!(did_parts[1], "kilt");
        assert_eq!(did_parts[2], "4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH#0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d");
    }

    #[test]
    fn test_get_did_account_id() {
        let did = "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH";
        let account_id = get_did_account_id(did).unwrap();
        assert_eq!(
            account_id,
            AccountId32::from_ss58check("4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH")
                .unwrap()
        );

        let did = "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH#0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d";
        let account_id = get_did_account_id(did).unwrap();
        assert_eq!(
            account_id,
            AccountId32::from_ss58check("4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH")
                .unwrap()
        );
    }

    #[test]
    fn test_get_did_key_id() {
        let did = "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH#0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d";
        let key_id = get_did_key_id(did).unwrap();
        assert_eq!(
            key_id.0,
            H256(
                hex_decode("0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d")
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
            .0
        );
    }

    #[test]
    fn test_hex_encode() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let hex_data = hex_encode(data);
        assert_eq!(hex_data, "0x12345678");
    }

    #[test]
    fn test_hex_decode() {
        let cases = vec![
            (
                "parse with 0x prefix",
                "0x12345678",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse without 0x prefix",
                "12345678",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse with 0x prefix and trailing whitespace",
                "0x12345678  ",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse without 0x prefix and trailing whitespace",
                "12345678  ",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse with 0x prefix and leading whitespace",
                "  0x12345678",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse without 0x prefix and leading whitespace",
                "  12345678",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse with 0x prefix and leading and trailing whitespace",
                "  0x12345678  ",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
            (
                "parse without 0x prefix and leading and trailing whitespace",
                "  12345678  ",
                vec![0x12, 0x34, 0x56, 0x78],
            ),
        ];

        for (_name, hex_data, expected) in cases {
            let data = hex_decode(hex_data).unwrap();
            assert_eq!(data, expected);
        }
    }
}
