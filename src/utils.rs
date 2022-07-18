use std::io::Read;

use crate::{credential::Credential, errors::Error};

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
        ];

        for (_name, hex_data, expected) in cases {
            let data = hex_decode(hex_data).unwrap();
            assert_eq!(data, expected);
        }
    }
}
