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

