mod errors;
use errors::Error;

mod utils;
use utils::*;

mod kilt;
use kilt::connect;

mod credential;

const ALLOWED_ISSUERS: [&str; 1] = [
    "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare", // socialkyc.io
];

#[tokio::main]
async fn main() -> Result<(), Error> {
    // connect to chain
    let cli = connect("wss://spiritnet.kilt.io:443").await?;

    // read credential from stdin
    let cred = read_credential()?;

    // check claim contents
    cred.check_claim_contents()?;
    println!("claim contents are valid");

    // check if root hash is valid
    cred.check_root_hash()?;
    println!("root hash is valid");

    // check if the owner signed the credential
    cred.check_signature(&cli).await?;
    println!("signature is valid");

    // check if the attestation of the credential is written to chain and not revoked
    cred.check_attestation(&cli, &ALLOWED_ISSUERS).await?;
    println!("attestation is valid");

    Ok(())
}
