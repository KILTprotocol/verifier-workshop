mod errors;
use errors::Error;

mod utils;
use utils::read_credential;

mod kilt;
use kilt::connect;

mod credential;

const ALLOWED_ISSUERS: [&str; 1] = [
    // socialkyc.io
    "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare",
];

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Connect to chain
    let cli = connect("wss://spiritnet.kilt.io:443").await?;

    // Read credential from stdin
    let cred = read_credential()?;

    // Check claim contents
    cred.check_claim_contents()?;
    println!("[1/4] Claim contents are valid");

    // Check if root hash is valid
    cred.check_root_hash()?;
    println!("[2/4] Root hash is valid");

    // Check if the owner signed the credential
    cred.check_signature(&cli).await?;
    println!("[3/4] Signature is valid");

    // Check if the attestation of the credential is written to chain and not revoked
    cred.check_attestation(&cli, &ALLOWED_ISSUERS).await?;
    println!("[4/4] ✅ Attestation is valid");

    Ok(())
}
