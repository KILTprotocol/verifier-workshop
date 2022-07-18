mod errors;
mod utils;
mod kilt;
mod credential;

use errors::Error;

const ALLOWED_ISSUERS: [&str; 1] = [
    "did:kilt:4pnfkRn5UurBJTW92d9TaVLR2CqJdY4z5HPjrEbpGyBykare", // socialkyc.io
];

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = kilt::connect("wss://spiritnet.kilt.io:443").await?;
    let cred = utils::read_credential("stdin")?;

    cred.check_claim_contents()?;
    cred.check_root_hash()?;
    cred.check_signature(&cli).await?;
    cred.check_attestation(&cli, &ALLOWED_ISSUERS).await?;
    
    Ok(())
}
