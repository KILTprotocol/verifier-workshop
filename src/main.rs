mod errors;
mod utils;
mod kilt;
mod credential;

use errors::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = kilt::connect("wss://spiritnet.kilt.io:443").await?;
    let cred = utils::read_credential("stdin")?;

    cred.check_claim_contents()?;
    cred.check_root_hash()?;
    cred.check_signature(&cli).await?;
    
    Ok(())
}
