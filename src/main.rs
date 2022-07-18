mod errors;
mod utils;
mod credential;

use errors::Error;

fn main() -> Result<(), Error> {
    let cred = utils::read_credential("stdin")?;

    cred.check_claim_contents()?;
    cred.check_root_hash()?;
    
    Ok(())
}
