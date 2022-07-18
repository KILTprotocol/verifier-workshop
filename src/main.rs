mod errors;
mod utils;
mod credential;

use errors::Error;

fn main() -> Result<(), Error> {
    let cred = utils::read_credential("stdin")?;

    println!("{:#?}", cred);
    
    Ok(())
}
