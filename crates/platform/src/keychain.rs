//! Generic-password items under service `bw-lite`.

use zeroize::Zeroizing;

use crate::Result;

pub fn set(account: &str, secret: &[u8]) -> Result<()> {
    let _ = (account, secret);
    todo!("step 6")
}

pub fn get(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let _ = account;
    todo!("step 6")
}

pub fn delete(account: &str) -> Result<()> {
    let _ = account;
    todo!("step 6")
}
