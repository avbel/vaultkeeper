//! Generic-password items under service `bw-lite`.
//!
//! Items live in the login keychain. Its ACL trusts the binary that created an item, so a
//! rebuilt binary with a different code signature gets an "allow access" prompt on read.

use zeroize::Zeroizing;

use crate::Result;

#[cfg(target_os = "macos")]
const SERVICE: &str = "bw-lite";

/// Creates or replaces the item for `account`.
pub fn set(account: &str, secret: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::set(SERVICE, account, secret)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (account, secret);
        Err(crate::Error::Unsupported)
    }
}

/// `Ok(None)` when no item exists for `account`.
pub fn get(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    #[cfg(target_os = "macos")]
    {
        macos::get(SERVICE, account)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = account;
        Err(crate::Error::Unsupported)
    }
}

/// Deleting a missing item succeeds.
pub fn delete(account: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::delete(SERVICE, account)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = account;
        Err(crate::Error::Unsupported)
    }
}

/// Deletes every item whose account starts with `account_prefix` (e.g. `"<user_id>."` on
/// logout) and returns how many were removed.
pub fn delete_all_for(account_prefix: &str) -> Result<usize> {
    if account_prefix.is_empty() {
        return Err(crate::Error::Keychain(
            "refusing to delete every item with an empty prefix".into(),
        ));
    }
    #[cfg(target_os = "macos")]
    {
        macos::delete_all_for(SERVICE, account_prefix)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = account_prefix;
        Err(crate::Error::Unsupported)
    }
}

/// Attempts every delete even after one fails, so a single locked or damaged item cannot leave
/// the rest of an account's secrets behind; reports the first error once all were tried.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn delete_each<'a>(
    accounts: impl IntoIterator<Item = &'a str>,
    mut delete: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut deleted = 0;
    let mut first_error = None;
    for account in accounts {
        match delete(account) {
            Ok(()) => deleted += 1,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(deleted), Err)
}

#[cfg(target_os = "macos")]
mod macos {
    use security_framework::{
        base::Error as SecError,
        item::{ItemClass, ItemSearchOptions, Limit},
        passwords,
    };
    use zeroize::Zeroizing;

    use crate::{Error, Result};

    /// `errSecItemNotFound` from `<Security/SecBase.h>`.
    const ITEM_NOT_FOUND: i32 = -25300;
    /// Key of the account attribute (`kSecAttrAccount`) in attribute dictionaries.
    const ACCOUNT_ATTRIBUTE: &str = "acct";

    fn keychain_error(err: SecError) -> Error {
        Error::Keychain(err.to_string())
    }

    pub(super) fn set(service: &str, account: &str, secret: &[u8]) -> Result<()> {
        passwords::set_generic_password(service, account, secret).map_err(keychain_error)
    }

    pub(super) fn get(service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let options = passwords::PasswordOptions::new_generic_password(service, account);
        match passwords::generic_password(options) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(err) if err.code() == ITEM_NOT_FOUND => Ok(None),
            Err(err) => Err(keychain_error(err)),
        }
    }

    pub(super) fn delete(service: &str, account: &str) -> Result<()> {
        match passwords::delete_generic_password(service, account) {
            Err(err) if err.code() != ITEM_NOT_FOUND => Err(keychain_error(err)),
            _ => Ok(()),
        }
    }

    pub(super) fn delete_all_for(service: &str, account_prefix: &str) -> Result<usize> {
        let accounts = accounts(service)?;
        super::delete_each(
            accounts
                .iter()
                .map(String::as_str)
                .filter(|account| account.starts_with(account_prefix)),
            |account| delete(service, account),
        )
    }

    /// Reads attributes only, which never needs the item's ACL and so never prompts.
    fn accounts(service: &str) -> Result<Vec<String>> {
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        match found {
            Ok(results) => Ok(results
                .iter()
                .filter_map(|result| result.simplify_dict()?.remove(ACCOUNT_ATTRIBUTE))
                .collect()),
            Err(err) if err.code() == ITEM_NOT_FOUND => Ok(Vec::new()),
            Err(err) => Err(keychain_error(err)),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Unique per run so a leftover from a crashed run (owned by an older binary, which would
    /// make the keychain prompt) is never touched.
    fn test_prefix() -> String {
        format!(
            "bwl-platform-test.{}.{:x}.",
            std::process::id(),
            rand::random::<u64>()
        )
    }

    #[test]
    fn missing_items_read_as_none_and_delete_succeeds() {
        let account = format!("{}missing", test_prefix());
        assert!(get(&account).expect("get").is_none());
        delete(&account).expect("delete missing");
        assert_eq!(delete_all_for(&account).expect("delete_all_for"), 0);
    }

    // Writes to the login keychain (measured: no prompt while it is unlocked); every item is
    // removed again.
    #[test]
    fn set_get_replace_delete_round_trip() {
        let account = format!("{}refresh_token", test_prefix());
        set(&account, b"first").expect("set");
        assert_eq!(
            get(&account).expect("get").as_deref().map(Vec::as_slice),
            Some(&b"first"[..])
        );
        set(&account, b"second").expect("replace");
        assert_eq!(
            get(&account).expect("get").as_deref().map(Vec::as_slice),
            Some(&b"second"[..])
        );
        delete(&account).expect("delete");
        assert!(get(&account).expect("get after delete").is_none());
    }

    #[test]
    fn delete_all_for_removes_only_matching_accounts() {
        let user = test_prefix();
        let other = test_prefix();
        let mine = [format!("{user}refresh_token"), format!("{user}touchid")];
        let theirs = format!("{other}refresh_token");
        for account in mine.iter().chain([&theirs]) {
            set(account, b"secret").expect("set");
        }
        assert_eq!(delete_all_for(&user).expect("delete_all_for"), 2);
        for account in &mine {
            assert!(get(account).expect("get").is_none(), "{account}");
        }
        assert!(get(&theirs).expect("get other").is_some());
        delete(&theirs).expect("cleanup");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod delete_each_tests {
    use super::*;

    #[test]
    fn every_item_is_attempted_and_the_first_error_is_reported() {
        let mut tried = Vec::new();
        let result = delete_each(["a", "b", "c", "d"], |account| {
            tried.push(account.to_owned());
            if account == "b" || account == "c" {
                Err(crate::Error::Keychain(format!("failed {account}")))
            } else {
                Ok(())
            }
        });
        assert_eq!(tried, ["a", "b", "c", "d"]);
        assert!(matches!(result, Err(crate::Error::Keychain(m)) if m == "failed b"));
    }

    #[test]
    fn success_counts_deleted_items() {
        assert_eq!(delete_each(["a", "b"], |_| Ok(())).unwrap(), 2);
        assert_eq!(delete_each([], |_| Ok(())).unwrap(), 0);
    }

    #[test]
    fn empty_prefix_is_refused() {
        assert!(matches!(delete_all_for(""), Err(crate::Error::Keychain(_))));
    }
}
