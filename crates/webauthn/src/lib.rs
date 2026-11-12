//! WebAuthn for Vaultkeeper: the client side (client data, request/creation options) and a
//! software authenticator for vault passkeys. Security-key 2FA reuses the client side and
//! talks to the hardware key in the app.

mod authenticator;
pub mod b64;
mod client_data;
mod error;
mod options;
mod response;

pub use authenticator::{
    AAGUID, Assertion, FLAG_ATTESTED_DATA, FLAG_BACKED_UP, FLAG_BACKUP_ELIGIBLE, FLAG_USER_PRESENT,
    FLAG_USER_VERIFIED, PASSKEY_FLAGS, PasskeyKey, Registration, attestation_object_none,
    authenticator_data, get_assertion, make_credential,
};
pub use client_data::{Ceremony, ClientDataJson, origin_of};
pub use error::{Error, Result};
pub use options::{
    AuthenticatorSelection, CreationExtensions, CreationOptions, CredentialDescriptor,
    CredentialParameter, ES256, RelyingParty, RequestExtensions, RequestOptions, UserEntity,
    UserVerification,
};
