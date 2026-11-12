//! Serde mirrors of the vault model, with conversions both ways. The vault types stay free of
//! serde; these are the only shapes that cross the socket.

mod error;
mod secret;
mod send;
mod view;

pub use error::{
    ApiErrorDto, CryptoErrorDto, GenErrorDto, IoErrorDto, IoKind, UNKNOWN_DETAIL, WireError,
};
pub use secret::{
    CustomFieldDto, IdentityDto, ItemDataDto, ItemDraftDto, LoginRequestDto, SshKeyDto,
    TotpCodeDto, TwoFactorAnswerDto,
};
pub use send::{SendDraftDto, SendKindDto, SendSummaryDto};
pub use view::{
    AccountDto, AttachmentDto, CollectionDto, CopyFieldDto, FilterDto, FolderDto, ItemKindDto,
    ItemSummaryDto, LoginStepDto, OrganizationDto, SessionStateDto,
};
