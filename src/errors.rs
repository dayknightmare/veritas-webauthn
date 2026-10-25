use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VeritasWebAuthnError {
    #[error("Invalid origin")]
    InvalidOrigin,

    #[error("Invalid timeout")]
    InvalidTimeout,

    #[error("Invalid RP ID")]
    InvalidRpId,

    #[error("Invalid RP Name")]
    InvalidRpName,

    #[error("Invalid base64 encoded URL")]
    InvalidBase64EncodedUrl,

    #[error("User not match with session user ID")]
    UserNotMatchWithSessionUserId,

    #[error("Invalid client data JSON")]
    InvalidClientDataJson,

    #[error("Invalid attestation object")]
    InvalidAttestationObject,

    #[error("Auth data too short")]
    AuthDataTooShort,

    #[error("Auth data AAGUID mismatch")]
    AuthDataAaguidMismatch,

    #[error("Auth data id length mismatch")]
    AuthDataIdLengthMismatch,

    #[error("Auth data with invalid length")]
    AuthDataInvalidLength,

    #[error("Invalid credential flags")]
    InvalidCredentialFlags,

    #[error("Invalid credential public key")]
    InvalidCredentialPublicKey,

    #[error("Invalid ceremony type")]
    InvalidCeremonyType,

    #[error("Session expired")]
    SessionExpired,

    #[error("User verification is required")]
    UserVerificationIsRequired,

    #[error("User presence is required")]
    UserPresenceIsRequired,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Unsupported public key")]
    UnsupportedPublicKey,
    
    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    #[error("Invalid challenge")]
    InvalidChallenge,

    #[error("Invalid user ID")]
    InvalidUserId,

    #[error("Invalid credential parameters")]
    InvalidCredentialParameters,

    #[error("Invalid backup state")]
    InvalidBackupState,

    #[error("Invalid credential ID")]
    InvalidCredentialId,

    #[error("Invalid AAGUID")]
    InvalidAaguid,

    #[error("Invalid authenticator")]
    InvalidAuthenticator,
}

pub type VeritasWebAuthnResult<T> = Result<T, VeritasWebAuthnError>;