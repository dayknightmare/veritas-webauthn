use crate::registration::begin::response::AuthenticatorSelectionRegistrationBeginResponse;
use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::protocol::attestation::{AttestationFormat, ConveyancePreference};
use crate::types::protocol::authenticator::{AuthenticatorAttachment, ResidentKeyRequirement, UserVerificationRequirement};
use crate::types::protocol::credential::{CredentialDescriptor, CredentialParameter};
use crate::types::protocol::extension::AuthenticationExtensions;
use crate::types::protocol::public_key::{CredentialParameterType, PublicKeyCredentialHint};
use crate::types::protocol::webauthn::Mediation;

pub struct RegistrationBeginOptions {
    pub(crate) excluded_credentials: Option<Vec<CredentialDescriptor>>,
    pub(crate) authenticator_selection: AuthenticatorSelectionRegistrationBeginResponse,
    pub(crate) parameters: Option<Vec<CredentialParameter>>,
    pub(crate) hints: Option<Vec<PublicKeyCredentialHint>>,
    pub(crate) attestation: Option<ConveyancePreference>,
    pub(crate) attestation_fmt: Option<Vec<AttestationFormat>>,
    pub(crate) extensions: Option<AuthenticationExtensions>,
    pub(crate) mediation: Option<Mediation>,
}

impl RegistrationBeginOptions {
    #[must_use]
    #[inline]
    pub fn builder() -> RegistrationBeginOptionsBuilder {
        RegistrationBeginOptionsBuilder::new()
    }
}

pub struct RegistrationBeginOptionsBuilder {
    options: RegistrationBeginOptions,
}

impl Default for RegistrationBeginOptionsBuilder {
    #[inline]
    fn default() -> Self {
        RegistrationBeginOptionsBuilder::new()
    }
}

impl RegistrationBeginOptionsBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        RegistrationBeginOptionsBuilder {
            options: RegistrationBeginOptions {
                excluded_credentials: None,
                authenticator_selection: AuthenticatorSelectionRegistrationBeginResponse{
                    resident_key: Some(ResidentKeyRequirement::Preferred),
                    authenticator_attachment: None,
                    user_verification: Some(UserVerificationRequirement::Required),
                    require_resident_key: Some(false),
                },
                parameters: None,
                hints: None,
                attestation: None,
                attestation_fmt: None,
                extensions: None,
                mediation: None,
            },
        }
    }

    #[must_use]
    #[inline]
    pub fn with_excluded_credentials(mut self, credentials: Vec<CredentialDescriptor>) -> Self {
        self.options.excluded_credentials = Some(credentials);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_excluded_credential(mut self, credential: CredentialDescriptor) -> Self {
        let mut credentials = self.options.excluded_credentials.clone().unwrap_or_default();
        credentials.push(credential);
        self.options.excluded_credentials = Some(credentials);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_excluded_credentials_by_id(mut self, credential_id: String) -> Self {
        let id = match Base64EncodedUrl::from_string(credential_id) {
            Ok(id) => id,
            Err(_) => return self,
        };

        let mut credentials = self.options.excluded_credentials.clone().unwrap_or_default();
        credentials.push(CredentialDescriptor {
            id,
            kind: CredentialParameterType::PublicKey,
            transports: None,
        });
        self.options.excluded_credentials = Some(credentials);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_parameters(mut self, parameters: Vec<CredentialParameter>) -> Self {
        self.options.parameters = Some(parameters);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_user_verification(mut self, user_verification: UserVerificationRequirement) -> Self {
        self.options.authenticator_selection.user_verification = Some(user_verification);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_resident_key(mut self, resident_key: ResidentKeyRequirement) -> Self {
        self.options.authenticator_selection.resident_key = Some(resident_key);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_authenticator_attachment(mut self, authenticator_attachment: AuthenticatorAttachment) -> Self {
        self.options.authenticator_selection.authenticator_attachment = Some(authenticator_attachment);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_attestation(mut self, attestation: ConveyancePreference) -> Self {
        self.options.attestation = Some(attestation);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_attestation_fmt(mut self, attestation_fmt: Vec<AttestationFormat>) -> Self {
        self.options.attestation_fmt = Some(attestation_fmt);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_hints(mut self, hints: Vec<PublicKeyCredentialHint>) -> Self {
        self.options.hints = Some(hints);
        self
    }

    #[must_use]
    #[inline]
    pub fn with_mediation(mut self, mediation: Mediation) -> Self {
        self.options.mediation = Some(mediation);
        self
    }

    fn resolve_resident_key(&mut self) {
        let resident_key = match self.options.authenticator_selection.resident_key.clone() {
            Some(e) => e,
            None => return,
        };

        match resident_key {
            ResidentKeyRequirement::Preferred | ResidentKeyRequirement::Discouraged => {
                self.options.authenticator_selection.require_resident_key = Some(false);
            }
            ResidentKeyRequirement::Required => {
                self.options.authenticator_selection.require_resident_key = Some(true);
            }
        }
    }

    fn resolve_hints(&mut self) {
        let hints = match self.options.hints.clone() {
            Some(e) => e,
            None => return,
        };

        if hints.is_empty() {
            return;
        }

        let first = match hints.first() {
            Some(f) => f,
            None => return,
        };

        if hints.iter().any(|h| h != first) {
            return;
        }

        match hints[0] {
            PublicKeyCredentialHint::SecurityKey | PublicKeyCredentialHint::Hybrid => {
                self.options.authenticator_selection.authenticator_attachment = Some(AuthenticatorAttachment::CrossPlatform);
            },
            PublicKeyCredentialHint::ClientDevice => {
                self.options.authenticator_selection.authenticator_attachment = Some(AuthenticatorAttachment::Platform);
            }
        };
    }

    #[inline]
    pub fn build(&mut self) -> RegistrationBeginOptions {
        self.resolve_resident_key();
        self.resolve_hints();

        RegistrationBeginOptions {
            excluded_credentials: self.options.excluded_credentials.clone(),
            authenticator_selection: self.options.authenticator_selection.clone(),
            parameters: self.options.parameters.clone(),
            hints: self.options.hints.clone(),
            attestation: self.options.attestation.clone(),
            attestation_fmt: self.options.attestation_fmt.clone(),
            extensions: self.options.extensions.clone(),// TODO
            mediation: self.options.mediation.clone(),
        }
    }
}