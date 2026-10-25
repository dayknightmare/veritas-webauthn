use crate::registration::finish::response::{RegistrationFinishRequest, RegistrationFinishRequestParsed};
use crate::types::protocol::authenticator::UserVerificationRequirement;
use crate::types::credential::{Attestation, Authenticator, Credential};
use crate::types::protocol::authenticator_data::AuthenticatorData;
use crate::errors::{VeritasWebAuthnError, VeritasWebAuthnResult};
use crate::types::protocol::webauthn::{CeremonyType, Mediation};
use crate::types::protocol::attestation::AttestationFormat;
use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::cose::public_key::PublicKeyData;
use crate::types::session::WebAuthnSession;
use crate::types::user::WebAuthnUserTrait;
use crate::utils::crypto::sha256_encrypt;
use crate::webauthn::WebAuthn;
use crate::utils::host;

impl WebAuthn {
    
    #[inline]
    pub fn registration_finish(
        &self,
        user: impl WebAuthnUserTrait,
        session: WebAuthnSession,
        request: RegistrationFinishRequest,
    ) -> VeritasWebAuthnResult<Credential> {
        self.verify_request(&request)?;

        let parsed = RegistrationFinishRequestParsed::try_from(request.clone())?;
        if parsed.response.client_data.kind != CeremonyType::Create {
            return Err(VeritasWebAuthnError::InvalidCeremonyType);
        }

        let auth_data = parsed.response.attestation_object.auth_data_parsed.ok_or(VeritasWebAuthnError::InvalidAttestationObject)?;

        self.verify_origin(parsed.response.client_data.origin)?;
        self.verify_session(&session, user, &auth_data, Base64EncodedUrl::from_string(parsed.response.client_data.challenge.clone())?)?;
        self.verify_rp_id(&auth_data)?;
        let alg = self.verify_public_key(&auth_data, &session)?;

        let credential = Credential::builder()
            .with_id(auth_data.attested_credential_data.credential_id.clone())
            .with_public_key(auth_data.attested_credential_data.credential_public_key.clone())
            .with_attestation_format(AttestationFormat::from(parsed.response.attestation_object.fmt))
            .with_transport(parsed.response.transports)
            .with_flags((&auth_data).into())
            .with_authenticator(Authenticator{
                aaguid: auth_data.attested_credential_data.aaguid,
                clone_warning: false,
                sign_count: auth_data.sign_count,
                attachment: parsed.authenticator_attachment,
            })
            .with_attestation(Attestation{
                client_data_json: request.response.client_data_json.clone(),
                client_data_hash: Base64EncodedUrl::new(sha256_encrypt(&request.response.client_data_json.to_vec())),
                authenticator_data: parsed.response.raw_client_data_json,
                public_key_algorithm: alg as i32,
            })
            .build()?;

        Ok(credential)
    }

    fn verify_request(&self, request: &RegistrationFinishRequest) -> VeritasWebAuthnResult<()> {
        if request.kind != "public-key" {
            return Err(VeritasWebAuthnError::InvalidCredentialPublicKey);
        }

        let id = Base64EncodedUrl::from_string(request.id.clone())?;
        if id != request.raw_id {
            return Err(VeritasWebAuthnError::InvalidBase64EncodedUrl);
        }

        Ok(())
    }

    fn verify_session(&self, session: &WebAuthnSession, user: impl WebAuthnUserTrait, auth_data: &AuthenticatorData, challenge: Base64EncodedUrl) -> VeritasWebAuthnResult<()> {
        if session.is_expired() {
            return Err(VeritasWebAuthnError::SessionExpired);
        }

        let user_id = Base64EncodedUrl::new(user.get_id().to_string().into_bytes());
        let session_user_id = Base64EncodedUrl::from_string(session.user_id.clone())?;

        if user_id != session_user_id {
            return Err(VeritasWebAuthnError::UserNotMatchWithSessionUserId);
        }

        if !auth_data.has_user_verified() && session.user_verification == UserVerificationRequirement::Required {
            return Err(VeritasWebAuthnError::UserVerificationIsRequired);
        }

        if !auth_data.has_user_presence() && session.mediation != Some(Mediation::Conditional) {
            return Err(VeritasWebAuthnError::UserPresenceIsRequired);
        }

        if session.challenge != challenge {
            return Err(VeritasWebAuthnError::InvalidChallenge);
        }

        if auth_data.has_backup_state() && !auth_data.has_backup_eligibility() {
            return Err(VeritasWebAuthnError::InvalidBackupState);
        }

        Ok(())
    }

    fn verify_public_key(&self, auth_data: &AuthenticatorData, session: &WebAuthnSession) -> VeritasWebAuthnResult<i64> {
        let pk = PublicKeyData::try_from(auth_data.attested_credential_data.credential_public_key.to_vec())?;
        if !pk.is_public_key_allowed(session.parameters.clone()) {
            return Err(VeritasWebAuthnError::InvalidPublicKey);
        }

        pk.verify_key_type()?;

        Ok(pk.algorithm)
    }

    fn verify_rp_id(&self, auth_data: &AuthenticatorData) -> VeritasWebAuthnResult<()> {
        let rp_id_hash = Base64EncodedUrl::new(sha256_encrypt(self.config.rp_id.as_bytes()));
        if rp_id_hash != auth_data.rp_id_hash {
            return Err(VeritasWebAuthnError::InvalidRpId);
        }
        Ok(())
    }

    fn verify_origin(&self, origin: String) -> VeritasWebAuthnResult<()> {
        let url = url::Url::parse(origin.as_str()).map_err(|_| VeritasWebAuthnError::InvalidOrigin)?;
        let host = host::get_host(url.clone());

        for i in self.config.origins.iter() {
            let origin_host = host::get_host(i.clone());

            if origin_host == host {
                if i.domain() == "localhost".into() || i.domain() == "127.0.0.1".into() {
                    return Ok(());
                }

                if url.origin() == i.origin() && i.as_str().starts_with("https://") {
                    return Ok(());
                }
            }
        }

        Err(VeritasWebAuthnError::InvalidOrigin)
    }
}
