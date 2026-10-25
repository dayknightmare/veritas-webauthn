use crate::registration::begin::response::RegistrationBeginResponse;
use crate::types::cose::algorithm::WebauthAlgorithm;
use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::user::{WebAuthnUser, WebAuthnUserTrait};
use crate::types::protocol::authenticator::UserVerificationRequirement;
use crate::types::protocol::public_key::CredentialParameterType;
use crate::registration::begin::options::RegistrationBeginOptions;
use crate::types::session::WebAuthnSession;
use crate::types::protocol::credential::CredentialParameter;
use crate::webauthn::WebAuthn;
use crate::errors::VeritasWebAuthnResult;
use rand::RngExt;

impl WebAuthn {
    #[inline]
    pub fn registration_begin(&self, user: impl WebAuthnUserTrait, opts: RegistrationBeginOptions) -> VeritasWebAuthnResult<(RegistrationBeginResponse, WebAuthnSession)> {
        let mut params = vec![];

        for param in WebauthAlgorithm::iter() {
            params.push(CredentialParameter {
                credential_type: CredentialParameterType::PublicKey,
                alg: param,
            });
        }

        params = opts.parameters.unwrap_or(params);

        let mut rng = rand::rng();
        
        let challenge = Base64EncodedUrl::new(rng.random::<[u8; 32]>().to_vec());
        let user_id = Base64EncodedUrl::new(user.get_id().to_string().into_bytes());
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::seconds(self.config.timeouts.registration as i64);
        
        let session = WebAuthnSession::builder()
            .with_challenge(challenge.clone())
            .with_rp_id(self.config.rp_id.clone())
            .with_user_id(user_id.to_base64url())
            .with_user_verification(opts.authenticator_selection.user_verification.clone().unwrap_or(UserVerificationRequirement::Required))
            .with_parameters(params.clone())
            .with_mediation(opts.mediation.clone())
            .with_expires_at(exp)
            .with_issued_at(now)
            .build()?;
        
        let register = RegistrationBeginResponse::builder()
            .with_challenge(challenge)
            .with_rp_id(self.config.rp_id.clone())
            .with_rp_name(self.config.rp_name.clone())
            .with_user(WebAuthnUser {
                id: user_id.to_base64url(),
                name: user.get_name().to_string(),
                display_name: user.get_display_name().to_string(),
            })
            .with_timeout(self.config.timeouts.registration)
            .with_parameters(params)
            .with_excluded_credentials(opts.excluded_credentials)
            .with_authenticator_selection(opts.authenticator_selection)
            .with_hints(opts.hints)
            .with_mediation(opts.mediation)
            .build()?;

        Ok((register, session))
    }
}
