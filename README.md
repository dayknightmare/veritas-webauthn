Veritas WebAuthn
================

###### #backend, #library, #authentication, #webauthn

[![rust](https://img.shields.io/badge/rust-22272E?style=for-the-badge&logo=rust&logoColor=fafafa)](https://www.rust-lang.org/)
[![webauthn](https://img.shields.io/badge/webauthn-22272E?style=for-the-badge&logo=webauthn&logoColor=3423A6)](https://www.w3.org/TR/webauthn-3/)
[![fido2](https://img.shields.io/badge/fido2-22272E?style=for-the-badge&logo=fidoalliance&logoColor=fafafa)](https://fidoalliance.org/fido2/)

A WebAuthn Relying Party library for Rust. It builds the credential creation options you hand to the browser and verifies what the authenticator sends back: client data, attestation object, authenticator flags, RP ID hash, origin, challenge and COSE public key.

The crate is transport and storage agnostic. There is no async runtime, no HTTP framework and no database: you get plain serializable types, so `RegistrationOptions` goes to your JSON layer, `WebAuthnSession` goes wherever you keep per-request state, and the `Credential` you get back is yours to persist.

> The authentication ceremony is not implemented yet, and the crate is not published to crates.io. Registration is complete: `registration_begin` and `registration_finish` verify a real authenticator response end to end.

Install
-------

```toml
[dependencies]
veritas-webauthn = { git = "https://github.com/<owner>/veritas-webauthn" }
```

Registration flow
-----------------

1. **Configure the Relying Party.** The `rp_id` is the domain the credential is bound to, and every origin the browser may call from has to be listed. Timeouts are in milliseconds.

   ```rust
   use url::Url;
   use veritas_webauthn::webauthn::{WebAuthn, WebAuthnConfig, WebAuthnTimeoutConfig};

   let config = WebAuthnConfig::builder()
       .with_rp_id("example.com".to_string())
       .with_rp_name("Example".to_string())
       .with_origins(vec![Url::parse("https://example.com")?])
       .with_timeouts(
           WebAuthnTimeoutConfig::builder()
               .with_registration(300_000)
               .with_authentication(300_000)
               .build(),
       )
       .build()?;

   let webauthn = WebAuthn::new(config);
   ```

2. **Describe your user.** Implement `WebAuthnUserTrait` on whatever type you already have. The id is what gets bound to the credential, so use a stable internal identifier, never an email or a username.

   ```rust
   use veritas_webauthn::types::user::WebAuthnUserTrait;

   impl WebAuthnUserTrait for User {
       fn get_id(&self) -> &str { &self.id }
       fn get_name(&self) -> &str { &self.email }
       fn get_display_name(&self) -> &str { &self.full_name }
   }
   ```

3. **Begin the ceremony.** You get the options to serialize into `navigator.credentials.create()` and a session. Keep the session server side: it carries the challenge, and the finish step refuses anything that does not match it.

   ```rust
   use veritas_webauthn::registration::begin::options::RegistrationBeginOptions;
   use veritas_webauthn::types::protocol::authenticator::ResidentKeyRequirement;

   let (options, session) = webauthn.registration_begin(
       user.clone(),
       RegistrationBeginOptions::builder()
           .with_resident_key(ResidentKeyRequirement::Required)
           .build(),
   )?;

   let json = serde_json::to_string(&options)?;
   ```

   Leaving the parameters unset offers every algorithm in the table below. Pass `with_parameters` to narrow that list.

4. **Finish the ceremony.** Deserialize the browser's response into `RegistrationFinishRequest` and hand it back with the session you stored. The call verifies the ceremony type, origin, RP ID hash, challenge, user handle, user presence and verification, backup flags, and the COSE public key against the algorithms you offered.

   ```rust
   use veritas_webauthn::registration::finish::response::RegistrationFinishRequest;

   let request: RegistrationFinishRequest = serde_json::from_str(&body)?;
   let credential = webauthn.registration_finish(user, session, request)?;
   ```

5. **Store the credential.** `Credential` holds the credential id, the COSE public key, the attestation format, the transports, the authenticator flags and the AAGUID with its signature counter. Everything is `Serialize`/`Deserialize`, so it maps straight onto a row or a document. Keep the id indexed: it is what the authentication ceremony will look the credential up by.

Supported algorithms
--------------------

Every algorithm below is offered by default and validated on the way back in, including the curve and the coordinate length of the public key.

| `alg` | Name | Key type | Validated as |
| :--- | :--- | :--- | :--- |
| -7 | ES256 | EC2, P-256 | 32-byte coordinates |
| -35 | ES384 | EC2, P-384 | 48-byte coordinates |
| -36 | ES512 | EC2, P-521 | 66-byte coordinates |
| -8 | EdDSA | OKP, Ed25519 | 32-byte x |
| -257, -258, -259 | RS256, RS384, RS512 | RSA | 2048 to 8192 bit modulus |
| -37, -38, -39 | PS256, PS384, PS512 | RSA | 2048 to 8192 bit modulus |

Contribute
----------

Fork it, make the change, open a pull request.

License
-------

MIT. The full text is in the `LICENSE` file.