use crate::types::base64_encoded_url::Base64EncodedUrl;
use crate::types::cose::algorithm::WebauthAlgorithm;
use crate::types::protocol::public_key::CredentialParameterType;
use crate::types::protocol::transport::Transport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CredentialDescriptor {
    pub id: Base64EncodedUrl,
    #[serde(rename = "type")]
    pub kind: CredentialParameterType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Transport>>,
}

impl Default for CredentialDescriptor {
    #[inline]
    fn default() -> Self {
        CredentialDescriptor {
            id: Base64EncodedUrl::new(Vec::new()),
            kind: CredentialParameterType::PublicKey,
            transports: None,
        }
    }
}

impl CredentialDescriptor {
    #[must_use]
    #[inline]
    pub fn builder() -> CredentialDescriptorBuilder {
        CredentialDescriptorBuilder::new()
    }
}

#[non_exhaustive]
pub struct CredentialDescriptorBuilder {
    options: CredentialDescriptor,
}

impl Default for CredentialDescriptorBuilder {
    #[inline]
    fn default() -> Self {
        CredentialDescriptorBuilder::new()
    }
}

impl CredentialDescriptorBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        CredentialDescriptorBuilder {
            options: CredentialDescriptor::default(),
        }
    }
    
    #[must_use]
    #[inline]
    pub fn with_id(mut self, id: Base64EncodedUrl) -> Self {
        self.options.id = id;
        self
    }
    
    #[must_use]
    #[inline]
    pub fn with_kind(mut self, kind: CredentialParameterType) -> Self {
        self.options.kind = kind;
        self
    }
    
    #[must_use]
    #[inline]
    pub fn with_transports(mut self, transports: Option<Vec<Transport>>) -> Self {
        self.options.transports = transports;
        self
    }
    
    #[must_use]
    #[inline]
    pub fn build(self) -> CredentialDescriptor {
        self.options
    }   
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CredentialParameter {
    #[serde(rename = "type")]
    pub credential_type: CredentialParameterType,
    pub alg: WebauthAlgorithm,
}

impl Default for CredentialParameter {
    #[inline]
    fn default() -> Self {
        CredentialParameter {
            credential_type: CredentialParameterType::PublicKey,
            alg: WebauthAlgorithm::AlgES256,
        }
    }
}

impl CredentialParameter {
    #[must_use]
    #[inline]
    pub fn builder() -> CredentialParameterBuilder {
        CredentialParameterBuilder::new()
    }
}

#[non_exhaustive]
pub struct CredentialParameterBuilder {
    options: CredentialParameter,
}

impl Default for CredentialParameterBuilder {
    #[inline]
    fn default() -> Self {
        CredentialParameterBuilder::new()
    }
}

impl CredentialParameterBuilder {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        CredentialParameterBuilder {
            options: CredentialParameter::default(),
        }
    }

    #[must_use]
    #[inline]
    pub fn with_credential_type(mut self, credential_type: CredentialParameterType) -> Self {
        self.options.credential_type = credential_type;
        self
    }

    #[must_use]
    #[inline]
    pub fn with_alg(mut self, alg: WebauthAlgorithm) -> Self {
        self.options.alg = alg;
        self
    }

    #[must_use]
    #[inline]
    pub fn build(self) -> CredentialParameter {
        self.options
    }
}