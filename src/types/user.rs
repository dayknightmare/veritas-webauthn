use serde::{Deserialize, Serialize};

pub trait WebAuthnUserTrait {
    fn get_id(&self) -> &str;
    fn get_name(&self) -> &str;
    fn get_display_name(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WebAuthnUser {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

impl WebAuthnUserTrait for WebAuthnUser {
    #[inline]
    fn get_id(&self) -> &str {
        &self.id
    }

    #[inline]
    fn get_name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn get_display_name(&self) -> &str {
        &self.display_name
    }
}