use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
#[non_exhaustive]
pub enum Transport {
    #[serde(rename = "usb")]
    USB,
    #[serde(rename = "nfc")]
    NFC,
    #[serde(rename = "ble")]
    BLE,
    #[serde(rename = "internal")]
    #[default]
    Internal,

    // WebAuthn Level 3
    #[serde(rename = "hybrid")]
    Hybrid,

    // WebAuthn Level 3
    #[serde(rename = "smartcard")]
    SmartCard,
}
