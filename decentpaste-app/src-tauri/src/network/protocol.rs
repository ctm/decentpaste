use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Largest clipboard content we will sync, in bytes.
///
/// This and [`GOSSIPSUB_MAX_TRANSMIT_SIZE`] are two halves of one budget: content is
/// AES-GCM encrypted (+28 bytes), base64 encoded (~1.34x) and wrapped in a JSON envelope,
/// so the wire size is roughly 1.4x the content. The transmit size must stay above that
/// product or large copies fail to publish.
pub const MAX_CLIPBOARD_CONTENT_BYTES: usize = 1024 * 1024;

/// Maximum gossipsub RPC size. libp2p defaults to 64 KiB, which silently capped clipboard
/// sync far below [`MAX_CLIPBOARD_CONTENT_BYTES`].
pub const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 2 * 1024 * 1024;

/// Serializes `Vec<u8>` as a base64 string rather than a JSON array of decimal numbers.
/// The array form costs ~3.6 wire bytes per payload byte; base64 costs ~1.34.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    Pairing(PairingMessage),
    Clipboard(ClipboardMessage),
    Heartbeat(HeartbeatMessage),
    /// Announces device name to all peers on the network.
    /// Used when device name is changed in settings.
    DeviceAnnounce(DeviceAnnounceMessage),
    /// Sync protocol messages for clipboard history synchronization.
    /// Used to deliver missed clipboard messages to peers who were offline.
    Sync(SyncMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    /// Request sync from a peer - sent when we reconnect after being offline.
    /// The responding peer will reply with HashListResponse containing hashes
    /// of messages we might have missed.
    Request {
        /// Our peer_id (so responder knows who's asking)
        peer_id: String,
    },
    /// Response containing list of message hashes available for sync.
    /// Requester will compare against their history and request missing content.
    HashListResponse { hashes: Vec<MessageHash> },
    /// Request full content for a specific hash.
    /// Sent after receiving HashListResponse for hashes we don't have.
    ContentRequest { hash: String },
    /// Response containing full clipboard message content.
    /// The message is already encrypted for the requesting peer.
    ContentResponse { message: ClipboardMessage },
}

/// Represents a hash of a buffered message with its timestamp.
/// Used in HashListResponse so requester can decide which messages to fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHash {
    /// content_hash from ClipboardMessage
    pub hash: String,
    /// Original message timestamp for chronological sorting
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PairingMessage {
    Request(PairingRequest),
    Challenge(PairingChallenge),
    Response(PairingResponse),
    Confirm(PairingConfirm),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    pub session_id: String, // Session ID from initiator - responder must use this
    pub device_name: String,
    pub device_id: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingChallenge {
    pub session_id: String,
    pub pin: String,
    pub device_name: String, // Responder's device name
    pub public_key: Vec<u8>, // Responder's X25519 public key for ECDH
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    pub session_id: String,
    pub pin_hash: Vec<u8>,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingConfirm {
    pub session_id: String,
    pub success: bool,
    pub error: Option<String>,
    pub device_name: Option<String>, // Sender's device name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardMessage {
    pub id: String,
    pub content_hash: String,
    #[serde(with = "base64_bytes")]
    pub encrypted_content: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub origin_device_id: String,
    pub origin_device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub device_id: String,
    pub timestamp: DateTime<Utc>,
}

/// Broadcast message to announce device name to all peers.
/// This allows peers to update their discovered devices list when
/// a device's name changes in settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAnnounceMessage {
    pub peer_id: String,
    pub device_name: String,
    pub timestamp: DateTime<Utc>,
}

impl ProtocolMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
