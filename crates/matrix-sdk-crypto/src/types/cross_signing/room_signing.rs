use std::{collections::btree_map::Iter, sync::Arc};

use ruma::{encryption::KeyUsage, OwnedDeviceKeyId, UserId};
use serde::{Deserialize, Serialize};

use super::{CrossSigningKey, MasterPubkey, SigningKey};
use crate::{olm::VerifyJson, types::SigningKeys, SignatureError};

/// Wrapper for a cross signing key marking it as a room signing key.
///
/// Room signing key is used to verify membership of users in rooms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "CrossSigningKey")]
pub struct RoomSigningPubkey(pub(super) Arc<CrossSigningKey>);

impl RoomSigningPubkey {
    /// Get the user id of the user signing key's owner.
    pub fn user_id(&self) -> &UserId {
        &self.0.user_id
    }

    /// Get the list of `KeyUsage` that is set for this key.
    pub fn usage(&self) -> &[KeyUsage] {
        &self.0.usage
    }

    /// Get the keys map of containing the user signing keys.
    pub fn keys(&self) -> &SigningKeys<OwnedDeviceKeyId> {
        &self.0.keys
    }

    /// Check if the given master key is signed by this user signing key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key that should be checked for a valid
    /// signature.
    ///
    /// Returns an empty result if the signature check succeeded, otherwise a
    /// SignatureError indicating why the check failed.
    pub(crate) fn verify_master_key(
        &self,
        master_key: &MasterPubkey,
    ) -> Result<(), SignatureError> {
        if let Some((key_id, key)) = self.0.get_first_key_and_id() {
            key.verify_json(&self.0.user_id, key_id, master_key.as_ref())
        } else {
            Err(SignatureError::UnsupportedAlgorithm)
        }
    }
}

impl<'a> IntoIterator for &'a RoomSigningPubkey {
    type Item = (&'a OwnedDeviceKeyId, &'a SigningKey);
    type IntoIter = Iter<'a, OwnedDeviceKeyId, SigningKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys().iter()
    }
}

impl TryFrom<CrossSigningKey> for RoomSigningPubkey {
    type Error = serde_json::Error;

    fn try_from(key: CrossSigningKey) -> Result<Self, Self::Error> {
        if key.usage.contains(&KeyUsage::RoomSigning) && key.usage.len() == 1 {
            Ok(Self(key.into()))
        } else {
            Err(serde::de::Error::custom(format!(
                "Expected cross signing key usage {} was not found",
                KeyUsage::RoomSigning
            )))
        }
    }
}
impl AsRef<CrossSigningKey> for RoomSigningPubkey {
    fn as_ref(&self) -> &CrossSigningKey {
        &self.0
    }
}
