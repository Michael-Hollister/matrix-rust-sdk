// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use itertools::Itertools;
use ruma::{
    api::client::{
        keys::upload_signatures::v3::SignedKeys,
        sync::sync_events::v3::{JoinedRoom, Rooms},
    },
    encryption::KeyUsage,
    events::{
        room::{
            create::{RoomCreateEventContent, SyncRoomCreateEvent},
            member::{MembershipState, RoomMemberEventContent, SyncRoomMemberEvent},
        },
        space::child::SpaceChildEventContent,
        AnySyncStateEvent, EventContent, OriginalStateEvent, OriginalSyncStateEvent,
        PossiblyRedactedStateEventContent, RedactContent, StateEvent, StateEventType,
        StaticStateEventContent, SyncStateEvent,
    },
    serde::{base64::UrlSafe, Base64, Raw},
    signatures::Verified,
    DeviceId, DeviceKeyAlgorithm, DeviceKeyId, EventId, MilliSecondsSinceUnixEpoch, OwnedDeviceId,
    OwnedDeviceKeyId, OwnedEventId, OwnedRoomId, OwnedUserId, RoomVersionId,
};
use serde::Deserialize;
use serde_json::Error;
use tracing::{error, warn};
use vodozemac::Ed25519PublicKey;

use crate::{
    error::OlmResult,
    olm::{ShareInfo, VerifyJson},
    store::{Changes, StoreTransaction},
    types::{
        events::room_key_withheld::WithheldCode, CrossSigningKey, MasterPubkey, RoomSigningPubkey,
        Signatures, SigningKey, SigningKeys,
    },
    EventError, OlmError, OlmMachine, UserIdentities,
};

impl OlmMachine {
    /// Docs TBD
    /// link to msc?
    /// What type of event is the cause-of-membership event?
    pub async fn verify_room_events(
        &self,
        changes: &mut Changes,
        room_events: &BTreeMap<OwnedRoomId, &Vec<Raw<AnySyncStateEvent>>>,
    ) -> OlmResult<()> {
        // update to correctly handle this
        changes.verified_events =
            self.store().get_value("verified_events").await.unwrap_or_default().unwrap_or_default();
        // changes.unverified_events =
        // self.store().get_value("unverified_events").await.unwrap_or_default().
        // unwrap_or_default();
        changes.unverified_events = BTreeMap::default();
        changes.missing_identities = self
            .store()
            .get_value("missing_identities")
            .await
            .unwrap_or_default()
            .unwrap_or_default();

        // Prevents cloning event data, will be merged with changes later
        let unverified_events: BTreeMap<OwnedRoomId, Vec<Raw<AnySyncStateEvent>>> = self
            .store()
            .get_value("unverified_events")
            .await
            .unwrap_or_default()
            .unwrap_or_default();

        if !unverified_events.is_empty() {
            self.verify_events(
                changes,
                &unverified_events.iter().map(|(k, v)| (k.to_owned(), v)).collect(),
            )
            .await?;
        }

        changes.unverified_events.extend(unverified_events);
        self.verify_events(changes, room_events).await?;


        // save changes in main method later (in save_changes method)
        // self.store().set_value("verified_events", &verified_events).await?;

        Ok(())
    }

    /// Docs TBD
    /// link to msc?
    async fn verify_events(
        &self,
        changes: &mut Changes,
        room_events: &BTreeMap<OwnedRoomId, &Vec<Raw<AnySyncStateEvent>>>,
        // room_events: &BTreeMap<OwnedRoomId, &Vec<(OwnedEventId, Raw<AnySyncStateEvent>)>>,
        // room_events: impl Iterator<Item = (&OwnedRoomId, &Vec<Raw<AnySyncStateEvent>>)>,
    ) -> OlmResult<()> {
        // misc notes
        // message on failure https://spec.matrix.org/latest/appendices/#checking-for-a-signature

        let mut new_missing_identities = BTreeSet::new();

        for (room_id, events) in room_events {
            for event in events.iter().sorted_by(|a, b| {
                Ord::cmp(
                    &a.get_field::<MilliSecondsSinceUnixEpoch>("origin_server_ts").unwrap(),
                    &b.get_field::<MilliSecondsSinceUnixEpoch>("origin_server_ts").unwrap(),
                )
            }) {
                match event.deserialize() {
                    Ok(e) => {
                        // Need to pause verification until we can fetch identity credentials from
                        // manager
                        if new_missing_identities.contains(&e.sender().to_owned()) {
                            // temp: note that events could be duplicated, though does not have
                            // effect on validation, only bloating the store
                            changes
                                .unverified_events
                                .entry(room_id.to_owned())
                                .or_default()
                                .push(event.clone());
                            continue;
                        }

                        if let Some(sender_msk) = self.get_user_msk(&e.sender().to_owned()).await {
                            if changes.missing_identities.contains(&e.sender().to_owned()) {
                                changes.missing_identities.remove(&e.sender().to_owned());
                            }

                            if e.event_type() == StateEventType::RoomCreate {
                                self.verify_room_create_event(changes, room_id, &sender_msk, event)
                                    .await?;
                            }
                            // Key being present in verified_events implies room id version >= V12
                            else if changes.verified_events.contains_key(room_id) {
                                match e.event_type() {
                                    StateEventType::RoomJoinRules => self.verify_join_rules_event(changes, room_id, &sender_msk, event).await?,
                                    StateEventType::RoomMember => {
                                        self.verify_room_member_event(
                                            changes,
                                            room_id,
                                            &sender_msk,
                                            event,
                                        )
                                        .await?
                                    }
                                    StateEventType::RoomThirdPartyInvite => self.verify_third_party_invite_event(changes, room_id, &sender_msk, event).await?,
                                    StateEventType::RoomTombstone => self.verify_room_tombstone_event(changes, room_id, &sender_msk, event).await?,
                                    StateEventType::SpaceChild => {
                                        self.verify_space_child_event(
                                            changes,
                                            room_id,
                                            &sender_msk,
                                            event,
                                        )
                                        .await?
                                    }
                                    // Only validating signatures for select state events
                                    _ => continue,
                                }
                            }

                            continue;
                        } else {
                            // Need to pause verification until we can fetch identity credentials
                            // from manager
                            new_missing_identities.insert(e.sender().to_owned());
                            // temp: note that events could be duplicated, though does not have
                            // effect on validation, only bloating the store
                            changes
                                .unverified_events
                                .entry(room_id.to_owned())
                                .or_default()
                                .push(event.clone());
                        }
                    }
                    Err(e) => {
                        warn!("Error deserializing room state event: {e}");
                        continue;
                    }
                }
            }
        }

        changes.missing_identities.extend(new_missing_identities);

        Ok(())
    }

    /// docs tbd
    async fn get_user_msk(&self, user_id: &OwnedUserId) -> Option<MasterPubkey> {
        // let rrk_bytes: [u8; PUBLIC_KEY_LENGTH] =
        // full_event.content.room_root_key.unwrap_or_default().as_bytes().try_into().
        // unwrap_or([0; PUBLIC_KEY_LENGTH]);

        // let rrk = match VerifyingKey::from_bytes(&rrk_bytes) {
        //     Ok(k) => k,
        //     Err(e) => {
        //         // should be failure since room version is 12
        //         return Ok(());
        //     },
        // };

        match self.get_identity(user_id, None).await {
            Ok(Some(UserIdentities::Own(identity))) => Some(identity.master_key().clone()),
            Ok(Some(UserIdentities::Other(identity))) => Some(identity.master_key().clone()),
            Ok(None) => {
                warn!("MSK does not exist in manager for {user_id}, pausing event validation");
                None
            }
            Err(e) => {
                error!("Error fetching MSK: {e:?}, pausing event validation");
                None
            }
        }
    }

    /// docs tbd
    async fn get_user_rsk(&self, user_id: &OwnedUserId) -> Option<RoomSigningPubkey> {
        match self.get_identity(user_id, None).await {
            Ok(Some(UserIdentities::Own(identity))) => Some(identity.room_signing_key().clone()),
            Ok(Some(UserIdentities::Other(identity))) => Some(identity.room_signing_key().clone()),
            Ok(None) => {
                warn!("RSK does not exist in manager for {user_id}, pausing event validation");
                None
            }
            Err(e) => {
                error!("Error fetching RSK: {e:?}, pausing event validation");
                None
            }
        }
    }

    /// Docs tbd
    async fn verify_room_create_event(
        &self,
        // verified_events: &mut BTreeMap<OwnedRoomId, BTreeSet<OwnedEventId>>,
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {
        match event.deserialize_as::<OriginalSyncStateEvent<RoomCreateEventContent>>() {
            Ok(sync_event) => {
                if sync_event.content.room_version == RoomVersionId::V12 {
                    let full_event = sync_event.into_full_event(room_id.to_owned());

                    let sender = full_event.sender;
                    let rrk = full_event.content.room_root_key.unwrap_or_default();

                    // TODO: do proper error handling

                    // let rrk = VerifyingKey::from_bytes(&full_event.content.room_root_key.
                    // unwrap_or_default());
                    let derived_room_id = Base64::<UrlSafe>::new(rrk.as_bytes().to_vec());

                    // TODO: need to verify only content, not full event
                    // also consider switching to using different verifying function?
                    let v: ruma::CanonicalJsonValue =
                        serde_json::to_value(event.json().get()).unwrap().try_into().unwrap();
                    let canonical_json =
                        ruma::CanonicalJsonObject::from(v.as_object().unwrap().clone());

                    let rrk2 = Base64::new(rrk.as_bytes().to_vec());
                    let rrk_map = ruma::signatures::PublicKeyMap::from([(
                        sender.to_owned().to_string(),
                        ruma::signatures::PublicKeySet::from([("ed25519:rrk".to_string(), rrk2)]),
                    )]);

                    // rrk.verify(msg, signature)

                    // if (ruma_signatures::verify_json(event.content.room_root_key, event.content))
                    // {

                    // }

                    // Does the event contain the correct RRK and the user's MSK?
                    // Does the event have a valid signature by the RRK?
                    if derived_room_id.encode() == full_event.room_id.as_str()
                        && full_event.content.creator_key.unwrap()
                            == sender_msk.get_first_key().unwrap().to_base64()
                        && ruma::signatures::verify_event(
                            &rrk_map,
                            &canonical_json,
                            &full_event.content.room_version,
                        )
                        .is_ok_and(|r| r == Verified::Signatures)
                    {
                        // Pass room membership for room creator, process next event
                        // The user's cause-of-membership event passes verification

                        // Add event to cache
                        changes
                            .verified_events
                            .entry(room_id.to_owned())
                            .and_modify(|(_, e)| {
                                e.insert(full_event.event_id.clone());
                            })
                            .or_insert((
                                full_event.content.room_version,
                                BTreeSet::from([full_event.event_id]),
                            ));
                    } else {
                        // The user's cause-of-membership event does NOT pass verification

                        // revisit key witholding and edge/cases

                        // need to consider, if roomkey withheld only blacklists devices, what
                        // happens if new devices are added later?

                        // Note that this procedure specifically verifies that a particular MSK may
                        // legitimately belong in the room. Devices that
                        // claim to belong to a user, but are not signed by a Self-Signing Key
                        // signed by that particular MSK, must not be
                        // treated as belonging in the room.

                        // If clients are unable to verify a user's cause-of-membership event for a
                        // room, they may refuse to share cryptographic
                        // material in that room with that user.

                        if let Some(outbound) =
                            self.store().get_outbound_group_session(room_id).await?
                        {
                            let share_info = ShareInfo::new_withheld(WithheldCode::Unauthorised);

                            for device in
                                self.store().get_user_devices_filtered(&sender).await?.devices()
                            {
                                outbound
                                    .shared_with_set
                                    .write()
                                    .unwrap()
                                    .entry(device.user_id().to_owned())
                                    .or_default()
                                    .insert(device.device_id().to_owned(), share_info.clone());
                            }
                        }

                        // temp use error handling later
                        return Ok(());
                    }
                }

                Ok(())
            }
            Err(e) => {
                warn!("Error deserializing room state event: {e}");
                Err(OlmError::JsonError(e))
            }
        }
    }

    /// Docs tbd
    async fn verify_room_member_event(
        &self,
        // verified_events: &mut BTreeMap<OwnedRoomId, BTreeSet<OwnedEventId>>,
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {
        // update result error type
        match event.deserialize_as::<OriginalSyncStateEvent<RoomMemberEventContent>>() {
            Ok(sync_event) => {
                let full_event = sync_event.into_full_event(room_id.to_owned());

                let invited_user = full_event.state_key;
                let user_msk = match self.get_user_msk(&invited_user).await {
                    Some(k) => k,
                    None => {
                        // Need to pause verification until we can fetch identity credentials from
                        // manager
                        changes.missing_identities.insert(invited_user.to_owned());
                        // temp: note that events could be duplicated, though does not have effect
                        // on validation, only bloating the store
                        changes
                            .unverified_events
                            .entry(room_id.to_owned())
                            .or_default()
                            .push(event.clone());
                        return Err(OlmError::EventError(EventError::MissingSigningKey));
                    }
                };

                // fix error case since only RSK is missing, not master key
                let sender = full_event.sender;
                let rsk = match self.get_user_rsk(&sender).await {
                    Some(k) => k,
                    None => {
                        // Need to pause verification until we can fetch identity credentials from
                        // manager
                        changes.missing_identities.insert(sender.to_owned());
                        // temp: note that events could be duplicated, though does not have effect
                        // on validation, only bloating the store
                        changes
                            .unverified_events
                            .entry(room_id.to_owned())
                            .or_default()
                            .push(event.clone());
                        return Err(OlmError::EventError(EventError::MissingSigningKey));
                    }
                };

                let rrk = full_event.content.room_root_key.to_owned().unwrap_or_default();
                let rsk_str = full_event.content.sender_key.to_owned().unwrap_or_default();
                let user_msk_str = full_event.content.user_key.to_owned().unwrap_or_default();
                let derived_room_id = Base64::<UrlSafe>::new(rrk.as_bytes().to_vec());

                let rsk_first_key = rsk.as_ref().get_first_key_and_id().unwrap();

                // let msk = full_event.content.user_key.clone().unwrap_or_default().to_owned();
                // let msk_str = full_event.content.user_key.unwrap_or_default().to_owned();
                // let msk = CrossSigningKey::new(
                //     sender,
                //     KeyUsage::Master,
                //     SigningKeys::from([("msk",
                // SigningKey::from_parts(&DeviceKeyAlgorithm::Ed25519,
                // msk_str).unwrap_or_default()]),     signatures
                // );

                // let v: ruma::CanonicalJsonValue =
                // serde_json::to_value(event.json().get()).unwrap().try_into().unwrap();
                // let canonical_json =
                // ruma::CanonicalJsonObject::from(v.as_object().unwrap().clone());

                let rsk2 = Base64::new(rsk_str.as_bytes().to_vec());
                let rsk_map = ruma::signatures::PublicKeyMap::from([(
                    sender.to_owned().to_string(),
                    ruma::signatures::PublicKeySet::from([("ed25519:rsk".to_string(), rsk2)]),
                )]);

                // return early json error deserialization
                let parent_event_id = match full_event.content.parent_event_id.to_owned() {
                    Some(e) => e,
                    None => todo!(),
                };

                // ban and leave events: parent event id should point to join event (also
                // confirm space child events if parent event id)
                // also if ourself is banned/left, then need to remove old events in verified_events


                // Does the event contain the correct RRK and the invited user's MSK?
                // Does the event have a valid signature by the RSK?
                // Does the user's RSK have a valid signature by the sender's MSK?
                // Has parent event been validated? (Lookup this event's parent event ID - i.e., the sender's cause-of-membership event)
                if matches!(full_event.content.membership, MembershipState::Invite | MembershipState::Join | MembershipState::Leave | MembershipState::Ban)
                    && derived_room_id.encode() == full_event.room_id.as_str()
                    && rsk_str == rsk.keys().get(&DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, "rsk".into())).unwrap().to_base64()
                    && user_msk_str == user_msk.get_first_key().unwrap().to_base64()
                    && rsk_first_key.1.verify_json(&sender, rsk_first_key.0, &full_event.content).is_ok()
                    && sender_msk.verify_subkey(&rsk).is_ok()
                    && changes.verified_events.get(room_id).is_some_and(|(_, e)| e.contains(&parent_event_id))
                {
                    // Add event to cache
                    changes.verified_events.entry(room_id.to_owned()).and_modify(|(_, e)| {
                        e.insert(full_event.event_id.clone());
                    });

                    // Pass room membership for room creator, process next event
                    // The user's cause-of-membership event passes verification
                } else {
                    // The user's cause-of-membership event does NOT pass verification

                    // revisit key witholding and edge/cases (see room create validation)

                    if let Some(outbound) = self.store().get_outbound_group_session(room_id).await?
                    {
                        let share_info = ShareInfo::new_withheld(WithheldCode::Unauthorised);

                        for device in
                            self.store().get_user_devices_filtered(&sender).await?.devices()
                        {
                            outbound
                                .shared_with_set
                                .write()
                                .unwrap()
                                .entry(device.user_id().to_owned())
                                .or_default()
                                .insert(device.device_id().to_owned(), share_info.clone());
                        }
                    }

                    // temp use error handling later
                    return Ok(());
                }

                Ok(())
            }
            Err(e) => {
                warn!("Error deserializing room state event: {e}");
                Err(OlmError::JsonError(e))
            }
        }
    }

    /// Docs tbd
    async fn verify_join_rules_event(
        &self,
        // verified_events: &mut BTreeMap<OwnedRoomId, BTreeSet<OwnedEventId>>,
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {

        // why_join ==>|<code>m.room.join_rules</code> event|join_rule_type{"What kind
        // of<br/>join rule?"} join_rule_type==>|Public|check_sender
        // join_rule_type ==>|Restricted|any_old_rooms{"Does the restricted<br/>join
        // rule include any rooms<br/>whose IDs are not RRKs?"}
        // any_old_rooms==>|Yes|check_sender
        // any_old_rooms==>|No|join_state{"Based on<br/>the list of state
        // events<br/>provided in the <code>join</code> event,<br/>does the user's
        // cause-of-membership event<br/>at the start of the list<br/>pass
        // verification?"} join_state -.-> start
        // join_state ==>|Yes|joinrule_match{"Does the join rule event<br/>include a
        // room ID that<br/>matches the room ID from<br/>the provided state?"}
        // join_state ------>|No|reject
        // joinrule_match ===>|Yes|check_sender
        // joinrule_match -->|No|reject

        Ok(())
    }

    /// Docs tbd
    async fn verify_third_party_invite_event(
        &self,
        // verified_events: &mut BTreeMap<OwnedRoomId, BTreeSet<OwnedEventId>>,
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {

        // invite_kind ==>|Created by the homeserver<br/>as a successor of
        // an<br/><code>m.room.third_party_invite</code> event|idserver_sig{"Does the
        // signed<br/>third-party-invite data<br/>have a valid signature<br/>from an
        // identity server?"} idserver_sig -->|No|reject
        // idserver_sig ==>|Yes|threepid_signed_msk{"Does the signed data<br/>contain
        // the user's MSK?"} threepid_signed_msk -->|No|reject
        // threepid_signed_msk ==>|Yes|lookup_threepid["Look up the
        // parent<br/><code>m.room.third_party_invite</code> event"] lookup_threepid
        // ==> threepid_token{"Does the event<br/>have a matching token,<br/>and include
        // the<br/>identity server public key<br/>that made the signature?"}
        // threepid_token -->|No|reject
        // threepid_token ==>|Yes|check_sender

        Ok(())
    }

    /// Docs tbd
    async fn verify_room_tombstone_event(
        &self,
        // verified_events: &mut BTreeMap<OwnedRoomId, BTreeSet<OwnedEventId>>,
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {

        // combine space child and tomebstone verification logic? should be identical
        Ok(())
    }

    /// Docs tbd
    async fn verify_space_child_event(
        &self,
        // verified_events: &mut BTreeMap<OwnedRoomId, BTreeSet<OwnedEventId>>,
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {
        match event.deserialize_as::<OriginalSyncStateEvent<SpaceChildEventContent>>() {
            Ok(sync_event) => {
                let full_event = sync_event.into_full_event(room_id.to_owned());

                // fix error case since only RSK is missing, not master key
                let sender = full_event.sender;
                let rsk = match self.get_user_rsk(&sender).await {
                    Some(k) => k,
                    None => {
                        // Need to pause verification until we can fetch identity credentials from
                        // manager
                        changes.missing_identities.insert(sender.to_owned());
                        // temp: note that events could be duplicated, though does not have effect
                        // on validation, only bloating the store
                        changes
                            .unverified_events
                            .entry(room_id.to_owned())
                            .or_default()
                            .push(event.clone());
                        return Err(OlmError::EventError(EventError::MissingSigningKey));
                    }
                };

                let rrk = full_event.content.room_root_key.to_owned().unwrap_or_default();
                let rsk_str = full_event.content.sender_key.to_owned().unwrap_or_default();
                let derived_room_id = Base64::<UrlSafe>::new(rrk.as_bytes().to_vec());

                let rsk_first_key = rsk.as_ref().get_first_key_and_id().unwrap();

                let rsk2 = Base64::new(rsk_str.as_bytes().to_vec());
                let rsk_map = ruma::signatures::PublicKeyMap::from([(
                    sender.to_owned().to_string(),
                    ruma::signatures::PublicKeySet::from([("ed25519:rsk".to_string(), rsk2)]),
                )]);

                // return early json error deserialization
                let parent_event_id = match full_event.content.parent_event_id.to_owned() {
                    Some(e) => e,
                    None => todo!(),
                };

                // Does the event contain the correct RRK?
                // Does the event have a valid signature by the RSK?
                // Does the user's RSK have a valid signature by the sender's MSK?
                // Has parent event been validated? (Lookup this event's parent event ID - i.e., the sender's cause-of-membership event)
                if derived_room_id.encode() == full_event.room_id.as_str()
                    && rsk_str == rsk.keys().get(&DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, "rsk".into())).unwrap().to_base64()
                    && rsk_first_key.1.verify_json(&sender, rsk_first_key.0, &full_event.content).is_ok()
                    && sender_msk.verify_subkey(&rsk).is_ok()
                    && changes.verified_events.get(room_id).is_some_and(|(_, e)| e.contains(&parent_event_id))
                {
                    // Add event to cache
                    changes.verified_events.entry(room_id.to_owned()).and_modify(|(_, e)| {
                        e.insert(full_event.event_id.clone());
                    });

                    // Pass room membership for room creator, process next event
                    // The user's cause-of-membership event passes verification
                } else {
                    // The user's cause-of-membership event does NOT pass verification

                    // revisit key witholding and edge/cases (see room create validation)

                    if let Some(outbound) = self.store().get_outbound_group_session(room_id).await?
                    {
                        let share_info = ShareInfo::new_withheld(WithheldCode::Unauthorised);

                        for device in
                            self.store().get_user_devices_filtered(&sender).await?.devices()
                        {
                            outbound
                                .shared_with_set
                                .write()
                                .unwrap()
                                .entry(device.user_id().to_owned())
                                .or_default()
                                .insert(device.device_id().to_owned(), share_info.clone());
                        }
                    }

                    // temp use error handling later
                    return Ok(());
                }

                Ok(())
            }
            Err(e) => {
                warn!("Error deserializing room state event: {e}");
                Err(OlmError::JsonError(e))
            }
        }
    }
}
