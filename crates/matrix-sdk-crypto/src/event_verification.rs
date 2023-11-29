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
    store::{Changes, StoreTransaction, RoomMemberVerificationMembershipInfo},
    types::{
        events::room_key_withheld::WithheldCode, CrossSigningKey, MasterPubkey, RoomSigningPubkey,
        Signatures, SigningKey, SigningKeys,
    },
    EventError, OlmError, OlmMachine, UserIdentities, SignatureError,
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
        changes.room_member_verification.verified_events =
            self.store().get_value("rmv_verified_events").await.unwrap_or_default().unwrap_or_default();
        // changes.unverified_events =
        // self.store().get_value("unverified_events").await.unwrap_or_default().
        // unwrap_or_default();
        changes.room_member_verification.unverified_events = BTreeMap::default();
        changes.room_member_verification.missing_identities = self
            .store()
            .get_value("rmv_missing_identities")
            .await
            .unwrap_or_default()
            .unwrap_or_default();
        changes.room_member_verification.blacklisted_members = self.store().get_value("rmv_blacklisted_members").await.unwrap_or_default().unwrap_or_default();

        // Prevents cloning event data, will be merged with changes later
        let unverified_events: BTreeMap<OwnedRoomId, Vec<Raw<AnySyncStateEvent>>> = self
            .store()
            .get_value("rmv_unverified_events")
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

        changes.room_member_verification.unverified_events.extend(unverified_events);
        self.verify_events(changes, room_events).await?;

        // save changes in main method later (in save_changes method)?
        self.store().set_value("rmv_verified_events", &changes.room_member_verification.verified_events).await?;
        self.store().set_value("rmv_unverified_events", &changes.room_member_verification.unverified_events).await?;
        self.store().set_value("rmv_missing_identities", &changes.room_member_verification.missing_identities).await?;
        self.store().set_value("rmv_blacklisted_members", &changes.room_member_verification.blacklisted_members).await?;

        // todo: add a return error list of failed verified event ids (and perhaps error info if needed)
        //       clients need to handle actions like tombstoning which cannot be handled fully in crypto crate

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
                                .room_member_verification
                                .unverified_events
                                .entry(room_id.to_owned())
                                .or_default()
                                .push(event.clone());
                            continue;
                        }

                        if let Some(sender_msk) = self.get_user_msk(&e.sender().to_owned()).await {
                            if changes.room_member_verification.missing_identities.contains(&e.sender().to_owned()) {
                                changes.room_member_verification.missing_identities.remove(&e.sender().to_owned());
                            }

                            if e.event_type() == StateEventType::RoomCreate {
                                self.verify_room_create_event(changes, room_id, &sender_msk, event)
                                    .await?;
                            }
                            // Key being present in verified_events implies room id version >= V12
                            else if changes.room_member_verification.verified_events.contains_key(room_id) {
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

                            self.add_missing_identity(changes, &e.sender().to_owned(), room_id, event);
                        }
                    }
                    Err(e) => {
                        warn!("Error deserializing room state event: {e}");
                        continue;
                    }
                }
            }
        }

        changes.room_member_verification.missing_identities.extend(new_missing_identities);

        Ok(())
    }

    /// docs tbd
    fn add_missing_identity(&self, changes: &mut Changes, user_id: &OwnedUserId, room_id: &OwnedRoomId, event: &Raw<AnySyncStateEvent>) {
        // Need to pause verification until we can fetch identity credentials from
        // manager
        changes.room_member_verification.missing_identities.insert(user_id.to_owned());
        // temp: note that events could be duplicated, though does not have effect
        // on validation, only bloating the store
        changes
            .room_member_verification
            .unverified_events
            .entry(room_id.to_owned())
            .or_default()
            .push(event.clone());
    }

    /// docs tbd
    async fn get_user_msk(&self, user_id: &OwnedUserId) -> Option<MasterPubkey> {
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

    /// docs tbd
    fn verify_event_content(
        &self,
        sender_key: Ed25519PublicKey,
        event: &Raw<AnySyncStateEvent>
    ) -> bool {
        // temp ruma compatibility
        let json_str = event.json().to_string().replace("org.matrix.msc3917.v1.signatures", "signatures");
        let updated_event = serde_json::from_str::<Raw<AnySyncStateEvent>>(json_str.as_str()).unwrap();

        // only verify event's content, not full event
        // match event.get_field::<ruma::CanonicalJsonObject>("content") {
        match updated_event.get_field::<ruma::CanonicalJsonObject>("content") {
            Ok(Some(content)) => {
                let public_key = Base64::parse(sender_key.to_base64()).unwrap();

                // panic!("VERIFY RESULT: {:?}", res);
                return ruma::signatures::verify_state_event_content(public_key, &content).is_ok_and(|r| r == true);
            },
            Ok(None) | Err(_) => false,
        }
    }

    /// docs tbd
    // async fn withold_session(
    //     &self,
    //     user_id: &OwnedUserId,
    //     room_id: &OwnedRoomId,
    // ) -> OlmResult<()> {
    //     // Should not withhold keys to ourself, although event verification failed
    //     if user_id == self.user_id() {
    //         return Ok(());
    //     }

    //     // revisit key witholding and edge/cases

    //     // need to consider, if roomkey withheld only blacklists devices, what
    //     // happens if new devices are added later?

    //     // Note that this procedure specifically verifies that a particular MSK may
    //     // legitimately belong in the room. Devices that
    //     // claim to belong to a user, but are not signed by a Self-Signing Key
    //     // signed by that particular MSK, must not be
    //     // treated as belonging in the room.

    //     // If clients are unable to verify a user's cause-of-membership event for a
    //     // room, they may refuse to share cryptographic
    //     // material in that room with that user.


    //     // self.inner.group_session_manager.get_outbound_group_session(room_id)

    //     // let outbound_session = self
    //     //     .inner
    //     //     .outbound_group_sessions
    //     //     .get_with_id(session.room_id(), session.session_id())
    //     //     .await;

    //     // println!("Keys added, SO FAILED then????");

    //     // if let Some(outbound) =
    //     //     self.store().get_outbound_group_session(room_id).await?
    //     // // if let Some(outbound) = self.inner.group_session_manager.get_outbound_group_session(room_id)
    //     // // if let Some(outbound) = self.inner.key_request_machine.get_or_load(room_id).await
    //     // {
    //     //     let share_info = ShareInfo::new_withheld(WithheldCode::Unauthorised);

    //     //     println!("Keys added, STARTING DEVICES?");
    //     //     for device in
    //     //         self.store().get_user_devices_filtered(&user_id).await?.devices()
    //     //     {
    //     //         println!("Keys added, but looks like session was already established?");
    //     //         outbound
    //     //             .shared_with_set
    //     //             .write()
    //     //             .unwrap()
    //     //             .entry(device.user_id().to_owned())
    //     //             .or_default()
    //     //             .insert(device.device_id().to_owned(), share_info.clone());
    //     //     }
    //     // }

    //     Ok(())
    // }

    /// Docs tbd
    async fn verify_room_create_event(
        &self,
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
                    let creator_key = full_event.content.to_owned().creator_key.unwrap_or_default();
                    let rrk = match Ed25519PublicKey::from_base64(&full_event.content.to_owned().room_root_key.unwrap_or_default()) {
                        Ok(key) => key,
                        Err(e) => {
                            warn!("Error deserializing room root key: {e}");
                            // todo: change to proper error type
                            return Err(OlmError::MissingSession);
                        },
                    };

                    // let rrk_base64 = rrk.to_base64();
                    let derived_room_id = format!("!{}", Base64::<UrlSafe>::new(rrk.as_bytes().to_vec()).encode());

                    // notable things to document / changes in proposal
                    // * noting what it means/how to not share cryptographic room material on verification failure? (mostly implementation specific, while flagging device for room key withheld)

                    // for ruma signatures interoperability purposes, just go with :1 for key id instead of rrk or rsk ids (and document MSC on that)
                    // && self.verify_event_content(&sender, format!("ed25519:{rrk_base64}").as_str(), rrk, event).await?


                    // Does the event contain the correct RRK and the user's MSK?
                    // Does the event have a valid signature by the RRK?
                    if derived_room_id == full_event.room_id.as_str()
                        && creator_key == sender_msk.get_first_key().unwrap().to_base64()
                        && self.verify_event_content(rrk, event)
                    {
                        // Pass room membership for room creator, process next event
                        // The user's cause-of-membership event passes verification

                        // Add event to cache
                        let member_info = changes
                            .room_member_verification
                            .verified_events
                            .entry(room_id.to_owned())
                            .or_default()
                            .entry(sender.to_owned())
                            .or_default();

                        member_info.user_key = creator_key;
                        member_info.room_create_parent_event =
                            .insert(RoomMemberVerificationMembershipInfo { user_key: creator_key, ..Default::default() });

                        // changes
                        //     .room_member_verification
                        //     .verified_events
                        //     .entry(room_id.to_owned())
                        //     .or_default()
                        //     .insert(full_event.event_id.to_owned());

                        // note unsigned server event requires additional handling of tracking keys?
                        changes
                            .room_member_verification
                            .master_keys
                            .entry(room_id.to_owned())
                            .or_default()
                            .insert(sender, RoomMemberVerificationMasterKeys { key: creator_key, membership_events: BTreeSet::from([(full_event.content.event_type().to_string(), full_event.event_id.to_owned())]) });

                        if let Some(invited_user_keys) = full_event.content.to_owned().invited_user_keys {
                            for (id, keys) in invited_user_keys {
                                if let Some(key) = keys.first_key_value() {
                                    changes
                                        .room_member_verification
                                        .master_keys
                                        .entry(room_id.to_owned())
                                        .or_default()
                                        .insert(id, RoomMemberVerificationMasterKeys { key: key.1.to_owned(), membership_events: BTreeSet::from([(full_event.content.event_type().to_string(), full_event.event_id.to_owned())]) });
                                }
                            }
                        }
                    } else {
                        println!("Verificaiton failed, event info");
                        println!("room ids: {:?} {:?}", derived_room_id, full_event.room_id.as_str());
                        println!("creator keys: {:?} {:?}", creator_key, sender_msk.get_first_key().unwrap().to_base64());
                        println!("rrk sig: {:?}", self.verify_event_content(rrk, event));

                        // The user's cause-of-membership event does NOT pass verification
                        changes.room_member_verification.blacklisted_members.entry(room_id.to_owned()).or_default().insert(sender.to_owned());

                        // self.withold_session(&sender, &room_id).await?;

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
        changes: &mut Changes,
        room_id: &OwnedRoomId,
        sender_msk: &MasterPubkey,
        event: &Raw<AnySyncStateEvent>,
    ) -> OlmResult<()> {
        match event.deserialize_as::<OriginalSyncStateEvent<RoomMemberEventContent>>() {
            Ok(sync_event) => {
                let full_event = sync_event.into_full_event(room_id.to_owned());

                let invited_user = full_event.state_key;
                let user_msk = match self.get_user_msk(&invited_user).await {
                    Some(k) => k,
                    None => {
                        self.add_missing_identity(changes, &invited_user, room_id, event);
                        return Err(OlmError::EventError(EventError::MissingSigningKey));
                    }
                };

                // fix error case since only RSK is missing, not master key
                let sender = full_event.sender;
                let rsk = match self.get_user_rsk(&sender).await {
                    Some(k) => k,
                    None => {
                        self.add_missing_identity(changes, &sender, room_id, event);
                        return Err(OlmError::EventError(EventError::MissingSigningKey));
                    }
                };

                let rrk = match Ed25519PublicKey::from_base64(&full_event.content.to_owned().room_root_key.unwrap_or_default()) {
                    Ok(key) => key,
                    Err(e) => {
                        warn!("Error deserializing room root key: {e}");
                        // todo: change to proper error type
                        return Err(OlmError::MissingSession);
                    },
                };
                let derived_room_id = format!("!{}", Base64::<UrlSafe>::new(rrk.as_bytes().to_vec()).encode());
                let user_msk_str = full_event.content.user_key.to_owned().unwrap_or_default();
                let rsk_str = full_event.content.sender_key.to_owned().unwrap_or_default();
                let (_, rsk_first_key) = rsk.as_ref().get_first_key_and_id().unwrap();

                // return early json error deserialization
                let parent_event_id = match full_event.content.parent_event_id.to_owned() {
                    Some(e) => e,
                    None => {
                        warn!("Error deserializing parent_event_id: {:?}", event);
                        // todo: change to proper error type
                        return Err(OlmError::MissingSession);
                        // Err(OlmError::JsonError(e))
                    },
                };

                let mut is_verified = false;

                // confirm space child events if parent event id)
                // also if ourself is banned/left, then need to remove old events in verified_events

                // Does the event contain the correct RRK and the invited user's MSK?
                // Has parent event been validated? (Lookup this event's parent event ID - i.e., the sender's cause-of-membership event)
                // Does the sender's MSK match the MSK in the sender's cause-of-membership event?
                if matches!(full_event.content.membership, MembershipState::Invite | MembershipState::Join | MembershipState::Leave | MembershipState::Ban)
                    && derived_room_id == full_event.room_id.as_str()
                    && user_msk_str == user_msk.get_first_key().unwrap().to_base64()
                    && changes.room_member_verification.verified_events.get(room_id).is_some_and(|e| e.contains(&parent_event_id))
                    && changes.room_member_verification.master_keys.get(room_id).is_some_and(|m|
                        m.get(&invited_user).is_some_and(|e|
                            e.key == user_msk_str && e.membership_events.iter().any(|(event_type, _)| *event_type == StateEventType::RoomCreate.to_string())
                        )
                    )
                {
                    // Does the event have a signature and RSK?
                    // Is the parent event a m.room.create event?
                    if full_event.content.sender_key.is_none()
                        && full_event.content.signatures.is_none()
                        && matches!(full_event.content.membership, MembershipState::Invite | MembershipState::Join)
                        && changes.room_member_verification.master_keys.get(room_id).is_some_and(|m|
                            m.get(&invited_user).is_some_and(|e|
                                e.membership_events.contains(&(StateEventType::RoomCreate.to_string(), parent_event_id.to_owned()))
                            )
                        ) {

                        is_verified = true;
                    }
                    // Does the event have a valid signature by the RSK?
                    // Does the user's RSK have a valid signature by the sender's MSK?
                    else if rsk_str == rsk_first_key.to_base64()
                        && self.verify_event_content( rsk_first_key, event)
                        && sender_msk.verify_subkey(&rsk).is_ok() {

                        is_verified = true;
                    }
                }

                if is_verified {
                    // Pass room membership for room creator, process next event
                    // The user's cause-of-membership event passes verification

                    // Add event to cache
                    changes
                        .room_member_verification
                        .verified_events
                        .entry(room_id.to_owned())
                        .or_default()
                        .insert(full_event.event_id.to_owned());

                    // note unsigned server event requires additional handling of tracking keys?
                    let user_msk_info = changes
                        .room_member_verification
                        .master_keys
                        .entry(room_id.to_owned())
                        .or_default()
                        .entry(invited_user.to_owned())
                        .or_default();

                    user_msk_info.key = user_msk_str;
                    user_msk_info.membership_events.insert((full_event.content.event_type().to_string(), parent_event_id));
                }
                else {
                    println!("Verificaiton failed, event info");
                    // println!("room ids: {:?} {:?}", derived_room_id, full_event.room_id.as_str());
                    // println!("creator keys: {:?} {:?}", creator_key, sender_msk.get_first_key().unwrap().to_base64());
                    // println!("rrk sig: {:?}", self.verify_event_content(&sender, "ed25519:1", rrk, event));

                    // The user's cause-of-membership event does NOT pass verification
                    changes.room_member_verification.blacklisted_members.entry(room_id.to_owned()).or_default().insert(sender.to_owned());

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
                        changes.room_member_verification.missing_identities.insert(sender.to_owned());
                        // temp: note that events could be duplicated, though does not have effect
                        // on validation, only bloating the store
                        changes
                            .room_member_verification
                            .unverified_events
                            .entry(room_id.to_owned())
                            .or_default()
                            .push(event.clone());
                        return Err(OlmError::EventError(EventError::MissingSigningKey));
                    }
                };

                let rrk = Ed25519PublicKey::from_base64(&full_event.content.room_root_key.unwrap_or_default()).unwrap(); // handle unwrap
                let derived_room_id = format!("!{}", Base64::<UrlSafe>::new(rrk.as_bytes().to_vec()).encode());
                let rsk_str = full_event.content.sender_key.to_owned().unwrap_or_default();
                let (rsk_key_id, rsk_first_key) = rsk.as_ref().get_first_key_and_id().unwrap();

                // return early json error deserialization
                let parent_event_id = match full_event.content.parent_event_id.to_owned() {
                    Some(e) => e,
                    None => todo!(),
                };

                // Does the event contain the correct RRK?
                // Does the event have a valid signature by the RSK?
                // Does the user's RSK have a valid signature by the sender's MSK?
                // Has parent event been validated? (Lookup this event's parent event ID - i.e., the sender's cause-of-membership event)
                if derived_room_id == full_event.room_id.as_str()
                    && rsk_str == rsk_first_key.to_base64()
                    && self.verify_event_content( rsk_first_key, event)
                    // && self.verify_event_content(&sender, rsk_key_id.as_str(), rsk_first_key, event)
                    && sender_msk.verify_subkey(&rsk).is_ok()
                    && changes.room_member_verification.verified_events.get(room_id).is_some_and(|e| e.contains(&parent_event_id))
                {
                    // Add event to cache
                    changes
                        .room_member_verification
                        .verified_events
                        .entry(room_id.to_owned())
                        .or_default()
                        .insert(full_event.event_id);

                    // Pass room membership for room creator, process next event
                    // The user's cause-of-membership event passes verification
                } else {
                    // The user's cause-of-membership event does NOT pass verification
                    // self.withold_session(&sender, &room_id).await?;

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
