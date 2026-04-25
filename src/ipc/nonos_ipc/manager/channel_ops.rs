// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::super::channel::NonosIPCChannel;
use super::super::error::IpcManagerError;
use super::super::types::NonosChannelType;
use super::core::NonosIPCManager;
use super::types::MAX_PARTICIPANTS;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl NonosIPCManager {
    pub fn create_channel(
        &self,
        creator_id: u64,
        channel_type: NonosChannelType,
        mut participants: Vec<u64>,
    ) -> Result<u64, IpcManagerError> {
        if !participants.contains(&creator_id) {
            participants.push(creator_id);
        }
        if participants.is_empty() {
            return Err(IpcManagerError::NoParticipants);
        }
        if participants.len() > MAX_PARTICIPANTS {
            return Err(IpcManagerError::TooManyParticipants {
                count: participants.len(),
                max: MAX_PARTICIPANTS,
            });
        }
        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        let capacity = self.default_queue_cap.load(Ordering::Relaxed) as usize;
        let channel =
            NonosIPCChannel::new(channel_id, channel_type, participants.clone(), capacity);
        {
            let mut ch_map = self.channels.write();
            if ch_map.contains_key(&channel_id) {
                return Err(IpcManagerError::ChannelIdCollision { channel_id });
            }
            ch_map.insert(channel_id, channel);
        }
        {
            let mut proc_map = self.process_channels.write();
            for pid in participants {
                proc_map.entry(pid).or_insert_with(Vec::new).push(channel_id);
            }
        }
        self.stats.channels_created.fetch_add(1, Ordering::Relaxed);
        Ok(channel_id)
    }

    pub fn destroy_channel(
        &self,
        destroyer_id: u64,
        channel_id: u64,
    ) -> Result<(), IpcManagerError> {
        let participants = {
            let ch_map = self.channels.read();
            let channel =
                ch_map.get(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;
            if !channel.has_participant(destroyer_id) {
                return Err(IpcManagerError::DestroyerNotAuthorized { destroyer_id, channel_id });
            }
            channel.participants.clone()
        };
        self.channels.write().remove(&channel_id);
        {
            let mut proc_map = self.process_channels.write();
            for pid in participants {
                if let Some(list) = proc_map.get_mut(&pid) {
                    list.retain(|&cid| cid != channel_id);
                    if list.is_empty() {
                        proc_map.remove(&pid);
                    }
                }
            }
        }
        self.stats.channels_destroyed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
