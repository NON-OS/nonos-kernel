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
use alloc::collections::BTreeMap;
use spin::RwLock;
use crate::capsule::{self, CapsuleId, caps::CAP_IPC};
use super::types::{CapsuleMsg, MsgError, RoutePolicy, MAX_MSG_SIZE};

type RoutePair = (CapsuleId, CapsuleId);
static ROUTES: RwLock<Option<BTreeMap<RoutePair, RoutePolicy>>> = RwLock::new(None);

pub fn init_router() { *ROUTES.write() = Some(BTreeMap::new()); }

type RouteMap = BTreeMap<RoutePair, RoutePolicy>;

pub fn set_route(src: CapsuleId, dst: CapsuleId, policy: RoutePolicy) {
    if let Some(r) = ROUTES.write().as_mut() { r.insert((src, dst), policy); }
}

pub fn get_route(src: CapsuleId, dst: CapsuleId) -> RoutePolicy {
    ROUTES.read().as_ref().and_then(|r: &RouteMap| r.get(&(src, dst)).copied()).unwrap_or(RoutePolicy::Deny)
}

pub fn remove_route(src: CapsuleId, dst: CapsuleId) {
    if let Some(r) = ROUTES.write().as_mut() { r.remove(&(src, dst)); }
}

pub fn check_route(msg: &CapsuleMsg) -> Result<(), MsgError> {
    if msg.payload.len() > MAX_MSG_SIZE { return Err(MsgError::TooLarge); }
    match get_route(msg.src, msg.dst) {
        RoutePolicy::Allow => Ok(()),
        RoutePolicy::Deny => Err(MsgError::NotAllowed),
        RoutePolicy::RequireCap(cap) => {
            let sb = capsule::registry::get_sandbox(msg.src).ok_or(MsgError::NotFound)?;
            if sb.has_cap(cap) && sb.has_cap(CAP_IPC) { Ok(()) } else { Err(MsgError::NotAllowed) }
        }
    }
}

pub fn allow_all(src: CapsuleId, dst: CapsuleId) {
    set_route(src, dst, RoutePolicy::Allow);
    set_route(dst, src, RoutePolicy::Allow);
}

pub fn deny_all(src: CapsuleId, dst: CapsuleId) {
    remove_route(src, dst);
    remove_route(dst, src);
}
