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

use alloc::vec::Vec;
use spin::Mutex;

use crate::crypto::{blake3, fill_random};

const CAP: usize = 64;
static SURBS: Mutex<Vec<Surb>> = Mutex::new(Vec::new());

#[derive(Clone, Copy)]
struct Surb {
    owner: u32,
    id: u32,
    session: u32,
}

pub fn create(owner: u32, session: u32, cred: &[u8; 32]) -> Option<(u32, [u8; 32])> {
    let mut seed = [0u8; 32];
    fill_random(&mut seed).ok()?;
    let id = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]).max(1);
    let tag = tag(owner, session, id, cred, &seed)?;
    let mut g = SURBS.lock();
    if g.len() >= CAP {
        g.remove(0);
    }
    g.push(Surb { owner, id, session });
    Some((id, tag))
}

pub fn session_for_surb(owner: u32, id: u32) -> Option<u32> {
    SURBS.lock().iter().find(|s| s.owner == owner && s.id == id).map(|s| s.session)
}

fn tag(owner: u32, session: u32, id: u32, cred: &[u8; 32], seed: &[u8; 32]) -> Option<[u8; 32]> {
    let mut material = Vec::with_capacity(76);
    material.extend_from_slice(&owner.to_le_bytes());
    material.extend_from_slice(&session.to_le_bytes());
    material.extend_from_slice(&id.to_le_bytes());
    material.extend_from_slice(cred);
    material.extend_from_slice(seed);
    let mut out = [0u8; 32];
    blake3(&material, &mut out).ok()?;
    Some(out)
}
