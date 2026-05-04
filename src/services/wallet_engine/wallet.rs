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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) struct Account {
    pub id: u32,
    pub pubkey: [u8; 33],
    pub address: [u8; 20],
    pub chain_id: u32,
}

static ACCOUNTS: Mutex<[Option<Account>; 16]> = Mutex::new([const { None }; 16]);
static NEXT_ACCOUNT_ID: AtomicU32 = AtomicU32::new(1);

pub(super) fn create_account(pubkey: &[u8; 33], chain_id: u32) -> u32 {
    let id = NEXT_ACCOUNT_ID.fetch_add(1, Ordering::Relaxed);
    let mut address = [0u8; 20];
    derive_address(pubkey, &mut address);
    let mut accounts = ACCOUNTS.lock();
    for slot in accounts.iter_mut() {
        if slot.is_none() {
            *slot = Some(Account { id, pubkey: *pubkey, address, chain_id });
            return id;
        }
    }
    0
}

fn derive_address(pubkey: &[u8; 33], address: &mut [u8; 20]) {
    let hash = crate::crypto::sha3::keccak256(&pubkey[1..]);
    address.copy_from_slice(&hash[12..32]);
}

pub(super) fn get_account(id: u32) -> Option<Account> {
    let accounts = ACCOUNTS.lock();
    for slot in accounts.iter() {
        if let Some(account) = slot {
            if account.id == id {
                return Some(Account {
                    id: account.id,
                    pubkey: account.pubkey,
                    address: account.address,
                    chain_id: account.chain_id,
                });
            }
        }
    }
    None
}

pub(super) fn delete_account(id: u32) -> bool {
    let mut accounts = ACCOUNTS.lock();
    for slot in accounts.iter_mut() {
        if let Some(account) = slot {
            if account.id == id {
                *slot = None;
                return true;
            }
        }
    }
    false
}

pub(super) fn account_count() -> u8 {
    ACCOUNTS.lock().iter().filter(|a| a.is_some()).count() as u8
}
