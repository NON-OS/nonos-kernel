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

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub enum FilterAction {
    Accept,
    Drop,
}

pub trait PacketFilter: Send + Sync + 'static {
    fn pre_recv(&self, _frame: &[u8]) -> FilterAction {
        FilterAction::Accept
    }
    fn post_recv(&self, _ethertype: u16, _payload: &[u8]) -> FilterAction {
        FilterAction::Accept
    }
    fn pre_send(&self, _frame: &[u8]) -> FilterAction {
        FilterAction::Accept
    }
}

static FILTERS: Mutex<Vec<Arc<dyn PacketFilter>>> = Mutex::new(Vec::new());

pub fn add_filter(f: Arc<dyn PacketFilter>) {
    FILTERS.lock().push(f);
}

pub(super) fn run_pre(frame: &[u8]) -> bool {
    for f in FILTERS.lock().iter() {
        if matches!(f.pre_recv(frame), FilterAction::Drop) {
            return false;
        }
    }
    true
}

pub(super) fn run_post(ethertype: u16, payload: &[u8]) -> bool {
    for f in FILTERS.lock().iter() {
        if matches!(f.post_recv(ethertype, payload), FilterAction::Drop) {
            return false;
        }
    }
    true
}

pub(super) fn run_send(frame: &[u8]) -> bool {
    for f in FILTERS.lock().iter() {
        if matches!(f.pre_send(frame), FilterAction::Drop) {
            return false;
        }
    }
    true
}
