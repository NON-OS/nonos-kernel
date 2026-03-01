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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use super::state::MscDeviceState;

static MSC_DEVICES: Mutex<BTreeMap<u8, Arc<Mutex<MscDeviceState>>>> = Mutex::new(BTreeMap::new());

pub(super) fn register_msc_device(slot_id: u8, state: Arc<Mutex<MscDeviceState>>) {
    MSC_DEVICES.lock().insert(slot_id, state);
}

pub(super) fn unregister_msc_device(slot_id: u8) {
    MSC_DEVICES.lock().remove(&slot_id);
}

pub fn get_msc_device(slot_id: u8) -> Option<Arc<Mutex<MscDeviceState>>> {
    MSC_DEVICES.lock().get(&slot_id).cloned()
}

pub fn get_msc_devices() -> Vec<Arc<Mutex<MscDeviceState>>> {
    MSC_DEVICES.lock().values().cloned().collect()
}
