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
use spin::Mutex;

use super::types::{CIRCUIT_SENDME_INCREMENT, CIRCUIT_SENDME_WINDOW};
use crate::network::onion::CircuitId;

pub(super) struct FlowControlManager {
    circuit_windows: Mutex<BTreeMap<CircuitId, CircuitWindow>>,
    congestion: CongestionControl,
}

#[derive(Debug, Clone)]
pub(super) struct CircuitWindow {
    pub send_window: i32,
    pub package_window: i32,
}

impl FlowControlManager {
    pub(super) fn new() -> Self {
        Self {
            circuit_windows: Mutex::new(BTreeMap::new()),
            congestion: CongestionControl::new(),
        }
    }

    fn ensure(&self, cid: CircuitId) {
        let mut map = self.circuit_windows.lock();
        map.entry(cid).or_insert(CircuitWindow {
            send_window: CIRCUIT_SENDME_WINDOW,
            package_window: CIRCUIT_SENDME_WINDOW,
        });
    }

    pub(super) fn can_package_on_circuit(&self, cid: CircuitId) -> bool {
        self.ensure(cid);
        let map = self.circuit_windows.lock();
        if let Some(w) = map.get(&cid) {
            w.send_window > 0 && w.package_window > 0
        } else {
            false
        }
    }

    pub(super) fn on_circuit_pack(&self, cid: CircuitId, cells: i32) {
        let mut map = self.circuit_windows.lock();
        if let Some(w) = map.get_mut(&cid) {
            w.send_window -= cells;
            w.package_window -= cells;
        }
    }

    pub(super) fn handle_circuit_sendme(&self, cid: CircuitId) {
        let mut map = self.circuit_windows.lock();
        if let Some(w) = map.get_mut(&cid) {
            w.send_window += CIRCUIT_SENDME_INCREMENT;
            w.package_window += CIRCUIT_SENDME_INCREMENT;
        }
        self.congestion.on_ack(cid);
    }

    pub(super) fn cc_tick(&self, cid: CircuitId) {
        self.congestion.on_tick(cid);
    }
}

pub(super) struct CongestionControl {
}

impl CongestionControl {
    pub(super) fn new() -> Self {
        Self {
        }
    }

    pub(super) fn on_ack(&self, _cid: CircuitId) {
    }

    pub(super) fn on_tick(&self, _cid: CircuitId) {
    }
}
