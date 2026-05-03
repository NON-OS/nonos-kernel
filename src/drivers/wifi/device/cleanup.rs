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

use super::super::constants::csr;
use super::intel::IntelWifiDevice;

impl IntelWifiDevice {
    pub(super) fn shutdown_hardware(&mut self) {
        self.trans.regs.write32(csr::INT_MASK, 0);
        self.trans.regs.write32(csr::FH_INT_STATUS, 0xFFFFFFFF);
        self.trans.regs.write32(csr::INT, 0xFFFFFFFF);

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

impl Drop for IntelWifiDevice {
    fn drop(&mut self) {
        self.shutdown_hardware();

        for queue in self.tx_queues.drain(..) {
            drop(queue);
        }

        if let Some(rx_queue) = self.rx_queue.take() {
            drop(rx_queue);
        }

        if let Some(cmd_queue) = self.cmd_queue.take() {
            drop(cmd_queue);
        }

        if let Some(ref mut wpa) = self.wpa_context {
            wpa.pmk.fill(0);
            wpa.ptk.fill(0);
        }

        crate::log::info!("iwlwifi: device resources released");
    }
}
