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

//! Reverse-order broker grant teardown invoked when a setup phase
//! fails partway. Best-effort: an `EINVAL` from a doubly-released
//! grant is harmless because the broker has already revoked it.

use nonos_libc::{mk_device_release, mk_dma_unmap, mk_irq_unbind, mk_mmio_unmap, IrqBindOut,
    MmioMapOut};

pub fn after(device_id: u64, mmio: &MmioMapOut, irq: &IrqBindOut, dma_grants: &[u64]) {
    for &g in dma_grants.iter().rev() {
        let _ = mk_dma_unmap(g);
    }
    let _ = mk_irq_unbind(irq.grant_id);
    let _ = mk_mmio_unmap(mmio.grant_id);
    let _ = mk_device_release(device_id);
}
