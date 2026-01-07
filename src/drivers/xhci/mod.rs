// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub mod constants;
pub mod controller;
pub mod dma;
pub mod error;
pub mod rings;
pub mod stats;
pub mod trb;
pub mod types;

#[cfg(test)]
mod tests;

pub use constants::{
    SPEED_FULL, SPEED_HIGH, SPEED_LOW, SPEED_SUPER, SPEED_SUPER_PLUS, TRB_IOC, TRB_TYPE_NORMAL,
    XHCI_CLASS, XHCI_PROGIF, XHCI_SUBCLASS,
};

pub use controller::{get_controller, init_xhci, XhciController, XHCI_CONTROLLER};

pub use controller::XHCI_CONTROLLER as XHCI_ONCE;

pub use dma::DmaRegion;

pub use error::{XhciError, XhciResult};

pub use rings::{CommandRing, EndpointRing, EventRing, TransferRing};

pub use stats::{ControllerHealth, XhciStatistics, XhciStats};

pub use trb::Trb;

pub use types::{
    DeviceContext, EpContext, EpState, ErstEntry, InputContext, InputControlContext, SlotContext,
    SlotState, UsbDeviceDescriptor, XhciConfig,
};

pub fn control_transfer(
    slot_id: u8,
    setup_packet: [u8; 8],
    data_buffer: Option<&mut [u8]>,
    _timeout_us: u32,
) -> Result<usize, &'static str> {
    let ctrl_mutex = XHCI_CONTROLLER
        .get()
        .ok_or("xHCI controller not initialized")?;
    let mut ctrl = ctrl_mutex.lock();

    ctrl.validate_slot_id(slot_id).map_err(|e| e.as_str())?;

    let bm_request_type = setup_packet[0];
    let b_request = setup_packet[1];
    let w_value = u16::from_le_bytes([setup_packet[2], setup_packet[3]]);
    let w_index = u16::from_le_bytes([setup_packet[4], setup_packet[5]]);
    let w_length = u16::from_le_bytes([setup_packet[6], setup_packet[7]]);

    let is_in = (bm_request_type & 0x80) != 0;
    let has_data = w_length > 0;

    let ep0 = ctrl.ep0_ring.as_mut().ok_or("EP0 ring not initialized")?;

    let setup = trb::SetupStageTrbBuilder::new()
        .setup_packet(bm_request_type, b_request, w_value, w_index, w_length)
        .transfer_type(has_data, is_in)
        .cycle(ep0.cycle())
        .build();

    let mut last_trb_ptr = ep0.enqueue(setup).map_err(|e| e.as_str())?;
    let mut bytes_transferred = 0usize;

    if let (true, Some(buffer)) = (has_data, data_buffer) {
        let transfer_len = core::cmp::min(w_length as usize, buffer.len());

        let dma_buf = DmaRegion::new(transfer_len, true).map_err(|e| e.as_str())?;

        if !is_in {
            dma_buf
                .copy_from(0, &buffer[..transfer_len])
                .map_err(|e| e.as_str())?;
        }

        let data = trb::DataStageTrbBuilder::new()
            .data_buffer(dma_buf.phys(), transfer_len as u32)
            .direction_in(is_in)
            .ioc(true)
            .cycle(ep0.cycle())
            .build();

        ep0.enqueue(data).map_err(|e| e.as_str())?;

        let status = trb::StatusStageTrbBuilder::new()
            .direction_in(!is_in)
            .cycle(ep0.cycle())
            .build();

        last_trb_ptr = ep0.enqueue(status).map_err(|e| e.as_str())?;

        ctrl.ring_doorbell(slot_id, 1);

        ctrl.wait_transfer_completion(last_trb_ptr)?;

        if is_in {
            dma_buf
                .copy_to(0, &mut buffer[..transfer_len])
                .map_err(|e| e.as_str())?;
        }

        bytes_transferred = transfer_len;
    } else {
        let status = trb::StatusStageTrbBuilder::new()
            .direction_in(true)
            .ioc(true)
            .cycle(ep0.cycle())
            .build();

        last_trb_ptr = ep0.enqueue(status).map_err(|e| e.as_str())?;

        ctrl.ring_doorbell(slot_id, 1);
        ctrl.wait_transfer_completion(last_trb_ptr)?;
    }

    Ok(bytes_transferred)
}

pub fn get_stats() -> Option<XhciStats> {
    get_controller().map(|ctrl| ctrl.get_stats())
}

pub fn get_health() -> ControllerHealth {
    if let Some(stats) = get_stats() {
        ControllerHealth::from_stats(&stats)
    } else {
        ControllerHealth::NotInitialized
    }
}

pub struct XhciControllerHandle;

impl XhciControllerHandle {
    pub fn get_stats() -> XhciStats {
        get_stats().unwrap_or_default()
    }
}
