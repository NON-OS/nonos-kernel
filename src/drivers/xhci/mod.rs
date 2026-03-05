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

mod api;
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

pub use api::{control_transfer, enumerate_all_devices, enumerate_first_device, get_enumerated_slots, get_health, get_stats, XhciControllerHandle};
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
