// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! AHCI (Advanced Host Controller Interface) SATA Driver
//!
//! # References
//! - AHCI 1.3.1 Specification (Intel)
//! - ATA/ATAPI-8 ACS (Data Set Management / TRIM)
//! - Serial ATA Revision 3.0 Specification
//!
//! 
//!                      AhciController                           
//!    ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ 
//!    │ Port 0  │  │ Port 1  │  │ Port 2  │  │ Port N  │ 
//!    │(PortDma)│  │(PortDma)│  │(PortDma)│  │(PortDma)│        
//!    └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘        
//!         │            │            │            │              
//!         ▼            ▼            ▼            ▼              
//!    ┌─────────────────────────────────────────────────┐       
//!    │            Command List (32 slots)              │       
//!    │     Command Headers → Command Tables → PRDTs    │       
//!    └─────────────────────────────────────────────────┘      


pub mod error;
pub mod constants;
pub mod types;
pub mod dma;
pub mod controller;
pub mod stats;

#[cfg(test)]
mod tests;

// Re-export main types at module root for convenience
pub use error::AhciError;
pub use types::{AhciDevice, AhciDeviceType, AhciHba, CommandHeader, CommandTable, PhysicalRegionDescriptor};
pub use controller::{AhciController, hdr_flags_for};
pub use stats::AhciStats;

use spin::Once;

/// Global AHCI controller instance (initialized once via Once).
///
/// Using spin::Once ensures thread-safe, one-time initialization without
/// requiring unsafe static mut access patterns.
static AHCI_CONTROLLER: Once<AhciController> = Once::new();

/// Initializes the AHCI subsystem.
pub fn init_ahci() -> Result<(), AhciError> {
    // Check if already initialized
    if AHCI_CONTROLLER.is_completed() {
        return Ok(());
    }

    // Find AHCI controller via PCI
    let ahci_device = crate::drivers::pci::find_device_by_class(0x01, 0x06)
        .ok_or(AhciError::NoControllerFound)?;

    let mut controller = AhciController::new(&ahci_device)?;
    controller.init()?;

    // Store in global instance (Once ensures this only happens once)
    AHCI_CONTROLLER.call_once(|| controller);

    crate::log::logger::log_critical("AHCI subsystem initialized");
    Ok(())
}

#[inline]
pub fn get_controller() -> Option<&'static AhciController> {
    AHCI_CONTROLLER.get()
}
