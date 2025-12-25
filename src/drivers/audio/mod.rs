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
//! Intel HD Audio (HDA) Controller Driver
//!
//! # References
//! - Intel High Definition Audio Specification, Revision 1.0a
//! - Intel High Definition Audio Link Interface Specification
//!
//! # Features
//! - **CORB/RIRB command interface**: Standard codec communication via DMA rings
//! - **Immediate command fallback**: Alternative path when CORB/RIRB times out
//! - **Codec auto-discovery**: Enumerates and initializes all connected codecs
//! - **Stream management**: Buffer Descriptor List-based scatter-gather DMA
//! - **Format support**: 48 kHz, 16-bit, stereo PCM (expandable)

pub mod error;
pub mod constants;
pub mod types;
pub mod controller;

#[cfg(test)]
mod tests;

// Re-export main types at module root for convenience
pub use error::AudioError;
pub use types::{AudioStats, AudioFormat, BdlEntry, DmaRegion, StreamState};
pub use controller::HdAudioController;
use alloc::boxed::Box;
use spin::Mutex;
use crate::drivers::pci;
use constants::{HDA_CLASS, HDA_SUBCLASS};

/// Global HD Audio controller instance.
static HDA_ONCE: spin::Once<&'static Mutex<HdAudioController>> = spin::Once::new();

/// Initializes the HD Audio subsystem.
pub fn init_hd_audio() -> Result<(), AudioError> {
    // Check if already initialized
    if HDA_ONCE.is_completed() {
        return Ok(());
    }

    // Find HD Audio controller via PCI
    let dev = pci::scan_and_collect()
        .into_iter()
        .find(|d| d.class == HDA_CLASS && d.subclass == HDA_SUBCLASS)
        .ok_or(AudioError::NoControllerFound)?;

    // Create and initialize controller
    let controller = HdAudioController::new(&dev)?;

    // Wrap in Mutex and leak to get 'static lifetime
    let boxed = Box::leak(Box::new(Mutex::new(controller)));

    // Store in global instance
    HDA_ONCE.call_once(|| boxed);

    crate::log::logger::log_critical("HD Audio subsystem initialized");
    Ok(())
}

#[inline]
pub fn get_controller() -> Option<spin::MutexGuard<'static, HdAudioController>> {
    HDA_ONCE.get().map(|m| m.lock())
}

#[inline]
pub fn is_initialized() -> bool {
    HDA_ONCE.is_completed()
}
