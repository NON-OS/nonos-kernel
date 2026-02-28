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

pub mod constants;
pub mod error;
pub mod state;
mod io;
pub mod init;
pub mod eoi;
pub mod mask;
pub mod ops;

pub use constants::{MAX_IRQ, SPURIOUS_IRQ_MASTER, SPURIOUS_IRQ_SLAVE, CASCADE_IRQ};
pub use error::{PicError, PicResult};
pub use state::{is_initialized, is_disabled};
pub use init::{init, init_default, disable_hard};
pub use eoi::{eoi, specific_eoi, handle_spurious_master, handle_spurious_slave};
pub use mask::{mask, unmask, mask_all, get_masks, set_masks};
pub use ops::{enable_aeoi, disable_aeoi, enable_smm, disable_smm, read_irr, read_isr, dump, status, restore_saved_masks, PicStatus};
