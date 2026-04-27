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
pub mod eoi;
pub mod error;
pub mod init;
mod io;
pub mod mask;
mod mask_bulk;
mod mask_ops;
pub mod ops;
mod ops_aeoi;
mod ops_isr;
mod ops_reinit;
mod ops_smm;
mod ops_status;
pub mod state;

pub use constants::{CASCADE_IRQ, MAX_IRQ, SPURIOUS_IRQ_MASTER, SPURIOUS_IRQ_SLAVE};
pub use eoi::{eoi, handle_spurious_master, handle_spurious_slave, specific_eoi};
pub use error::{PicError, PicResult};
pub use init::{disable_hard, init, init_default};
pub use mask::{get_masks, mask, mask_all, set_masks, unmask};
pub use ops::{
    disable_aeoi, disable_smm, dump, enable_aeoi, enable_smm, read_irr, read_isr,
    restore_saved_masks, status, PicStatus,
};
pub use state::{is_disabled, is_initialized};
