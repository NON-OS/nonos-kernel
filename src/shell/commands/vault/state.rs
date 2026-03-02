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

use core::sync::atomic::{AtomicBool, Ordering};

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_RED, COLOR_TEXT_DIM};

pub(super) static VAULT_SEALED: AtomicBool = AtomicBool::new(true);
pub(super) static VAULT_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(super) fn is_sealed() -> bool {
    VAULT_SEALED.load(Ordering::SeqCst)
}

pub(super) fn is_initialized() -> bool {
    VAULT_INITIALIZED.load(Ordering::SeqCst)
}

pub(super) fn set_sealed(sealed: bool) {
    VAULT_SEALED.store(sealed, Ordering::SeqCst);
}

pub(super) fn set_initialized(initialized: bool) {
    VAULT_INITIALIZED.store(initialized, Ordering::SeqCst);
}

pub(super) fn check_vault_unsealed() -> bool {
    if !is_initialized() {
        print_line(b"Vault not initialized", COLOR_RED);
        print_line(b"Run: vault-unseal <passphrase>", COLOR_TEXT_DIM);
        return false;
    }

    if is_sealed() {
        print_line(b"Vault is sealed", COLOR_RED);
        print_line(b"Run: vault-unseal <passphrase>", COLOR_TEXT_DIM);
        return false;
    }

    true
}
