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

extern crate alloc;
use super::store::VaultSealStore;
use super::types::SealPolicy;
use crate::arch::x86_64::uefi::{set_variable as uefi_set_variable, Guid, VariableAttributes};
use crate::fs::nonos_filesystem::NonosFilesystem;
use crate::vault::nonos_vault::{VaultAuditEvent, NONOS_VAULT};
use alloc::format;

impl VaultSealStore {
    pub fn secure_erase_sealed(&self, backend: Option<SealPolicy>) {
        let mut sealed = self.sealed.lock();
        for entry in sealed.iter_mut() {
            for b in entry.sealed_data.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            entry.sealed_data.clear();
        }
        sealed.clear();
        if let Some(ref policy) = backend {
            match policy {
                SealPolicy::UEFI => {
                    let _ = uefi_set_variable(
                        "NONOS_VAULT_SECRET",
                        &Guid::GLOBAL_VARIABLE,
                        VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS,
                        &[],
                    );
                }
                SealPolicy::Disk => {
                    let _ = NonosFilesystem::new().delete_file("nonos_vault.sealed");
                }
                SealPolicy::Custom(_) | SealPolicy::RAMOnly => {}
            }
        }
        let audit = VaultAuditEvent {
            timestamp: crate::time::timestamp_millis(),
            event: "secure_erase_sealed".into(),
            context: backend.map(|b| format!("{:?}", b)),
            status: Some("success".into()),
        };
        NONOS_VAULT.audit_log().lock().push(audit);
    }
}
