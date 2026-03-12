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

/*
 * Kernel loading entry point.
 *
 * Handles capsule validation and dispatches to ET_EXEC or ET_DYN loaders.
 */

use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::image::KernelImage;
use crate::log::logger::{log_error, log_info};
use crate::verify::load_validated_capsule;
use uefi::prelude::*;

use super::dynamic::load_dyn_kernel;
use super::exec::load_exec_kernel;
use super::validate::validate_elf;

pub fn load_kernel(
    system_table: &mut SystemTable<Boot>,
    capsule_bytes: &[u8],
) -> LoaderResult<KernelImage> {
    log_info("loader", "Starting kernel load operation");

    let payload: &[u8] = match load_validated_capsule(capsule_bytes) {
        Some(validated) => {
            log_info("loader", "Capsule validated successfully");
            return load_kernel_internal(system_table, &validated);
        }
        None => {
            log_info("loader", "No capsule format, loading as raw ELF");
            capsule_bytes
        }
    };

    load_kernel_internal(system_table, payload)
}

fn load_kernel_internal(
    system_table: &mut SystemTable<Boot>,
    payload: &[u8],
) -> LoaderResult<KernelImage> {
    let validation = validate_elf(payload)?;
    let bs = system_table.boot_services();

    if validation.is_exec {
        load_exec_kernel(bs, payload, &validation)
    } else if validation.is_dyn {
        load_dyn_kernel(bs, payload, &validation)
    } else {
        log_error("loader", "ELF is neither ET_EXEC nor ET_DYN");
        Err(LoaderError::UnsupportedElf("unsupported ELF type"))
    }
}
