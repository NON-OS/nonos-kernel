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

use spin::Once;

use crate::elf::errors::ElfError;

use super::core::ElfLoader;
use super::image::ElfImage;

static ELF_LOADER: Once<spin::Mutex<ElfLoader>> = Once::new();

pub fn init_elf_loader() {
    ELF_LOADER.call_once(|| spin::Mutex::new(ElfLoader::new()));
}

pub fn is_initialized() -> bool {
    ELF_LOADER.is_completed()
}

pub fn get_elf_loader() -> Option<&'static spin::Mutex<ElfLoader>> {
    ELF_LOADER.get()
}

pub fn load_elf_executable(elf_data: &[u8]) -> Result<ElfImage, ElfError> {
    let loader = get_elf_loader().ok_or(ElfError::NotInitialized)?;
    let mut guard = loader.lock();
    guard.load_executable(elf_data)
}
