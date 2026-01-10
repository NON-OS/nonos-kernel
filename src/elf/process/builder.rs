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

use alloc::string::String;
use x86_64::VirtAddr;

use super::image::{ProcessConfig, ProcessImage};
use crate::elf::auxv::AuxvBuilder;
use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::loader::{ElfImage, ElfLoader};
use crate::elf::stack::{setup_user_stack, StackConfig};
use crate::elf::types::ProgramHeader;

pub const DEFAULT_USER_STACK_TOP: u64 = 0x7FFF_FFFF_F000;

pub struct ProcessBuilder<'a> {
    loader: &'a mut ElfLoader,
    config: ProcessConfig,
    stack_top: VirtAddr,
}

impl<'a> ProcessBuilder<'a> {
    pub fn new(loader: &'a mut ElfLoader, name: String) -> Self {
        Self {
            loader,
            config: ProcessConfig::new(name),
            stack_top: VirtAddr::new(DEFAULT_USER_STACK_TOP),
        }
    }

    pub fn with_config(mut self, config: ProcessConfig) -> Self {
        self.config = config;
        self
    }

    pub fn stack_top(mut self, addr: VirtAddr) -> Self {
        self.stack_top = addr;
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.config.args = args.into_iter().collect();
        self
    }

    pub fn env(mut self, env: impl IntoIterator<Item = String>) -> Self {
        self.config.env = env.into_iter().collect();
        self
    }

    pub fn stack_size(mut self, size: usize) -> Self {
        self.config.stack_size = size;
        self
    }

    pub fn credentials(mut self, uid: u32, gid: u32) -> Self {
        self.config.uid = uid;
        self.config.gid = gid;
        self
    }

    pub fn build(self, elf_data: &[u8]) -> ElfResult<ProcessImage> {
        let executable = self.loader.load_executable(elf_data)?;

        let interpreter = if let Some(ref interp_path) = executable.interpreter {
            Some(self.load_interpreter(interp_path)?)
        } else {
            None
        };

        let phdr_addr = self.find_phdr_addr(&executable, elf_data)?;
        let phnum = self.get_phnum(elf_data)?;

        let auxv = AuxvBuilder::from_elf_image(&executable, phdr_addr, phnum)
            .set_uid(self.config.uid as u64)
            .set_euid(self.config.uid as u64)
            .set_gid(self.config.gid as u64)
            .set_egid(self.config.gid as u64)
            .build();

        let stack_config = StackConfig::new()
            .with_args(self.config.args)
            .with_env(self.config.env)
            .with_auxv(auxv)
            .with_stack_size(self.config.stack_size);

        let stack = setup_user_stack(self.stack_top, self.config.stack_size, &stack_config)?;

        let mut process = ProcessImage::new(executable, interpreter, stack);

        if let Some(ref tls_info) = process.executable.tls_info {
            process.set_tls(*tls_info);
        }

        process.set_ready();

        Ok(process)
    }

    fn load_interpreter(&self, _path: &str) -> ElfResult<ElfImage> {
        Err(ElfError::InterpreterNotFound)
    }

    fn find_phdr_addr(&self, image: &ElfImage, _elf_data: &[u8]) -> ElfResult<VirtAddr> {
        Ok(image.base_addr + 64)
    }

    fn get_phnum(&self, elf_data: &[u8]) -> ElfResult<u16> {
        if elf_data.len() < 58 {
            return Err(ElfError::FileTooSmall);
        }
        Ok(u16::from_le_bytes([elf_data[56], elf_data[57]]))
    }
}

pub fn create_process(
    loader: &mut ElfLoader,
    name: String,
    elf_data: &[u8],
) -> ElfResult<ProcessImage> {
    ProcessBuilder::new(loader, name).build(elf_data)
}

pub fn create_process_with_args(
    loader: &mut ElfLoader,
    name: String,
    elf_data: &[u8],
    args: impl IntoIterator<Item = String>,
    env: impl IntoIterator<Item = String>,
) -> ElfResult<ProcessImage> {
    ProcessBuilder::new(loader, name)
        .args(args)
        .env(env)
        .build(elf_data)
}
