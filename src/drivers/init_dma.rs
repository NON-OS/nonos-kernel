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

pub fn init_dma_subsystem() -> Result<(), &'static str> {
    crate::memory::dma::init_dma_allocator().map_err(|_| "Failed to initialize DMA allocator")?;
    let _ = crate::memory::dma::create_dma_pool(
        4096,
        128,
        crate::memory::dma::DmaConstraints::default(),
    );
    let _ = crate::memory::dma::create_dma_pool(
        2048,
        256,
        crate::memory::dma::DmaConstraints::default(),
    );
    Ok(())
}
