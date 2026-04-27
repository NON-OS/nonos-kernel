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

use alloc::format;
use alloc::string::String;

pub fn read_meminfo() -> String {
    let stats = crate::memory::get_memory_stats();
    let total_kb = stats.total_bytes / 1024;
    let free_kb = stats.free_bytes / 1024;
    let available_kb = stats.available_bytes / 1024;
    let buffers_kb = stats.buffers_bytes / 1024;
    let cached_kb = stats.cached_bytes / 1024;
    let swap_total_kb = stats.swap_total / 1024;
    let swap_free_kb = stats.swap_free / 1024;
    let slab_kb = stats.slab_bytes / 1024;
    let sreclaimable_kb = stats.sreclaimable / 1024;
    let sunreclaim_kb = stats.sunreclaim / 1024;
    let kernel_stack_kb = stats.kernel_stack / 1024;
    let page_tables_kb = stats.page_tables / 1024;
    let vmalloc_total_kb = stats.vmalloc_total / 1024;
    let vmalloc_used_kb = stats.vmalloc_used / 1024;
    format!(
        "MemTotal:       {:>8} kB\nMemFree:        {:>8} kB\nMemAvailable:   {:>8} kB\nBuffers:        {:>8} kB\nCached:         {:>8} kB\nSwapCached:     {:>8} kB\nActive:         {:>8} kB\nInactive:       {:>8} kB\nActive(anon):   {:>8} kB\nInactive(anon): {:>8} kB\nActive(file):   {:>8} kB\nInactive(file): {:>8} kB\nUnevictable:    {:>8} kB\nMlocked:        {:>8} kB\nSwapTotal:      {:>8} kB\nSwapFree:       {:>8} kB\nDirty:          {:>8} kB\nWriteback:      {:>8} kB\nAnonPages:      {:>8} kB\nMapped:         {:>8} kB\nShmem:          {:>8} kB\nKReclaimable:   {:>8} kB\nSlab:           {:>8} kB\nSReclaimable:   {:>8} kB\nSUnreclaim:     {:>8} kB\nKernelStack:    {:>8} kB\nPageTables:     {:>8} kB\nNFS_Unstable:   {:>8} kB\nBounce:         {:>8} kB\nWritebackTmp:   {:>8} kB\nCommitLimit:    {:>8} kB\nCommitted_AS:   {:>8} kB\nVmallocTotal:   {:>8} kB\nVmallocUsed:    {:>8} kB\nVmallocChunk:   {:>8} kB\nPercpu:         {:>8} kB\nHardwareCorrupted: {:>5} kB\nAnonHugePages:  {:>8} kB\nShmemHugePages: {:>8} kB\nShmemPmdMapped: {:>8} kB\nFileHugePages:  {:>8} kB\nFilePmdMapped:  {:>8} kB\nHugePages_Total:{:>8}\nHugePages_Free: {:>8}\nHugePages_Rsvd: {:>8}\nHugePages_Surp: {:>8}\nHugepagesize:   {:>8} kB\nHugetlb:        {:>8} kB\nDirectMap4k:    {:>8} kB\nDirectMap2M:    {:>8} kB\nDirectMap1G:    {:>8} kB\n",
        total_kb, free_kb, available_kb, buffers_kb, cached_kb, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        swap_total_kb, swap_free_kb, 0, 0, 0, 0, 0, sreclaimable_kb, slab_kb, sreclaimable_kb, sunreclaim_kb,
        kernel_stack_kb, page_tables_kb, 0, 0, 0, total_kb, 0, vmalloc_total_kb, vmalloc_used_kb, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 2048, 0, 0, 0, 0
    )
}
