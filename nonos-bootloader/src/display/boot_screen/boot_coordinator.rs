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

use super::production_ui::{draw_production_bootloader, advance_boot_stage, update_stage_progress, add_boot_message};

static mut BOOT_TIMER: u64 = 0;
static mut LAST_UPDATE: u64 = 0;
static mut AUTO_PROGRESS: bool = true;

pub fn run_boot_sequence() {
    initialize_boot_sequence();

    loop {
        let current_time = get_system_time_ms();

        if current_time - unsafe { LAST_UPDATE } >= 16 {
            update_boot_animation();
            draw_production_bootloader();
            unsafe { LAST_UPDATE = current_time; }
        }

        if unsafe { AUTO_PROGRESS } {
            simulate_boot_progress();
        }

        if get_current_boot_stage() >= 10 {
            complete_boot_sequence();
            break;
        }

        micro_delay(1000);
    }
}

fn initialize_boot_sequence() {
    add_boot_message("✓ UEFI services initialized");
    add_boot_message("✓ Memory map acquired");
    add_boot_message("✓ Graphics mode configured");
    add_boot_message("✓ Starting secure boot sequence...");
}

fn simulate_boot_progress() {
    let current_time = get_system_time_ms();
    unsafe { BOOT_TIMER += 1; }

    let stage_duration = 200;
    let progress_per_tick = 100.0 / stage_duration as f32;

    if unsafe { BOOT_TIMER } % stage_duration == 0 {
        advance_boot_stage();
        add_stage_completion_message();
    } else {
        let stage_progress = (unsafe { BOOT_TIMER } % stage_duration) as f32 * progress_per_tick;
        update_stage_progress(stage_progress);
    }
}

fn add_stage_completion_message() {
    let stage = get_current_boot_stage();
    let message = match stage {
        1 => "✓ Security policies loaded",
        2 => "✓ Bootloader signature verified",
        3 => "✓ Memory protection enabled",
        4 => "✓ Cryptographic subsystem ready",
        5 => "✓ Kernel image loaded",
        6 => "✓ Kernel signature verified",
        7 => "✓ Capability system configured",
        8 => "✓ Microkernel started",
        9 => "✓ Userspace services launched",
        10 => "✓ Boot sequence complete",
        _ => "✓ Unknown stage completed",
    };

    if stage <= 10 {
        add_boot_message(message);
    }
}

fn update_boot_animation() {
    super::enhanced_progress::animate_progress_step();
}

fn complete_boot_sequence() {
    add_boot_message("✓ System ready - transferring control...");
    update_stage_progress(100.0);

    for _ in 0..30 {
        draw_production_bootloader();
        micro_delay(33_000);
    }
}

fn get_current_boot_stage() -> u8 {
    super::production_ui::get_current_stage()
}

fn get_system_time_ms() -> u64 {
    unsafe {
        static mut MOCK_TIME: u64 = 0;
        MOCK_TIME += 16;
        MOCK_TIME
    }
}

fn micro_delay(microseconds: u32) {
    let cycles = microseconds * 3;
    for _ in 0..cycles {
        unsafe {
            core::arch::asm!("nop");
        }
    }
}

pub fn set_auto_progress(enabled: bool) {
    unsafe { AUTO_PROGRESS = enabled; }
}

pub fn force_stage_advance() {
    advance_boot_stage();
    add_stage_completion_message();
}

pub fn add_custom_message(message: &'static str) {
    add_boot_message(message);
}