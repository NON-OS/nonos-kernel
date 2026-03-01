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


pub mod io;
pub mod gdt;
pub mod idt;
pub mod serial;
pub mod clock;
pub mod apic;
pub mod timer;
pub mod settings;
pub mod process;


pub use io::{outb, inb, outw, inw, outl, inl, io_wait};

pub use gdt::setup as gdt_setup;
pub use gdt::enable_iopl;

pub use idt::setup as idt_setup;

pub use serial::init as serial_init;
pub use serial::{print, print_str, println, print_hex, print_dec};

pub use clock::init as clock_init;
pub use clock::{unix_ms, Time, get_time, format_time, format_time_full};

pub use apic::init as apic_init;
pub use apic::is_init as apic_is_init;
pub use apic::{
    init_local_apic, eoi, setup_timer, stop_timer,
    init_ioapic, ioapic_set_irq, enable_irq, disable_irq,
    irq_to_vector, setup_keyboard_irq, setup_mouse_irq,
    TIMER_VECTOR, IRQ_TIMER, IRQ_KEYBOARD, IRQ_CASCADE, IRQ_COM2, IRQ_COM1,
    IRQ_LPT2, IRQ_FLOPPY, IRQ_LPT1, IRQ_RTC, IRQ_FREE1, IRQ_FREE2, IRQ_FREE3,
    IRQ_MOUSE, IRQ_COPROCESSOR, IRQ_PRIMARY_ATA, IRQ_SECONDARY_ATA,
    VECTOR_TIMER, VECTOR_KEYBOARD, VECTOR_MOUSE, VECTOR_COM1,
};

pub use timer::init as timer_init;
pub use timer::is_init as timer_is_init;
pub use timer::{
    rdtsc, tsc_frequency, ticks_to_ns, ticks_to_us, ticks_to_ms,
    us_to_ticks, ms_to_ticks, uptime_ms, uptime_us, uptime_seconds,
    unix_timestamp_ms, unix_timestamp, delay_us, delay_ms, short_delay,
    Stopwatch, TimerCallback, register_callback, unregister_callback,
    process_callbacks, stats, format_uptime, init_default,
};

pub use settings::init as settings_init;
pub use settings::{
    Settings, get, get_mut, mark_modified, needs_save, brightness, set_brightness,
    mouse_sensitivity, set_mouse_sensitivity, anonymous_mode, set_anonymous_mode,
    anyone_enabled, set_anyone_enabled, theme, set_theme, auto_wipe, set_auto_wipe,
    SETTINGS_FILENAME, serialize, deserialize, save_to_disk, load_from_disk,
    reset_to_defaults, init_hostname, get_hostname, set_hostname, get_domainname,
    set_domainname,
};

pub use process::init as process_init;
pub use process::is_init as process_is_init;
pub use process::{
    MAX_TASKS, TASK_STACK_SIZE, TaskState, CpuContext, Task, state_str,
    spawn, exit, yield_now, sleep_ms, schedule, current_id, task_count,
    get_task_info, for_each_task,
};
