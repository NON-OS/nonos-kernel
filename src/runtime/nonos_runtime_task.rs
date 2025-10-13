/// A cooperative runtime daemon that:
/// Processes IPC,
/// Monitors ZeroState capsules,
/// Runs the supervisor (restart policy),
/// Yields to the scheduler.

#![no_std]

extern crate alloc;

use crate::runtime::nonos_supervisor;
use crate::runtime::nonos_zerostate;
use crate::syscall::capabilities::CapabilityToken;

pub fn run_runtime_daemon(token: &CapabilityToken) -> ! {
    loop {
        crate::ipc::process_message_queue();

        nonos_zerostate::monitor_once();

        nonos_supervisor::run_once(token);

        crate::sched::yield_cpu();
    }
}
