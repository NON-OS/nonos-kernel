#![no_std]

extern crate alloc;

use alloc::string::String;
use super::nonos_core as core;

#[inline]
pub fn spawn(name: &str) -> Result<core::Pid, &'static str> {
    core::create_process(name, core::ProcessState::Ready, core::Priority::Normal)
}

#[inline]
pub fn kill(pid: core::Pid, code: i32) -> Result<(), &'static str> {
    let Some(p) = core::get_process_table().find_by_pid(pid) else { return Err("not found"); };
    p.terminate(code);
    Ok(())
}

#[inline]
pub fn set_name(pid: core::Pid, name: &str) -> Result<(), &'static str> {
    if name.is_empty() { return Err("empty name"); }
    let Some(p) = core::get_process_table().find_by_pid(pid) else { return Err("not found"); };
    *p.name.lock() = String::from(name);
    Ok(())
}
