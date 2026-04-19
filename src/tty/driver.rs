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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

static DRIVERS: Mutex<BTreeMap<String, Arc<TtyDriver>>> = Mutex::new(BTreeMap::new());

pub struct TtyDriver {
    pub name: String,
    pub major: u32,
    pub minor_start: u32,
    pub num: u32,
    pub driver_type: TtyDriverType,
    pub subtype: TtyDriverSubtype,
    pub flags: u32,
    pub ops: Arc<dyn TtyDriverOps>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyDriverType { System, Console, Serial, Pty }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyDriverSubtype { PtyMaster, PtySlave, System, Console }

pub trait TtyDriverOps: Send + Sync {
    fn open(&self, tty: &TtyStruct) -> Result<(), i32>;
    fn close(&self, tty: &TtyStruct) -> Result<(), i32>;
    fn write(&self, tty: &TtyStruct, buf: &[u8]) -> Result<usize, i32>;
    fn write_room(&self, tty: &TtyStruct) -> usize;
    fn chars_in_buffer(&self, tty: &TtyStruct) -> usize;
    fn set_termios(&self, tty: &TtyStruct, old: &super::termios::Termios) -> Result<(), i32>;
    fn throttle(&self, tty: &TtyStruct);
    fn unthrottle(&self, tty: &TtyStruct);
}

pub struct TtyStruct {
    pub index: u32,
    pub driver: Arc<TtyDriver>,
    pub termios: super::termios::Termios,
    pub winsize: super::termios::Winsize,
    pub ldisc: Arc<dyn super::ldisc::LineDiscipline>,
    pub pgrp: i32,
    pub session: i32,
}

pub fn register_driver(driver: Arc<TtyDriver>) -> Result<(), i32> {
    let mut drivers = DRIVERS.lock();
    if drivers.contains_key(&driver.name) { return Err(-16); }
    drivers.insert(driver.name.clone(), driver);
    Ok(())
}

pub fn unregister_driver(name: &str) -> Result<(), i32> {
    DRIVERS.lock().remove(name).ok_or(-2)?;
    Ok(())
}

pub fn get_driver(name: &str) -> Option<Arc<TtyDriver>> {
    DRIVERS.lock().get(name).cloned()
}

pub fn get_driver_by_major(major: u32) -> Option<Arc<TtyDriver>> {
    DRIVERS.lock().values().find(|d| d.major == major).cloned()
}
