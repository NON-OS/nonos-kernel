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

use super::driver::TtyStruct;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;

pub const N_TTY: u32 = 0;
pub const N_SLIP: u32 = 1;
pub const N_PPP: u32 = 3;

static LDISCS: Mutex<BTreeMap<u32, Arc<dyn LineDiscipline>>> = Mutex::new(BTreeMap::new());

pub trait LineDiscipline: Send + Sync {
    fn open(&self, tty: &mut TtyStruct) -> Result<(), i32>;
    fn close(&self, tty: &mut TtyStruct) -> Result<(), i32>;
    fn read(&self, tty: &mut TtyStruct, buf: &mut [u8]) -> Result<usize, i32>;
    fn write(&self, tty: &mut TtyStruct, buf: &[u8]) -> Result<usize, i32>;
    fn receive_buf(&self, tty: &mut TtyStruct, buf: &[u8], flags: &[u8]);
    fn write_wakeup(&self, tty: &TtyStruct);
    fn ioctl(&self, tty: &mut TtyStruct, cmd: u32, arg: u64) -> Result<i64, i32>;
    fn poll(&self, tty: &TtyStruct) -> u32;
    fn flush_buffer(&self, tty: &mut TtyStruct);
}

pub fn register_ldisc(num: u32, ldisc: Arc<dyn LineDiscipline>) -> Result<(), i32> {
    let mut ldiscs = LDISCS.lock();
    if ldiscs.contains_key(&num) {
        return Err(-16);
    }
    ldiscs.insert(num, ldisc);
    Ok(())
}

pub fn unregister_ldisc(num: u32) {
    LDISCS.lock().remove(&num);
}

pub fn get_ldisc(num: u32) -> Option<Arc<dyn LineDiscipline>> {
    LDISCS.lock().get(&num).cloned()
}

pub fn set_ldisc(tty: &mut TtyStruct, num: u32) -> Result<(), i32> {
    let new_ldisc = get_ldisc(num).ok_or(-22)?;
    let old_ldisc = tty.ldisc.clone();
    old_ldisc.close(tty)?;
    tty.ldisc = new_ldisc;
    let ldisc = tty.ldisc.clone();
    ldisc.open(tty)
}

pub fn init_ldiscs() {
    let n_tty = Arc::new(super::n_tty::NTtyLdisc::new());
    let _ = register_ldisc(N_TTY, n_tty);
}
