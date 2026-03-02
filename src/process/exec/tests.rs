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

use super::*;
use alloc::vec;
use alloc::vec::Vec;

// For testing, we simulate a non-zero entry by providing bytes that parser accepts.
fn fake_exe_with_entry(entry: u64) -> Vec<u8> {
    let mut v = vec![0u8; 16];
    v[..8].copy_from_slice(&entry.to_le_bytes());
    v
}

#[test]
fn create_execute_terminate_flow() {
    let exe = fake_exe_with_entry(0x401000);
    let pid = create_nonos_process(NonosExecCreate { executable_data: exe }).expect("create");
    let ex = get_nonos_executor().get(pid).expect("ctx");
    assert_eq!(ex.state, NonosExecState::Ready);
    assert_eq!(ex.entry_point, 0x401000);

    execute_nonos_process(pid).expect("run");
    let ex = get_nonos_executor().get(pid).unwrap();
    assert_eq!(ex.state, NonosExecState::Running);

    suspend_nonos_process(pid).expect("suspend");
    let ex = get_nonos_executor().get(pid).unwrap();
    assert_eq!(ex.state, NonosExecState::Suspended);

    terminate_nonos_process(pid).expect("term");
    let ex = get_nonos_executor().get(pid).unwrap();
    assert_eq!(ex.state, NonosExecState::Terminated);

    let st = nonos_executor_stats();
    assert!(st.total_created >= 1);
    assert!(st.total_terminated >= 1);
    assert!(st.active_processes <= st.total_created as usize);
}

#[test]
fn invalid_executable_rejected() {
    // Empty buffer
    assert!(create_nonos_process(NonosExecCreate { executable_data: Vec::new() }).is_err());
    // Parser returns entry=0 -> ENOEXEC
    let bad = fake_exe_with_entry(0);
    assert_eq!(
        create_nonos_process(NonosExecCreate { executable_data: bad }).unwrap_err(),
        "ENOEXEC"
    );
}

#[test]
fn unknown_pid_errors() {
    assert_eq!(execute_nonos_process(0xDEAD).unwrap_err(), "ESRCH");
    assert_eq!(suspend_nonos_process(0xDEAD).unwrap_err(), "ESRCH");
    assert_eq!(terminate_nonos_process(0xDEAD).unwrap_err(), "ESRCH");
}
