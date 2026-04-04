use crate::process::acct_record::*;
use crate::process::accounting::ProcessRecord;

#[test]
fn acct_flag_constants() {
    assert_eq!(AFORK, 0x01);
    assert_eq!(ASU, 0x02);
    assert_eq!(ACORE, 0x08);
    assert_eq!(AXSIG, 0x10);
}

#[test]
fn acct_flags_no_overlap() {
    assert_eq!(AFORK & ASU, 0);
    assert_eq!(AFORK & ACORE, 0);
    assert_eq!(AFORK & AXSIG, 0);
    assert_eq!(ASU & ACORE, 0);
    assert_eq!(ASU & AXSIG, 0);
    assert_eq!(ACORE & AXSIG, 0);
}

#[test]
fn acct_record_default() {
    let rec = AcctRecord::default();
    assert_eq!(rec.ac_flag, 0);
    assert_eq!(rec.ac_version, 0);
    assert_eq!(rec.ac_tty, 0);
    assert_eq!(rec.ac_exitcode, 0);
    assert_eq!(rec.ac_uid, 0);
    assert_eq!(rec.ac_gid, 0);
    assert_eq!(rec.ac_pid, 0);
    assert_eq!(rec.ac_ppid, 0);
    assert_eq!(rec.ac_btime, 0);
    assert_eq!(rec.ac_etime, 0.0);
    assert_eq!(rec.ac_utime, 0.0);
    assert_eq!(rec.ac_stime, 0.0);
    assert_eq!(rec.ac_mem, 0.0);
    assert_eq!(rec.ac_io, 0.0);
    assert_eq!(rec.ac_rw, 0.0);
    assert_eq!(rec.ac_minflt, 0.0);
    assert_eq!(rec.ac_majflt, 0.0);
    assert_eq!(rec.ac_swaps, 0.0);
    assert_eq!(rec.ac_comm, [0u8; 16]);
}

#[test]
fn acct_record_with_values() {
    let rec = AcctRecord {
        ac_flag: AFORK | ASU,
        ac_version: 3,
        ac_tty: 1,
        ac_exitcode: 0,
        ac_uid: 1000,
        ac_gid: 1000,
        ac_pid: 12345,
        ac_ppid: 1,
        ac_btime: 1000000,
        ac_etime: 5.5,
        ac_utime: 2.0,
        ac_stime: 1.5,
        ac_mem: 1024.0,
        ac_io: 512.0,
        ac_rw: 256.0,
        ac_minflt: 100.0,
        ac_majflt: 10.0,
        ac_swaps: 0.0,
        ac_comm: [0u8; 16],
    };
    assert_eq!(rec.ac_flag, AFORK | ASU);
    assert_eq!(rec.ac_pid, 12345);
    assert_eq!(rec.ac_ppid, 1);
    assert_eq!(rec.ac_uid, 1000);
}

#[test]
fn acct_record_clone() {
    let rec1 = AcctRecord {
        ac_pid: 999,
        ac_uid: 500,
        ..Default::default()
    };
    let rec2 = rec1;
    assert_eq!(rec1.ac_pid, rec2.ac_pid);
    assert_eq!(rec1.ac_uid, rec2.ac_uid);
}

#[test]
fn acct_record_comm_field() {
    let mut rec = AcctRecord::default();
    let name = b"test_process";
    rec.ac_comm[..name.len()].copy_from_slice(name);
    assert_eq!(&rec.ac_comm[..12], b"test_process");
}

#[test]
fn acct_record_flag_combinations() {
    let rec = AcctRecord {
        ac_flag: AFORK | ACORE | AXSIG,
        ..Default::default()
    };
    assert_ne!(rec.ac_flag & AFORK, 0);
    assert_ne!(rec.ac_flag & ACORE, 0);
    assert_ne!(rec.ac_flag & AXSIG, 0);
    assert_eq!(rec.ac_flag & ASU, 0);
}

#[test]
fn process_record_new() {
    let rec = ProcessRecord::new(123, 1, "test_app");
    assert_eq!(rec.pid, 123);
    assert_eq!(rec.ppid, 1);
    assert_eq!(rec.name, "test_app");
    assert_eq!(rec.exit_code, 0);
    assert_eq!(rec.start_time_ms, 0);
    assert_eq!(rec.end_time_ms, 0);
    assert_eq!(rec.elapsed_ms, 0);
    assert_eq!(rec.peak_memory_kb, 0);
    assert_eq!(rec.capabilities, 0);
    assert!(!rec.signaled);
    assert_eq!(rec.clone_flags, 0);
}

#[test]
fn process_record_clone() {
    let rec1 = ProcessRecord::new(456, 100, "app");
    let rec2 = rec1.clone();
    assert_eq!(rec1.pid, rec2.pid);
    assert_eq!(rec1.ppid, rec2.ppid);
    assert_eq!(rec1.name, rec2.name);
}

#[test]
fn process_record_format_basic() {
    let rec = ProcessRecord {
        pid: 100,
        ppid: 1,
        name: alloc::string::String::from("myapp"),
        exit_code: 0,
        start_time_ms: 1000,
        end_time_ms: 2000,
        elapsed_ms: 1000,
        peak_memory_kb: 512,
        capabilities: 0x1234,
        signaled: false,
        clone_flags: 0,
    };
    let formatted = rec.format();
    assert!(formatted.contains("[100]"));
    assert!(formatted.contains("myapp"));
    assert!(formatted.contains("ppid=1"));
    assert!(formatted.contains("exit=0"));
    assert!(formatted.contains("elapsed=1000ms"));
    assert!(formatted.contains("mem=512KB"));
}

#[test]
fn process_record_format_signaled() {
    let rec = ProcessRecord {
        pid: 200,
        ppid: 1,
        name: alloc::string::String::from("signaled_app"),
        exit_code: 9,
        start_time_ms: 0,
        end_time_ms: 100,
        elapsed_ms: 100,
        peak_memory_kb: 256,
        capabilities: 0,
        signaled: true,
        clone_flags: 0,
    };
    let formatted = rec.format();
    assert!(formatted.contains("[SIGNALED]"));
}

#[test]
fn process_record_format_not_signaled() {
    let rec = ProcessRecord {
        pid: 300,
        ppid: 1,
        name: alloc::string::String::from("normal_app"),
        exit_code: 0,
        start_time_ms: 0,
        end_time_ms: 50,
        elapsed_ms: 50,
        peak_memory_kb: 128,
        capabilities: 0,
        signaled: false,
        clone_flags: 0,
    };
    let formatted = rec.format();
    assert!(!formatted.contains("[SIGNALED]"));
}

#[test]
fn process_record_with_capabilities() {
    let rec = ProcessRecord {
        pid: 400,
        ppid: 1,
        name: alloc::string::String::from("cap_app"),
        exit_code: 0,
        start_time_ms: 0,
        end_time_ms: 0,
        elapsed_ms: 0,
        peak_memory_kb: 0,
        capabilities: 0xDEAD_BEEF_CAFE_BABE,
        signaled: false,
        clone_flags: 0,
    };
    let formatted = rec.format();
    assert!(formatted.contains("deadbeefcafebabe") || formatted.contains("DEADBEEFCAFEBABE"));
}

#[test]
fn process_record_with_clone_flags() {
    let rec = ProcessRecord {
        pid: 500,
        ppid: 1,
        name: alloc::string::String::from("clone_app"),
        exit_code: 0,
        start_time_ms: 0,
        end_time_ms: 0,
        elapsed_ms: 0,
        peak_memory_kb: 0,
        capabilities: 0,
        signaled: false,
        clone_flags: 0x100 | 0x200,
    };
    assert_eq!(rec.clone_flags, 0x300);
}
