use crate::process::scheduler::policy_types::*;

#[test]
fn sched_policy_constants() {
    assert_eq!(SCHED_NORMAL, 0);
    assert_eq!(SCHED_FIFO, 1);
    assert_eq!(SCHED_RR, 2);
    assert_eq!(SCHED_BATCH, 3);
    assert_eq!(SCHED_IDLE, 5);
    assert_eq!(SCHED_DEADLINE, 6);
}

#[test]
fn sched_priority_range() {
    assert_eq!(SCHED_PRIORITY_MIN, 1);
    assert_eq!(SCHED_PRIORITY_MAX, 99);
}

#[test]
fn nice_value_range() {
    assert_eq!(NICE_MIN, -20);
    assert_eq!(NICE_MAX, 19);
    assert_eq!(NICE_DEFAULT, 0);
}

#[test]
fn sched_flag_constants() {
    assert_eq!(SCHED_FLAG_RESET_ON_FORK, 0x01);
    assert_eq!(SCHED_FLAG_RECLAIM, 0x02);
    assert_eq!(SCHED_FLAG_DL_OVERRUN, 0x04);
    assert_eq!(SCHED_FLAG_KEEP_POLICY, 0x08);
    assert_eq!(SCHED_FLAG_KEEP_PARAMS, 0x10);
    assert_eq!(SCHED_FLAG_UTIL_CLAMP_MIN, 0x20);
    assert_eq!(SCHED_FLAG_UTIL_CLAMP_MAX, 0x40);
}

#[test]
fn ioprio_class_constants() {
    assert_eq!(IOPRIO_CLASS_NONE, 0);
    assert_eq!(IOPRIO_CLASS_RT, 1);
    assert_eq!(IOPRIO_CLASS_BE, 2);
    assert_eq!(IOPRIO_CLASS_IDLE, 3);
}

#[test]
fn ioprio_who_constants() {
    assert_eq!(IOPRIO_WHO_PROCESS, 1);
    assert_eq!(IOPRIO_WHO_PGRP, 2);
    assert_eq!(IOPRIO_WHO_USER, 3);
}

#[test]
fn timeslice_constants() {
    assert_eq!(DEFAULT_TIMESLICE_MS, 100);
    assert_eq!(FIFO_TIMESLICE_MS, 0);
    assert_eq!(RR_TIMESLICE_MS, 100);
}

#[test]
fn sched_attr_default() {
    let attr = SchedAttr::default();
    assert_eq!(attr.policy, SCHED_NORMAL);
    assert_eq!(attr.rt_priority, 0);
    assert_eq!(attr.nice, NICE_DEFAULT);
    assert_eq!(attr.cpu_affinity, 0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(attr.flags, 0);
    assert_eq!(attr.timeslice, DEFAULT_TIMESLICE_MS);
    assert_eq!(attr.runtime, 0);
    assert_eq!(attr.deadline, 0);
    assert_eq!(attr.period, 0);
}

#[test]
fn sched_attr_is_realtime_fifo() {
    let attr = SchedAttr {
        policy: SCHED_FIFO,
        rt_priority: 50,
        ..Default::default()
    };
    assert!(attr.is_realtime());
}

#[test]
fn sched_attr_is_realtime_rr() {
    let attr = SchedAttr {
        policy: SCHED_RR,
        rt_priority: 50,
        ..Default::default()
    };
    assert!(attr.is_realtime());
}

#[test]
fn sched_attr_is_not_realtime() {
    let normal = SchedAttr { policy: SCHED_NORMAL, ..Default::default() };
    let batch = SchedAttr { policy: SCHED_BATCH, ..Default::default() };
    let idle = SchedAttr { policy: SCHED_IDLE, ..Default::default() };
    let deadline = SchedAttr { policy: SCHED_DEADLINE, ..Default::default() };
    assert!(!normal.is_realtime());
    assert!(!batch.is_realtime());
    assert!(!idle.is_realtime());
    assert!(!deadline.is_realtime());
}

#[test]
fn sched_attr_effective_priority_normal() {
    let attr = SchedAttr {
        policy: SCHED_NORMAL,
        nice: 0,
        ..Default::default()
    };
    assert_eq!(attr.effective_priority(), 20);
}

#[test]
fn sched_attr_effective_priority_normal_with_nice() {
    let attr_nice_max = SchedAttr {
        policy: SCHED_NORMAL,
        nice: NICE_MAX,
        ..Default::default()
    };
    assert_eq!(attr_nice_max.effective_priority(), 20 - NICE_MAX);

    let attr_nice_min = SchedAttr {
        policy: SCHED_NORMAL,
        nice: NICE_MIN,
        ..Default::default()
    };
    assert_eq!(attr_nice_min.effective_priority(), 20 - NICE_MIN);
}

#[test]
fn sched_attr_effective_priority_fifo() {
    let attr = SchedAttr {
        policy: SCHED_FIFO,
        rt_priority: 50,
        ..Default::default()
    };
    assert_eq!(attr.effective_priority(), 150);
}

#[test]
fn sched_attr_effective_priority_rr() {
    let attr = SchedAttr {
        policy: SCHED_RR,
        rt_priority: 99,
        ..Default::default()
    };
    assert_eq!(attr.effective_priority(), 199);
}

#[test]
fn sched_attr_effective_priority_deadline() {
    let attr = SchedAttr {
        policy: SCHED_DEADLINE,
        ..Default::default()
    };
    assert_eq!(attr.effective_priority(), 200);
}

#[test]
fn sched_attr_effective_priority_idle() {
    let attr = SchedAttr {
        policy: SCHED_IDLE,
        ..Default::default()
    };
    assert_eq!(attr.effective_priority(), -1);
}

#[test]
fn sched_attr_effective_priority_batch() {
    let attr = SchedAttr {
        policy: SCHED_BATCH,
        nice: 0,
        ..Default::default()
    };
    assert_eq!(attr.effective_priority(), 19);
}

#[test]
fn sched_attr_can_run_on_cpu() {
    let attr = SchedAttr {
        cpu_affinity: 0b1010,
        ..Default::default()
    };
    assert!(!attr.can_run_on_cpu(0));
    assert!(attr.can_run_on_cpu(1));
    assert!(!attr.can_run_on_cpu(2));
    assert!(attr.can_run_on_cpu(3));
}

#[test]
fn sched_attr_can_run_on_cpu_high_cpu() {
    let attr = SchedAttr {
        cpu_affinity: u64::MAX,
        ..Default::default()
    };
    assert!(!attr.can_run_on_cpu(64));
    assert!(!attr.can_run_on_cpu(100));
}

#[test]
fn sched_attr_get_timeslice_fifo() {
    let attr = SchedAttr {
        policy: SCHED_FIFO,
        timeslice: 999,
        ..Default::default()
    };
    assert_eq!(attr.get_timeslice(), FIFO_TIMESLICE_MS);
}

#[test]
fn sched_attr_get_timeslice_rr() {
    let attr = SchedAttr {
        policy: SCHED_RR,
        timeslice: 999,
        ..Default::default()
    };
    assert_eq!(attr.get_timeslice(), RR_TIMESLICE_MS);
}

#[test]
fn sched_attr_get_timeslice_normal() {
    let attr = SchedAttr {
        policy: SCHED_NORMAL,
        timeslice: 50,
        ..Default::default()
    };
    assert_eq!(attr.get_timeslice(), 50);
}

#[test]
fn sched_attr_clone() {
    let attr1 = SchedAttr {
        policy: SCHED_FIFO,
        rt_priority: 75,
        nice: -10,
        cpu_affinity: 0xFF,
        ioprio: encode_ioprio(IOPRIO_CLASS_RT, 3),
        flags: SCHED_FLAG_RESET_ON_FORK,
        timeslice: 200,
        runtime: 1000,
        deadline: 5000,
        period: 10000,
    };
    let attr2 = attr1.clone();
    assert_eq!(attr1.policy, attr2.policy);
    assert_eq!(attr1.rt_priority, attr2.rt_priority);
    assert_eq!(attr1.nice, attr2.nice);
    assert_eq!(attr1.cpu_affinity, attr2.cpu_affinity);
    assert_eq!(attr1.ioprio, attr2.ioprio);
    assert_eq!(attr1.flags, attr2.flags);
    assert_eq!(attr1.runtime, attr2.runtime);
    assert_eq!(attr1.deadline, attr2.deadline);
    assert_eq!(attr1.period, attr2.period);
}

#[test]
fn encode_decode_ioprio() {
    let encoded = encode_ioprio(IOPRIO_CLASS_BE, 4);
    assert_eq!(decode_ioprio_class(encoded), IOPRIO_CLASS_BE);
    assert_eq!(decode_ioprio_level(encoded), 4);
}

#[test]
fn encode_decode_ioprio_rt() {
    let encoded = encode_ioprio(IOPRIO_CLASS_RT, 0);
    assert_eq!(decode_ioprio_class(encoded), IOPRIO_CLASS_RT);
    assert_eq!(decode_ioprio_level(encoded), 0);
}

#[test]
fn encode_decode_ioprio_idle() {
    let encoded = encode_ioprio(IOPRIO_CLASS_IDLE, 0);
    assert_eq!(decode_ioprio_class(encoded), IOPRIO_CLASS_IDLE);
    assert_eq!(decode_ioprio_level(encoded), 0);
}

#[test]
fn encode_ioprio_max_level() {
    let encoded = encode_ioprio(IOPRIO_CLASS_BE, 7);
    assert_eq!(decode_ioprio_class(encoded), IOPRIO_CLASS_BE);
    assert_eq!(decode_ioprio_level(encoded), 7);
}

#[test]
fn sched_param_default() {
    let param = SchedParam::default();
    assert_eq!(param.sched_priority, 0);
}

#[test]
fn sched_param_with_priority() {
    let param = SchedParam { sched_priority: 50 };
    assert_eq!(param.sched_priority, 50);
}

#[test]
fn linux_sched_attr_default() {
    let attr = LinuxSchedAttr::default();
    assert_eq!(attr.size, core::mem::size_of::<LinuxSchedAttr>() as u32);
    assert_eq!(attr.sched_policy, SCHED_NORMAL as u32);
    assert_eq!(attr.sched_flags, 0);
    assert_eq!(attr.sched_nice, 0);
    assert_eq!(attr.sched_priority, 0);
    assert_eq!(attr.sched_runtime, 0);
    assert_eq!(attr.sched_deadline, 0);
    assert_eq!(attr.sched_period, 0);
    assert_eq!(attr.sched_util_min, 0);
    assert_eq!(attr.sched_util_max, 1024);
}

#[test]
fn linux_sched_attr_clone() {
    let attr1 = LinuxSchedAttr {
        size: 56,
        sched_policy: SCHED_DEADLINE as u32,
        sched_flags: 0x07,
        sched_nice: 0,
        sched_priority: 0,
        sched_runtime: 10_000,
        sched_deadline: 30_000,
        sched_period: 100_000,
        sched_util_min: 100,
        sched_util_max: 800,
    };
    let attr2 = attr1;
    assert_eq!(attr1.sched_policy, attr2.sched_policy);
    assert_eq!(attr1.sched_runtime, attr2.sched_runtime);
    assert_eq!(attr1.sched_deadline, attr2.sched_deadline);
    assert_eq!(attr1.sched_period, attr2.sched_period);
}

#[test]
fn sched_policy_stats_default() {
    let stats = SchedPolicyStats::default();
    assert_eq!(stats.total_processes, 0);
    assert_eq!(stats.normal_count, 0);
    assert_eq!(stats.fifo_count, 0);
    assert_eq!(stats.rr_count, 0);
    assert_eq!(stats.batch_count, 0);
    assert_eq!(stats.idle_count, 0);
    assert_eq!(stats.deadline_count, 0);
    assert_eq!(stats.policy_changes, 0);
    assert_eq!(stats.affinity_changes, 0);
    assert_eq!(stats.priority_changes, 0);
}

#[test]
fn sched_policy_stats_clone() {
    let stats1 = SchedPolicyStats {
        total_processes: 100,
        normal_count: 50,
        fifo_count: 10,
        rr_count: 20,
        batch_count: 5,
        idle_count: 10,
        deadline_count: 5,
        policy_changes: 1000,
        affinity_changes: 500,
        priority_changes: 200,
    };
    let stats2 = stats1.clone();
    assert_eq!(stats1.total_processes, stats2.total_processes);
    assert_eq!(stats1.normal_count, stats2.normal_count);
    assert_eq!(stats1.policy_changes, stats2.policy_changes);
}
