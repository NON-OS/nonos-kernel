use crate::security::*;

#[test]
fn test_cpu_vulnerabilities_default() {
    let vulns = CpuVulnerabilities::default();
    assert!(vulns.spectre_v1);
    assert!(vulns.spectre_v2);
    assert!(vulns.spectre_v4);
    assert!(vulns.meltdown);
    assert!(vulns.mds);
    assert!(vulns.l1tf);
    assert!(vulns.taa);
    assert!(vulns.srbds);
    assert!(vulns.retbleed);
    assert!(vulns.mmio_stale_data);
}

#[test]
fn test_cpu_vulnerabilities_all_fields() {
    let vulns = CpuVulnerabilities {
        spectre_v1: false,
        spectre_v2: false,
        spectre_v4: false,
        meltdown: false,
        mds: false,
        l1tf: false,
        taa: false,
        srbds: false,
        retbleed: false,
        mmio_stale_data: false,
    };
    assert!(!vulns.spectre_v1);
    assert!(!vulns.spectre_v2);
    assert!(!vulns.meltdown);
}

#[test]
fn test_cpu_vulnerabilities_copy() {
    let vulns1 = CpuVulnerabilities::default();
    let vulns2 = vulns1;
    assert_eq!(vulns1.spectre_v1, vulns2.spectre_v1);
}

#[test]
fn test_cpu_vulnerabilities_clone() {
    let vulns1 = CpuVulnerabilities::default();
    let vulns2 = vulns1.clone();
    assert_eq!(vulns1.spectre_v2, vulns2.spectre_v2);
}

#[test]
fn test_mitigation_status_default() {
    let status = MitigationStatus::default();
    assert!(!status.kpti_enabled);
    assert!(status.retpoline_enabled);
    assert!(!status.ibrs_enabled);
    assert!(!status.ibpb_enabled);
    assert!(!status.stibp_enabled);
    assert!(!status.ssbd_enabled);
    assert!(!status.mds_clear_enabled);
    assert!(!status.l1d_flush_enabled);
    assert!(!status.taa_mitigation_enabled);
    assert!(!status.rsb_stuffing_enabled);
}

#[test]
fn test_mitigation_status_all_enabled() {
    let status = MitigationStatus {
        kpti_enabled: true,
        retpoline_enabled: true,
        ibrs_enabled: true,
        ibpb_enabled: true,
        stibp_enabled: true,
        ssbd_enabled: true,
        mds_clear_enabled: true,
        l1d_flush_enabled: true,
        taa_mitigation_enabled: true,
        rsb_stuffing_enabled: true,
    };
    assert!(status.kpti_enabled);
    assert!(status.ibrs_enabled);
    assert!(status.mds_clear_enabled);
}

#[test]
fn test_mitigation_status_copy() {
    let status1 = MitigationStatus::default();
    let status2 = status1;
    assert_eq!(status1.kpti_enabled, status2.kpti_enabled);
}

#[test]
fn test_mitigation_status_clone() {
    let status1 = MitigationStatus::default();
    let status2 = status1.clone();
    assert_eq!(status1.retpoline_enabled, status2.retpoline_enabled);
}

#[test]
fn test_mitigation_status_partial_enabled() {
    let status = MitigationStatus {
        kpti_enabled: true,
        retpoline_enabled: true,
        ibrs_enabled: false,
        ibpb_enabled: true,
        stibp_enabled: false,
        ssbd_enabled: false,
        mds_clear_enabled: true,
        l1d_flush_enabled: false,
        taa_mitigation_enabled: false,
        rsb_stuffing_enabled: true,
    };
    assert!(status.kpti_enabled);
    assert!(!status.ibrs_enabled);
    assert!(status.mds_clear_enabled);
    assert!(status.rsb_stuffing_enabled);
}

#[test]
fn test_lfence_barrier() {
    lfence();
}

#[test]
fn test_mfence_barrier() {
    mfence();
}

#[test]
fn test_sfence_barrier() {
    sfence();
}

#[test]
fn test_array_index_mask_nospec() {
    let mask = array_index_mask_nospec(5, 10);
    assert_eq!(mask, !0usize);
}

#[test]
fn test_array_index_mask_nospec_out_of_bounds() {
    let mask = array_index_mask_nospec(15, 10);
    assert_eq!(mask, 0);
}

#[test]
fn test_array_index_mask_nospec_boundary() {
    let mask = array_index_mask_nospec(10, 10);
    assert_eq!(mask, 0);
}

#[test]
fn test_array_access_nospec() {
    let array = [10, 20, 30, 40, 50];
    let value = array_access_nospec(&array, 2);
    assert_eq!(value, 30);
}

#[test]
fn test_array_access_nospec_first_element() {
    let array = [100, 200, 300];
    let value = array_access_nospec(&array, 0);
    assert_eq!(value, 100);
}

#[test]
fn test_array_access_nospec_last_element() {
    let array = [1, 2, 3, 4, 5];
    let value = array_access_nospec(&array, 4);
    assert_eq!(value, 5);
}

#[test]
fn test_rsb_fill() {
    rsb_fill();
}

#[test]
fn test_rsb_clear() {
    rsb_clear();
}

#[test]
fn test_l1d_flush() {
    l1d_flush();
}

#[test]
fn test_mds_clear() {
    mds_clear();
}

#[test]
fn test_kernel_entry_mitigations() {
    kernel_entry_mitigations();
}

#[test]
fn test_kernel_exit_mitigations() {
    kernel_exit_mitigations();
}

#[test]
fn test_context_switch_mitigations() {
    context_switch_mitigations();
}

#[test]
fn test_get_vulnerabilities() {
    let vulns = get_vulnerabilities();
    let _ = vulns.spectre_v1;
}

#[test]
fn test_get_mitigation_status() {
    let status = get_mitigation_status();
    let _ = status.kpti_enabled;
}

#[test]
fn test_are_mitigations_enabled() {
    let enabled = are_mitigations_enabled();
    let _ = enabled;
}

#[test]
fn test_cpu_vulnerabilities_debug_format() {
    let vulns = CpuVulnerabilities::default();
    let debug_str = alloc::format!("{:?}", vulns);
    assert!(debug_str.contains("spectre_v1"));
}

#[test]
fn test_mitigation_status_debug_format() {
    let status = MitigationStatus::default();
    let debug_str = alloc::format!("{:?}", status);
    assert!(debug_str.contains("kpti_enabled"));
}

#[test]
fn test_vulnerability_fields_are_bools() {
    let vulns = CpuVulnerabilities::default();
    let _: bool = vulns.spectre_v1;
    let _: bool = vulns.meltdown;
    let _: bool = vulns.mds;
}

#[test]
fn test_mitigation_fields_are_bools() {
    let status = MitigationStatus::default();
    let _: bool = status.kpti_enabled;
    let _: bool = status.retpoline_enabled;
    let _: bool = status.ibrs_enabled;
}
