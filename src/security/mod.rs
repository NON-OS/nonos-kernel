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

pub mod boot;
pub mod crypto;
pub mod hardening;
pub mod monitoring;
pub mod policy;
pub mod network;
pub mod quantum;
pub mod module_db;
mod init;
mod periodic;
mod stats;
mod wipe;

pub use boot::secure_boot;
pub use boot::firmware;

pub use boot::{
    secure_boot_init, set_policy, get_policy, is_enforcing, verify_code_signature,
    verify_kernel, record_boot_measurements, verify_boot_chain, is_boot_chain_verified,
    get_boot_measurements, generate_attestation_report, BootMeasurements, TrustedBootKeys,
    SecureBootPolicy, SecureBootError, SecureBootResult, AttestationReport, SecureBootStats,
    firmware_init, FirmwareDB,
};

pub use crypto::key_management;
pub use crypto::constant_time;
pub use crypto::random;
pub use crypto::trusted_keys;
pub use crypto::trusted_hashes;
pub use crypto::trusted_keys as nonos_trusted_keys;
pub use crypto::trusted_hashes as nonos_trusted_hashes;

pub use crypto::{
    key_management_init, generate_key, import_key, use_key, export_key, rotate_key,
    derive_key, delete_key, delete_all_keys, get_key_info, list_keys, list_keys_by_owner,
    find_key_by_fingerprint, KeyType, KeyUsage, KeyEntry, KeyStore, KeyAuditEntry,
    KeyOperation, KeyError, KeyResult, KeyInfo,
    constant_time_init, ct_compare, ct_verify, ct_select_u8, ct_select_u32, ct_select_u64,
    ct_select_slice, ct_swap_slices, ct_lt_u32, ct_lt_u64, ct_gt_u32, ct_eq_u32, ct_eq_u64,
    ct_min_u32, ct_max_u32, ct_copy_bounded, ct_zero, ct_zero_u64, ct_hmac_verify,
    ct_signature_verify, run_self_tests, CtVerifyResult, TimingMode, SelfTestResult,
    random_init, secure_random_u64, fill_random, secure_random_u32, secure_random_u8,
    trusted_keys_init, add_trusted_key, get_trusted_key, verify_signature as crypto_verify_signature,
    list_trusted_keys as crypto_list_trusted_keys, init_trusted_keys, get_trusted_keys,
    TrustedKeyDB, TrustedKey,
    trusted_hashes_init, add_trusted_hash, get_trusted_hash, verify_integrity,
    list_trusted_hashes, TrustedHashDB,
};

pub use hardening::spectre_mitigations;
pub use hardening::memory_sanitization;

pub use hardening::{
    spectre_init, CpuVulnerabilities, MitigationStatus, lfence, mfence, sfence,
    array_index_mask_nospec, array_access_nospec, rsb_fill, rsb_clear, ibpb, ibrs_enable,
    ibrs_disable, stibp_enable, stibp_disable, ssbd_enable, ssbd_disable, mds_clear, l1d_flush,
    kernel_entry_mitigations, kernel_exit_mitigations, context_switch_mitigations,
    detect_vulnerabilities, enable_mitigations, get_vulnerabilities, get_mitigation_status,
    are_mitigations_enabled,
    memory_sanitization_init, SanitizationLevel, StackCanaryConfig, secure_zero,
    secure_zero_slice, dod_5220_erase, paranoid_erase, gutmann_erase, sanitize, sanitize_slice,
    init_stack_canary, get_stack_canary, verify_stack_canary, stack_canary_failed,
    GuardPage, allocate_with_guards, free_with_guards, SensitiveData, SecureString,
    on_free, on_realloc, sanitize_process_memory, zerostate_shutdown_wipe,
    SanitizationStats, sanitization_stats, set_level, get_level,
};

pub use monitoring::audit;
pub use monitoring::monitor;
pub use monitoring::rootkit;
pub use monitoring::leak_detection;

pub use monitoring::{
    audit_init, AuditSeverity, SecurityAuditEvent, log_security_event,
    log_security_violation, get_audit_log, clear_audit_log, AuditEvent, audit_event,
    SecurityEventType, SecurityEvent, MonitorStats, log_event, get_recent_events,
    monitor_stats, set_enabled, is_enabled,
    rootkit_init, RootkitScanResult, rootkit_scan, rootkit_last_scan,
    LeakScanResult, LeakFinding, LeakLocation, add_sensitive_pattern,
    list_sensitive_patterns, leak_scan_memory, leak_scan_filesystem, leak_scan_network,
    leak_last_scan,
};

pub use policy::capability;
pub use policy::advanced;
pub use policy::session;

pub use policy::capability::*;
pub use policy::advanced::*;
pub use policy::session::{
    UID_ROOT, UID_ANONYMOUS, UID_DEFAULT, GID_ROOT, GID_WHEEL, GID_USERS,
    PrivilegeLevel, UserAccount, SessionState, UserSession, SessionManager,
    session_manager, init as session_init, current_uid, current_username,
    current_cwd, getenv, setenv, chdir, environ, SessionStats, get_stats as session_get_stats,
};

pub use network::dns_privacy;
pub use network::zkids;

pub use network::dns_privacy::*;
pub use network::zkids::*;

pub use quantum::pqc;

pub use quantum::pqc::*;

pub use module_db::{
    ModuleDB, init as module_db_init, is_trusted_module, get_loaded_modules,
};

pub use init::init_all_security;
pub use periodic::run_periodic_checks;
pub use stats::{SecurityStats, get_security_stats};
pub use wipe::secure_wipe_all_memory;
