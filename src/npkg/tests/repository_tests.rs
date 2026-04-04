use crate::npkg::*;
use crate::npkg::repository::{RepositoryKind, RepositoryConfig};

#[test]
fn test_repository_kind_official_trust_level() {
    let kind = RepositoryKind::Official;
    assert_eq!(kind.trust_level(), 100);
}

#[test]
fn test_repository_kind_community_trust_level() {
    let kind = RepositoryKind::Community;
    assert_eq!(kind.trust_level(), 75);
}

#[test]
fn test_repository_kind_thirdparty_trust_level() {
    let kind = RepositoryKind::ThirdParty;
    assert_eq!(kind.trust_level(), 50);
}

#[test]
fn test_repository_kind_local_trust_level() {
    let kind = RepositoryKind::Local;
    assert_eq!(kind.trust_level(), 25);
}

#[test]
fn test_repository_kind_variants() {
    let kinds = [
        RepositoryKind::Official,
        RepositoryKind::Community,
        RepositoryKind::ThirdParty,
        RepositoryKind::Local,
    ];
    assert_eq!(kinds.len(), 4);
}

#[test]
fn test_repository_kind_equality() {
    assert_eq!(RepositoryKind::Official, RepositoryKind::Official);
    assert_ne!(RepositoryKind::Official, RepositoryKind::Local);
}

#[test]
fn test_repository_kind_copy() {
    let kind = RepositoryKind::Community;
    let copied = kind;
    assert_eq!(kind, copied);
}

#[test]
fn test_repository_kind_clone() {
    let kind = RepositoryKind::ThirdParty;
    let cloned = kind.clone();
    assert_eq!(kind, cloned);
}

#[test]
fn test_repository_kind_debug_format() {
    let kind = RepositoryKind::Official;
    let debug_str = alloc::format!("{:?}", kind);
    assert!(debug_str.contains("Official"));
}

#[test]
fn test_repository_config_official() {
    let config = RepositoryConfig::official("main", "https://repo.nonos.org/main");
    assert_eq!(config.name, "main");
    assert_eq!(config.url, "https://repo.nonos.org/main");
    assert_eq!(config.kind, RepositoryKind::Official);
    assert!(config.enabled);
    assert!(config.signature_required);
    assert_eq!(config.priority, 100);
}

#[test]
fn test_repository_config_community() {
    let config = RepositoryConfig::community("user-repo", "https://example.com/repo");
    assert_eq!(config.name, "user-repo");
    assert_eq!(config.kind, RepositoryKind::Community);
    assert!(config.enabled);
    assert!(config.signature_required);
    assert_eq!(config.priority, 50);
}

#[test]
fn test_repository_config_local() {
    let config = RepositoryConfig::local("/home/user/packages");
    assert_eq!(config.name, "local");
    assert_eq!(config.url, "/home/user/packages");
    assert_eq!(config.kind, RepositoryKind::Local);
    assert!(config.enabled);
    assert!(!config.signature_required);
    assert_eq!(config.priority, 200);
}

#[test]
fn test_repository_config_clone() {
    let config = RepositoryConfig::official("test", "https://test.com");
    let cloned = config.clone();
    assert_eq!(config.name, cloned.name);
    assert_eq!(config.url, cloned.url);
    assert_eq!(config.kind, cloned.kind);
}

#[test]
fn test_repository_config_debug_format() {
    let config = RepositoryConfig::official("debug", "https://debug.com");
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("RepositoryConfig"));
}

#[test]
fn test_repository_config_priority_ordering() {
    let local = RepositoryConfig::local("/local");
    let official = RepositoryConfig::official("main", "https://main.com");
    let community = RepositoryConfig::community("comm", "https://comm.com");

    assert!(local.priority > official.priority);
    assert!(official.priority > community.priority);
}

#[test]
fn test_repository_config_signature_policy() {
    let official = RepositoryConfig::official("main", "https://main.com");
    let local = RepositoryConfig::local("/local");

    assert!(official.signature_required);
    assert!(!local.signature_required);
}

#[test]
fn test_repository_config_enabled_by_default() {
    let official = RepositoryConfig::official("main", "https://main.com");
    let community = RepositoryConfig::community("comm", "https://comm.com");
    let local = RepositoryConfig::local("/local");

    assert!(official.enabled);
    assert!(community.enabled);
    assert!(local.enabled);
}

#[test]
fn test_list_repositories() {
    let repos = list_repositories();
    let _ = repos.len();
}

#[test]
fn test_repository_kind_trust_ordering() {
    let official = RepositoryKind::Official.trust_level();
    let community = RepositoryKind::Community.trust_level();
    let thirdparty = RepositoryKind::ThirdParty.trust_level();
    let local = RepositoryKind::Local.trust_level();

    assert!(official > community);
    assert!(community > thirdparty);
    assert!(thirdparty > local);
}

#[test]
fn test_repository_config_with_https() {
    let config = RepositoryConfig::official("secure", "https://secure.repo.org");
    assert!(config.url.starts_with("https://"));
}

#[test]
fn test_repository_config_local_path_absolute() {
    let config = RepositoryConfig::local("/var/cache/packages");
    assert!(config.url.starts_with('/'));
}
