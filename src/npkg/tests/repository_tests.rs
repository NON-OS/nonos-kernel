use crate::npkg::repository::{RepositoryConfig, RepositoryKind};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_repository_kind_official_trust_level() -> TestResult {
    let kind = RepositoryKind::Official;
    if kind.trust_level() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_community_trust_level() -> TestResult {
    let kind = RepositoryKind::Community;
    if kind.trust_level() != 75 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_thirdparty_trust_level() -> TestResult {
    let kind = RepositoryKind::ThirdParty;
    if kind.trust_level() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_local_trust_level() -> TestResult {
    let kind = RepositoryKind::Local;
    if kind.trust_level() != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_variants() -> TestResult {
    let kinds = [
        RepositoryKind::Official,
        RepositoryKind::Community,
        RepositoryKind::ThirdParty,
        RepositoryKind::Local,
    ];
    if kinds.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_equality() -> TestResult {
    if RepositoryKind::Official != RepositoryKind::Official {
        return TestResult::Fail;
    }
    if RepositoryKind::Official == RepositoryKind::Local {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_copy() -> TestResult {
    let kind = RepositoryKind::Community;
    let copied = kind;
    if kind != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_clone() -> TestResult {
    let kind = RepositoryKind::ThirdParty;
    let cloned = kind.clone();
    if kind != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_kind_debug_format() -> TestResult {
    let kind = RepositoryKind::Official;
    let debug_str = alloc::format!("{:?}", kind);
    if !debug_str.contains("Official") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_official() -> TestResult {
    let config = RepositoryConfig::official("main", "https://repo.nonos.org/main");
    if config.name != "main" {
        return TestResult::Fail;
    }
    if config.url != "https://repo.nonos.org/main" {
        return TestResult::Fail;
    }
    if config.kind != RepositoryKind::Official {
        return TestResult::Fail;
    }
    if !config.enabled {
        return TestResult::Fail;
    }
    if !config.signature_required {
        return TestResult::Fail;
    }
    if config.priority != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_community() -> TestResult {
    let config = RepositoryConfig::community("user-repo", "https://example.com/repo");
    if config.name != "user-repo" {
        return TestResult::Fail;
    }
    if config.kind != RepositoryKind::Community {
        return TestResult::Fail;
    }
    if !config.enabled {
        return TestResult::Fail;
    }
    if !config.signature_required {
        return TestResult::Fail;
    }
    if config.priority != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_local() -> TestResult {
    let config = RepositoryConfig::local("/home/user/packages");
    if config.name != "local" {
        return TestResult::Fail;
    }
    if config.url != "/home/user/packages" {
        return TestResult::Fail;
    }
    if config.kind != RepositoryKind::Local {
        return TestResult::Fail;
    }
    if !config.enabled {
        return TestResult::Fail;
    }
    if config.signature_required {
        return TestResult::Fail;
    }
    if config.priority != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_clone() -> TestResult {
    let config = RepositoryConfig::official("test", "https://test.com");
    let cloned = config.clone();
    if config.name != cloned.name {
        return TestResult::Fail;
    }
    if config.url != cloned.url {
        return TestResult::Fail;
    }
    if config.kind != cloned.kind {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_debug_format() -> TestResult {
    let config = RepositoryConfig::official("debug", "https://debug.com");
    let debug_str = alloc::format!("{:?}", config);
    if !debug_str.contains("RepositoryConfig") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_priority_ordering() -> TestResult {
    let local = RepositoryConfig::local("/local");
    let official = RepositoryConfig::official("main", "https://main.com");
    let community = RepositoryConfig::community("comm", "https://comm.com");

    if local.priority <= official.priority {
        return TestResult::Fail;
    }
    if official.priority <= community.priority {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_signature_policy() -> TestResult {
    let official = RepositoryConfig::official("main", "https://main.com");
    let local = RepositoryConfig::local("/local");

    if !official.signature_required {
        return TestResult::Fail;
    }
    if local.signature_required {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_enabled_by_default() -> TestResult {
    let official = RepositoryConfig::official("main", "https://main.com");
    let community = RepositoryConfig::community("comm", "https://comm.com");
    let local = RepositoryConfig::local("/local");

    if !official.enabled {
        return TestResult::Fail;
    }
    if !community.enabled {
        return TestResult::Fail;
    }
    if !local.enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_repositories() -> TestResult {
    let repos = list_repositories();
    let _ = repos.len();
    TestResult::Pass
}

pub(crate) fn test_repository_kind_trust_ordering() -> TestResult {
    let official = RepositoryKind::Official.trust_level();
    let community = RepositoryKind::Community.trust_level();
    let thirdparty = RepositoryKind::ThirdParty.trust_level();
    let local = RepositoryKind::Local.trust_level();

    if official <= community {
        return TestResult::Fail;
    }
    if community <= thirdparty {
        return TestResult::Fail;
    }
    if thirdparty <= local {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_with_https() -> TestResult {
    let config = RepositoryConfig::official("secure", "https://secure.repo.org");
    if !config.url.starts_with("https://") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_repository_config_local_path_absolute() -> TestResult {
    let config = RepositoryConfig::local("/var/cache/packages");
    if !config.url.starts_with('/') {
        return TestResult::Fail;
    }
    TestResult::Pass
}
