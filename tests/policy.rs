use tinysig::{
    EMBEDDED_GITHUB_TRUST_ROOT, Error, Policy, PolicyBuilder, RunnerEnvironment, TrustedRoot,
    verify,
};

const ARTIFACT: &[u8] = include_bytes!("fixtures/measurements.json");
const BUNDLE: &[u8] = include_bytes!("fixtures/provenance.sigstore.json");
const SIGNED_AT: u64 = 1_792_538_002;

fn builder() -> PolicyBuilder {
    Policy::builder()
        .release_tag("v1.0.0")
        .artifact_name("measurements.json")
        .now_unix_seconds(1_792_627_200)
}

#[test]
fn embedded_authorities_verify_the_real_ci_bundle() {
    let roots = TrustedRoot::embedded().unwrap();
    let policy = builder()
        .repository_id("1421861904")
        .repository_owner_id("192444375")
        .runner_environment(RunnerEnvironment::SelfHosted)
        .build()
        .unwrap();
    let result = verify(ARTIFACT, BUNDLE, &roots, &policy).unwrap();
    assert_eq!(result.source_ref, "refs/tags/v1.0.0");
    let explicit = TrustedRoot::from_json(EMBEDDED_GITHUB_TRUST_ROOT).unwrap();
    assert_eq!(
        result,
        verify(ARTIFACT, BUNDLE, &explicit, &policy).unwrap()
    );
}

#[test]
fn multiple_refs_remain_exact_and_report_the_matched_ref() {
    let roots = TrustedRoot::embedded().unwrap();
    let policy = builder()
        .git_ref("refs/heads/main")
        .allow_git_ref("refs/tags/v1.0.0")
        .allow_git_ref("refs/tags/v1.0.0")
        .build()
        .unwrap();
    assert_eq!(policy.allowed_git_refs().len(), 2);
    assert_eq!(
        verify(ARTIFACT, BUNDLE, &roots, &policy)
            .unwrap()
            .source_ref,
        "refs/tags/v1.0.0"
    );
    let wrong = builder()
        .branch("main")
        .allow_git_ref("refs/tags/v1.0.00")
        .build()
        .unwrap();
    assert_eq!(
        verify(ARTIFACT, BUNDLE, &roots, &wrong),
        Err(Error::Identity)
    );
}

#[test]
fn every_optional_identity_constraint_is_enforced() {
    let roots = TrustedRoot::embedded().unwrap();
    for policy in [
        builder().repository("prem-research/podvm"),
        builder().workflow_path(".github/workflows/other.yaml"),
        builder().oidc_issuer("https://example.com"),
        builder().event_name("workflow_dispatch"),
        builder().repository_id("1"),
        builder().repository_owner_id("1"),
        builder().runner_environment(RunnerEnvironment::GitHubHosted),
        builder().source_revision("0000000000000000000000000000000000000000"),
    ] {
        assert_eq!(
            verify(ARTIFACT, BUNDLE, &roots, &policy.build().unwrap()),
            Err(Error::Identity)
        );
    }
}

#[test]
fn timestamp_bounds_are_inclusive_and_enforced() {
    let roots = TrustedRoot::embedded().unwrap();
    let policy = builder()
        .not_before(SIGNED_AT)
        .not_after(SIGNED_AT)
        .build()
        .unwrap();
    verify(ARTIFACT, BUNDLE, &roots, &policy).unwrap();
    let policy = builder().not_before(SIGNED_AT + 1).build().unwrap();
    assert_eq!(
        verify(ARTIFACT, BUNDLE, &roots, &policy),
        Err(Error::Timestamp)
    );
    let policy = builder().not_after(SIGNED_AT - 1).build().unwrap();
    assert_eq!(
        verify(ARTIFACT, BUNDLE, &roots, &policy),
        Err(Error::Timestamp)
    );
}

#[test]
fn missing_and_malformed_policy_configuration_is_rejected() {
    for policy in [
        Policy::builder(),
        Policy::builder().release_tag("v1.0.0").not_after(1),
        Policy::builder()
            .artifact_name("measurements.json")
            .not_after(1),
        Policy::builder()
            .artifact_name("measurements.json")
            .release_tag("v1.0.0"),
        builder().artifact_name(""),
        builder().artifact_name("name\n"),
        builder().not_after(0),
        builder().not_before(1_792_627_201),
        builder().repository("https://evil.test/prem-research/trustbase"),
        builder().repository("prem-research/trustbase/extra"),
        builder().repository("../trustbase"),
        builder().repository("prem-research/trustbase.git"),
        builder().workflow_path(".github/workflows/../release.yml"),
        builder().workflow_path(".github/workflows/release.txt"),
        builder().source_revision("short"),
        builder().source_revision("F".repeat(40)),
        builder().oidc_issuer("http://example.com"),
        builder().oidc_issuer("https:///issuer"),
        builder().oidc_issuer("https://"),
        builder().oidc_issuer("https://bad host"),
        builder().event_name(""),
        builder().event_name("push*"),
        builder().repository_id(""),
        builder().repository_id("1x"),
        builder().repository_owner_id("-1"),
    ] {
        assert!(matches!(policy.build(), Err(Error::Policy)));
    }
    for git_ref in [
        "",
        "main",
        "refs/main",
        "refs/tags/",
        "refs/tags/*",
        "refs/tags/a..b",
        "refs/heads/.hidden",
        "refs/heads/x.lock",
        "refs/heads/x/",
        "refs/heads/a//b",
        "refs/tags/a@{b}",
    ] {
        assert!(
            matches!(builder().git_ref(git_ref).build(), Err(Error::Policy)),
            "{git_ref}"
        );
    }
    let mut policy = builder();
    for i in 0..32 {
        policy = policy.allow_git_ref(format!("refs/tags/v{i}"));
    }
    assert!(matches!(policy.build(), Err(Error::Policy)));
}

#[test]
fn builder_owns_configuration_and_normalizes_only_repository_prefix() {
    let policy = builder()
        .repository(String::from("https://github.com/example/project"))
        .workflow_path(String::from(".github/workflows/build.yaml"))
        .release_tag("releases/1.2.3")
        .not_before(100)
        .source_revision("a".repeat(40))
        .oidc_issuer("https://example.com/oidc")
        .event_name("workflow_dispatch")
        .repository_id("123")
        .repository_owner_id("456")
        .runner_environment(RunnerEnvironment::SelfHosted)
        .build()
        .unwrap();
    assert_eq!(policy.repository(), "https://github.com/example/project");
    assert_eq!(policy.workflow_path(), ".github/workflows/build.yaml");
    assert_eq!(policy.allowed_git_refs(), &["refs/tags/releases/1.2.3"]);
    assert_eq!(policy.artifact_name(), "measurements.json");
    assert_eq!(policy.not_before(), Some(100));
    assert_eq!(policy.not_after(), 1_792_627_200);
    assert_eq!(
        policy.source_revision(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(policy.oidc_issuer(), "https://example.com/oidc");
    assert_eq!(policy.event_name(), "workflow_dispatch");
    assert_eq!(policy.repository_id(), Some("123"));
    assert_eq!(policy.repository_owner_id(), Some("456"));
    assert_eq!(
        policy.runner_environment(),
        Some(RunnerEnvironment::SelfHosted)
    );
    assert_eq!(
        builder()
            .branch("release/1.x")
            .build()
            .unwrap()
            .allowed_git_refs(),
        &["refs/heads/release/1.x"]
    );
    assert_eq!(
        builder()
            .release_tag("1.2.3")
            .build()
            .unwrap()
            .allowed_git_refs(),
        &["refs/tags/1.2.3"]
    );
}

#[test]
fn existing_policy_can_be_rebuilt_without_losing_constraints() {
    let policy = builder()
        .repository_id("1421861904")
        .repository_owner_id("192444375")
        .runner_environment(RunnerEnvironment::SelfHosted)
        .not_before(1_792_500_000)
        .source_revision("d8525fb042f3ad96f3f7bfb481138b3661f282bf")
        .build()
        .unwrap();
    assert_eq!(policy, policy.to_builder().build().unwrap());
    let updated = policy
        .to_builder()
        .release_tag("v1.0.1")
        .not_after(1_792_627_201)
        .build()
        .unwrap();
    assert_eq!(updated.allowed_git_refs(), &["refs/tags/v1.0.1"]);
    assert_eq!(updated.not_after(), 1_792_627_201);
    assert_eq!(
        policy,
        updated
            .to_builder()
            .release_tag("v1.0.0")
            .not_after(policy.not_after())
            .build()
            .unwrap()
    );
}

#[test]
fn policy_length_limits_are_exact() {
    let owner = "o".repeat(100);
    assert!(
        builder()
            .repository(format!("{owner}/{}", "r".repeat(99)))
            .build()
            .is_ok()
    );
    assert!(matches!(
        builder()
            .repository(format!("{owner}/{}", "r".repeat(100)))
            .build(),
        Err(Error::Policy)
    ));
    assert!(matches!(
        builder().repository("a/.").build(),
        Err(Error::Policy)
    ));
    assert!(matches!(
        builder().repository("./a").build(),
        Err(Error::Policy)
    ));
    assert!(matches!(
        builder().repository("a/b c").build(),
        Err(Error::Policy)
    ));
    let path = |n: usize| format!(".github/workflows/{}.yml", "w".repeat(n));
    assert!(builder().workflow_path(path(255 - 22)).build().is_ok());
    assert!(matches!(
        builder().workflow_path(path(256 - 22)).build(),
        Err(Error::Policy)
    ));
    assert!(matches!(
        builder().workflow_path(".github/workflows/a b.yml").build(),
        Err(Error::Policy)
    ));
    assert!(builder().artifact_name("a".repeat(255)).build().is_ok());
    assert!(matches!(
        builder().artifact_name("a".repeat(256)).build(),
        Err(Error::Policy)
    ));
    assert!(builder().event_name("e".repeat(64)).build().is_ok());
    assert!(matches!(
        builder().event_name("e".repeat(65)).build(),
        Err(Error::Policy)
    ));
    assert!(builder().repository_id("1".repeat(20)).build().is_ok());
    assert!(matches!(
        builder().repository_id("1".repeat(21)).build(),
        Err(Error::Policy)
    ));
    assert!(matches!(
        builder().repository_owner_id("1".repeat(21)).build(),
        Err(Error::Policy)
    ));
    // `builder()` already allows one tag; 31 more is the 32-ref maximum.
    let mut policy = builder();
    for i in 0..31 {
        policy = policy.allow_git_ref(format!("refs/tags/v{i}"));
    }
    assert_eq!(policy.build().unwrap().allowed_git_refs().len(), 32);
    assert!(
        builder()
            .git_ref(format!("refs/tags/{}", "t".repeat(502)))
            .build()
            .is_ok()
    );
    assert!(matches!(
        builder()
            .git_ref(format!("refs/tags/{}", "t".repeat(503)))
            .build(),
        Err(Error::Policy)
    ));
    for issuer in [
        "https://example.com/a?b",
        "https://example.com/a#b",
        "https://example.com/a\\b",
        "https://example.com/a b",
        "https://exa mple.com",
    ] {
        assert!(
            matches!(builder().oidc_issuer(issuer).build(), Err(Error::Policy)),
            "{issuer}"
        );
    }
    assert!(
        builder()
            .oidc_issuer(format!("https://e.com/{}", "p".repeat(2048 - 14)))
            .build()
            .is_ok()
    );
    assert!(matches!(
        builder()
            .oidc_issuer(format!("https://e.com/{}", "p".repeat(2049 - 14)))
            .build(),
        Err(Error::Policy)
    ));
}
