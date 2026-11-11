use tinysig::{Error, Identity, IdentityBuilder};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const WORKFLOW: &str = "https://github.com/example/project/.github/workflows/release.yml";

fn builder() -> IdentityBuilder {
    Identity::builder().repository("example/project")
}

#[test]
fn exact_uri_and_email_identities_pin_both_subject_and_issuer() {
    for subject in ["signer@example.com", "https://example.com/workflow@v1"] {
        let identity = Identity::builder()
            .subject(String::from(subject))
            .oidc_issuer("https://example.com/oidc")
            .build()
            .unwrap();
        assert!(identity.matches(subject, "https://example.com/oidc"));
        assert!(!identity.matches(subject, ISSUER));
        assert!(!identity.matches("other@example.com", "https://example.com/oidc"));
        assert_eq!(identity.subject(), Some(subject));
        assert_eq!(identity.repository(), None);
        assert_eq!(identity.workflow_path(), None);
        assert!(identity.allowed_git_refs().is_empty());
        assert_eq!(identity.semver_range(), None);
        assert_eq!(identity.tag_prefix(), None);
        assert_eq!(identity, identity.to_builder().build().unwrap());
    }
}

#[test]
fn ranges_only_accept_valid_release_tags_in_the_pinned_workflow() {
    let identity = builder().semver_range(">=1.2.3, <2.0.0").build().unwrap();
    assert_eq!(
        identity.repository(),
        Some("https://github.com/example/project")
    );
    assert_eq!(
        identity.workflow_path(),
        Some(".github/workflows/release.yml")
    );
    assert_eq!(identity.tag_prefix(), Some("v"));
    assert_eq!(
        identity.semver_range().unwrap().to_string(),
        ">=1.2.3, <2.0.0"
    );
    for tag in ["v1.2.3", "v1.2.4", "v1.99.99", "v1.2.3+build.123"] {
        assert!(
            identity.matches(&format!("{WORKFLOW}@refs/tags/{tag}"), ISSUER),
            "{tag}"
        );
    }
    for git_ref in [
        "refs/tags/v1.2.2",
        "refs/tags/v2.0.0",
        "refs/tags/v1.3.0-rc.1",
        "refs/tags/v01.2.3",
        "refs/tags/v1.2",
        "refs/tags/v1.2.3/extra",
        "refs/tags/1.2.3",
        "refs/tags/vv1.2.3",
        "refs/tags/releases/v1.2.3",
        "refs/heads/v1.2.3",
        "refs/pull/v1.2.3",
        "refs/tags/v1.2.3+bad..metadata",
    ] {
        assert!(
            !identity.matches(&format!("{WORKFLOW}@{git_ref}"), ISSUER),
            "{git_ref}"
        );
    }
    for subject in [
        format!("{WORKFLOW}@refs/tags/v1.2.3@refs/tags/v1.2.4"),
        format!("{WORKFLOW}@refs/tags/v1.2.3/trailing"),
        format!("{WORKFLOW}@refs/tags/v1.2.3").replace("example/project", "evil/project"),
        format!("{WORKFLOW}@refs/tags/v1.2.3").replace("release.yml", "other.yml"),
        format!("{WORKFLOW}@refs/tags/v1.2.3").replace("github.com/", "github.com.evil/"),
        format!("{WORKFLOW}@refs/tags/v1.2.3").replace("example/project", "Example/project"),
    ] {
        assert!(!identity.matches(&subject, ISSUER), "{subject}");
    }
    assert!(!identity.matches(
        &format!("{WORKFLOW}@refs/tags/v1.2.3"),
        "https://evil.example"
    ));
    assert_eq!(identity, identity.to_builder().build().unwrap());
}

#[test]
fn cargo_requirements_handle_zero_major_prereleases_and_metadata() {
    for (requirement, tag, expected) in [
        ("^0.2.3", "v0.2.9", true),
        ("^0.2.3", "v0.3.0", false),
        ("~1.2.3", "v1.2.9", true),
        ("~1.2.3", "v1.3.0", false),
        ("*", "v1.2.3-rc.1", false),
        (">=1.2.3-rc.1, <2.0.0", "v1.2.3-rc.2", true),
        (">=1.2.3-rc.1, <2.0.0", "v1.2.4-rc.1", false),
        ("=1.2.3", "v1.2.3+build.9", true),
    ] {
        let identity = builder().semver_range(requirement).build().unwrap();
        assert_eq!(
            identity.matches(&format!("{WORKFLOW}@refs/tags/{tag}"), ISSUER),
            expected,
            "{requirement}: {tag}"
        );
    }
}

#[test]
fn tag_prefixes_are_explicit_and_literal() {
    for prefix in ["", "releases/v", "package-v"] {
        let identity = builder()
            .semver_range("^1.2")
            .tag_prefix(prefix)
            .build()
            .unwrap();
        assert!(identity.matches(&format!("{WORKFLOW}@refs/tags/{prefix}1.2.3"), ISSUER));
        assert!(!identity.matches(&format!("{WORKFLOW}@refs/tags/other{prefix}1.2.3"), ISSUER));
        assert_eq!(identity, identity.to_builder().build().unwrap());
    }
}

#[test]
fn exact_refs_are_alternatives_and_replacing_constraints_is_predictable() {
    let identity = builder()
        .semver_range("^1.2")
        .allow_git_ref("refs/heads/main")
        .allow_git_ref("refs/heads/main")
        .build()
        .unwrap();
    assert_eq!(identity.allowed_git_refs(), &["refs/heads/main"]);
    assert!(identity.matches(&format!("{WORKFLOW}@refs/heads/main"), ISSUER));
    assert!(identity.matches(&format!("{WORKFLOW}@refs/tags/v1.2.3"), ISSUER));
    let exact = identity.to_builder().release_tag("v3.0.0").build().unwrap();
    assert!(exact.semver_range().is_none());
    assert!(!exact.matches(&format!("{WORKFLOW}@refs/tags/v1.2.3"), ISSUER));
    assert!(!exact.matches(&format!("{WORKFLOW}@refs/heads/main"), ISSUER));
    assert!(exact.matches(&format!("{WORKFLOW}@refs/tags/v3.0.0"), ISSUER));
    let range = exact.to_builder().semver_range("^1.2").build().unwrap();
    assert!(range.allowed_git_refs().is_empty());
    assert!(!range.matches(&format!("{WORKFLOW}@refs/tags/v3.0.0"), ISSUER));
}

#[test]
fn rebuilding_preserves_parsed_ranges_without_revalidating_display_length() {
    let mut comparators =
        vec![">=18446744073709551615.18446744073709551615.18446744073709551615"; 10];
    comparators.extend(vec![
        ">=1844674407370955161.1844674407370955161.1844674407370955161";
        6
    ]);
    let requirement = comparators.join(",");
    assert!(requirement.len() <= 1024);
    let identity = builder().semver_range(requirement).build().unwrap();
    assert!(identity.semver_range().unwrap().to_string().len() > 1024);
    assert_eq!(identity, identity.to_builder().build().unwrap());
    assert_eq!(
        tinysig::Policy::builder()
            .identity(identity.clone())
            .artifact_name("artifact")
            .not_after(1)
            .build()
            .unwrap()
            .identity(),
        &identity
    );
}

#[test]
fn missing_ambiguous_or_malformed_identity_configuration_fails_closed() {
    for builder in [
        IdentityBuilder::default(),
        builder(),
        Identity::builder().subject(""),
        Identity::builder().subject("bad subject"),
        Identity::builder().subject("bad\nsubject"),
        Identity::builder().subject("x".repeat(2049)),
        Identity::builder()
            .subject("signer@example.com")
            .oidc_issuer(""),
        Identity::builder()
            .subject("signer@example.com")
            .oidc_issuer("http://example.com"),
        Identity::builder()
            .subject("signer@example.com")
            .oidc_issuer("https:///issuer"),
        builder()
            .subject("signer@example.com")
            .release_tag("v1.2.3"),
        Identity::builder()
            .subject("signer@example.com")
            .semver_range("^1"),
        Identity::builder()
            .subject("signer@example.com")
            .workflow_path(".github/workflows/other.yml"),
        Identity::builder()
            .subject("signer@example.com")
            .tag_prefix(""),
        builder().semver_range(""),
        builder().semver_range(" "),
        builder().semver_range("not a range"),
        builder().semver_range("^1.2 || ^2.0"),
        builder().semver_range("1".repeat(1025)),
        builder().semver_range("^1").tag_prefix("../"),
        builder().semver_range("^1").tag_prefix("*"),
        builder()
            .semver_range("^1")
            .repository("evil.example/project/repo"),
        builder()
            .semver_range("^1")
            .workflow_path(".github/workflows/../release.yml"),
    ] {
        assert_eq!(builder.build(), Err(Error::Policy));
    }
}
