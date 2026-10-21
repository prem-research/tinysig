//! Validated, exact-match policy construction. No regex or wildcard dependency.
use crate::{Error, error::Result};
use alloc::{format, string::String, vec::Vec};

/// GitHub runner classification authenticated by the signing certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerEnvironment {
    /// A runner hosted by GitHub.
    GitHubHosted,
    /// A runner hosted by the repository owner or another external operator.
    SelfHosted,
}

impl RunnerEnvironment {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::GitHubHosted => "github-hosted",
            Self::SelfHosted => "self-hosted",
        }
    }
}

/// A validated GitHub workflow identity and artifact policy.
///
/// Construct with [`Policy::builder`]. All allowed refs are exact matches;
/// identity, signature, digest, and timestamp checks cannot be disabled.
/// The format remains GitHub's timestamp-based DSSE/SLSA v1 profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub(crate) repository: String,
    pub(crate) workflow_path: String,
    pub(crate) git_refs: Vec<String>,
    pub(crate) artifact_name: String,
    pub(crate) not_after: u64,
    pub(crate) not_before: Option<u64>,
    pub(crate) source_revision: Option<String>,
    pub(crate) oidc_issuer: String,
    pub(crate) event_name: String,
    pub(crate) runner_environment: Option<RunnerEnvironment>,
    pub(crate) repository_id: Option<String>,
    pub(crate) repository_owner_id: Option<String>,
}

impl Policy {
    /// Start with Trustbase's repository, release workflow, GitHub OIDC issuer,
    /// and `push` trigger. Artifact, allowed ref, and upper time bound are required.
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }

    /// Copy this policy into a builder, for example to advance the upper time
    /// bound or replace the expected release without repeating identity pins.
    pub fn to_builder(&self) -> PolicyBuilder {
        PolicyBuilder {
            repository: self.repository.clone(),
            workflow_path: self.workflow_path.clone(),
            git_refs: self.git_refs.clone(),
            artifact_name: Some(self.artifact_name.clone()),
            not_after: Some(self.not_after),
            not_before: self.not_before,
            source_revision: self.source_revision.clone(),
            oidc_issuer: self.oidc_issuer.clone(),
            event_name: self.event_name.clone(),
            runner_environment: self.runner_environment,
            repository_id: self.repository_id.clone(),
            repository_owner_id: self.repository_owner_id.clone(),
        }
    }

    /// Expected source repository as a canonical `https://github.com/owner/repo` URI.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Expected workflow path within the source repository.
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    /// Exact source refs that may sign this artifact.
    pub fn allowed_git_refs(&self) -> &[String] {
        &self.git_refs
    }

    /// Required in-toto subject name.
    pub fn artifact_name(&self) -> &str {
        &self.artifact_name
    }

    /// Inclusive upper bound on the authenticated signing time, in Unix seconds.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Optional inclusive lower bound on the authenticated signing time.
    pub fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    /// Optional immutable source commit pin.
    pub fn source_revision(&self) -> Option<&str> {
        self.source_revision.as_deref()
    }

    /// Required OIDC token issuer URI.
    pub fn oidc_issuer(&self) -> &str {
        &self.oidc_issuer
    }

    /// Required GitHub event name.
    pub fn event_name(&self) -> &str {
        &self.event_name
    }

    /// Optional required runner classification.
    pub fn runner_environment(&self) -> Option<RunnerEnvironment> {
        self.runner_environment
    }

    /// Optional immutable GitHub repository ID pin.
    pub fn repository_id(&self) -> Option<&str> {
        self.repository_id.as_deref()
    }

    /// Optional immutable GitHub repository owner ID pin.
    pub fn repository_owner_id(&self) -> Option<&str> {
        self.repository_owner_id.as_deref()
    }

    pub(crate) fn workflow_identity(&self, git_ref: &str) -> String {
        format!("{}/{}@{git_ref}", self.repository, self.workflow_path)
    }
}

/// Builder for [`Policy`], using owned strings so dynamically supplied
/// configuration does not need to outlive the resulting policy.
///
/// Setters replace their corresponding value; [`Self::allow_git_ref`] appends.
/// Validation happens in [`Self::build`]. There are no implicit clock reads.
#[derive(Clone, Debug)]
#[must_use]
pub struct PolicyBuilder {
    repository: String,
    workflow_path: String,
    git_refs: Vec<String>,
    artifact_name: Option<String>,
    not_after: Option<u64>,
    not_before: Option<u64>,
    source_revision: Option<String>,
    oidc_issuer: String,
    event_name: String,
    runner_environment: Option<RunnerEnvironment>,
    repository_id: Option<String>,
    repository_owner_id: Option<String>,
}

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self {
            repository: "prem-research/trustbase".into(),
            workflow_path: ".github/workflows/release.yml".into(),
            git_refs: Vec::new(),
            artifact_name: None,
            not_after: None,
            not_before: None,
            source_revision: None,
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
            event_name: "push".into(),
            runner_environment: None,
            repository_id: None,
            repository_owner_id: None,
        }
    }
}

impl PolicyBuilder {
    /// Expected GitHub source repository, either `owner/repo` or its canonical
    /// `https://github.com/owner/repo` URL. No trailing slash or `.git` suffix.
    pub fn repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = repository.into();
        self
    }

    /// Expected source workflow path, such as `.github/workflows/release.yml`.
    /// Reusable workflows in a different repository/ref are not supported.
    pub fn workflow_path(mut self, path: impl Into<String>) -> Self {
        self.workflow_path = path.into();
        self
    }

    /// Replace all allowed refs with one exact `refs/...` ref.
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_refs = alloc::vec![git_ref.into()];
        self
    }

    /// Append an exact allowed ref. At least one and at most 32 refs are required.
    /// Duplicates are removed by `build`; no patterns or wildcard matching is used.
    pub fn allow_git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_refs.push(git_ref.into());
        self
    }

    /// Replace all allowed refs with `refs/tags/<tag>`. A `v` prefix is optional,
    /// and nested tags such as `releases/1.0.0` are accepted.
    pub fn release_tag(self, tag: impl AsRef<str>) -> Self {
        self.git_ref(format!("refs/tags/{}", tag.as_ref()))
    }

    /// Replace all allowed refs with `refs/heads/<branch>`.
    pub fn branch(self, branch: impl AsRef<str>) -> Self {
        self.git_ref(format!("refs/heads/{}", branch.as_ref()))
    }

    /// Required exact in-toto artifact subject name, at most 255 bytes.
    pub fn artifact_name(mut self, name: impl Into<String>) -> Self {
        self.artifact_name = Some(name.into());
        self
    }

    /// Inclusive upper signing-time bound in Unix seconds, from a trusted clock
    /// or caller policy. This value is required and must be nonzero.
    pub fn not_after(mut self, seconds: u64) -> Self {
        self.not_after = Some(seconds);
        self
    }

    /// Supply the trusted current time as the inclusive upper signing-time bound.
    /// Equivalent to [`Self::not_after`]; neither method reads a platform clock.
    pub fn now_unix_seconds(self, seconds: u64) -> Self {
        self.not_after(seconds)
    }

    /// Inclusive lower signing-time bound in Unix seconds; optional.
    pub fn not_before(mut self, seconds: u64) -> Self {
        self.not_before = Some(seconds);
        self
    }

    /// Require an immutable source commit: exactly 40 lowercase hexadecimal digits.
    pub fn source_revision(mut self, revision: impl Into<String>) -> Self {
        self.source_revision = Some(revision.into());
        self
    }

    /// Require an exact OIDC issuer URI. Defaults to GitHub Actions' issuer.
    /// Changing this does not change the trust roots or supported bundle format.
    pub fn oidc_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.oidc_issuer = issuer.into();
        self
    }

    /// Require an exact trigger in both certificate and provenance, e.g.
    /// `push` (default) or `workflow_dispatch`.
    pub fn event_name(mut self, event: impl Into<String>) -> Self {
        self.event_name = event.into();
        self
    }

    /// Require a runner classification in both certificate and provenance.
    /// By default either runner classification is accepted.
    pub fn runner_environment(mut self, environment: RunnerEnvironment) -> Self {
        self.runner_environment = Some(environment);
        self
    }

    /// Pin GitHub's immutable decimal repository ID in certificate and provenance.
    pub fn repository_id(mut self, id: impl Into<String>) -> Self {
        self.repository_id = Some(id.into());
        self
    }

    /// Pin GitHub's immutable decimal owner ID in certificate and provenance.
    pub fn repository_owner_id(mut self, id: impl Into<String>) -> Self {
        self.repository_owner_id = Some(id.into());
        self
    }

    /// Validate and finish the policy. Missing fields, malformed identities,
    /// unsupported refs, or inverted time bounds return [`Error::Policy`].
    pub fn build(self) -> Result<Policy> {
        let repository = self
            .repository
            .strip_prefix("https://github.com/")
            .unwrap_or(&self.repository);
        let parts: Vec<_> = repository.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|p| {
                p.is_empty()
                    || *p == "."
                    || *p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
            || repository.len() > 200
            || repository.ends_with(".git")
        {
            return Err(Error::Policy);
        }
        if !self.workflow_path.starts_with(".github/workflows/")
            || ![".yml", ".yaml"]
                .iter()
                .any(|s| self.workflow_path.ends_with(s))
            || self.workflow_path.len() > 255
        {
            return Err(Error::Policy);
        }
        let file = &self.workflow_path[".github/workflows/".len()..];
        if file.starts_with('.')
            || !file
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(Error::Policy);
        }
        if self.git_refs.is_empty()
            || self.git_refs.len() > 32
            || self.git_refs.iter().any(|r| !valid_ref(r))
        {
            return Err(Error::Policy);
        }
        let mut git_refs = self.git_refs;
        git_refs.sort();
        git_refs.dedup();
        let artifact_name = self.artifact_name.ok_or(Error::Policy)?;
        if artifact_name.is_empty()
            || artifact_name.len() > 255
            || artifact_name.chars().any(char::is_control)
        {
            return Err(Error::Policy);
        }
        let not_after = self.not_after.filter(|t| *t != 0).ok_or(Error::Policy)?;
        if self.not_before.is_some_and(|t| t > not_after)
            || self
                .source_revision
                .as_deref()
                .is_some_and(|r| !valid_revision(r))
            || !valid_issuer(&self.oidc_issuer)
            || self.event_name.is_empty()
            || self.event_name.len() > 64
            || !self
                .event_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || [&self.repository_id, &self.repository_owner_id]
                .iter()
                .any(|id| {
                    id.as_deref().is_some_and(|s| {
                        s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit())
                    })
                })
        {
            return Err(Error::Policy);
        }
        Ok(Policy {
            repository: format!("https://github.com/{repository}"),
            workflow_path: self.workflow_path,
            git_refs,
            artifact_name,
            not_after,
            not_before: self.not_before,
            source_revision: self.source_revision,
            oidc_issuer: self.oidc_issuer,
            event_name: self.event_name,
            runner_environment: self.runner_environment,
            repository_id: self.repository_id,
            repository_owner_id: self.repository_owner_id,
        })
    }
}

fn valid_ref(git_ref: &str) -> bool {
    git_ref.starts_with("refs/")
        && git_ref.len() <= 512
        && git_ref.split('/').count() >= 3
        && git_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && !git_ref.contains("..")
        && git_ref.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock")
        })
}

pub(crate) fn valid_revision(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_issuer(issuer: &str) -> bool {
    let Some(rest) = issuer.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !authority.is_empty()
        && issuer.len() <= 2048
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        && issuer
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"?#\\".contains(&b))
}
