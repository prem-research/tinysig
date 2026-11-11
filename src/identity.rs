//! Validated signer identities shared by both verification profiles.

use crate::{Error, error::Result};
use alloc::{format, string::String, vec::Vec};
use semver::{Version, VersionReq};

/// An expected certificate subject and OIDC issuer, not an identity discovered
/// from an untrusted bundle. Construct with [`Self::builder`].
///
/// Match either an exact URI/email or a pinned GitHub repository/workflow with
/// exact refs and/or a semantic-version requirement on release tags. Matching is
/// case-sensitive and never uses regexes or identity wildcards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    issuer: String,
    kind: IdentityKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IdentityKind {
    Exact(String),
    GitHub {
        repository: String,
        workflow_path: String,
        git_refs: Vec<String>,
        range: Option<VersionReq>,
        tag_prefix: String,
    },
}

impl Identity {
    /// Start an identity builder. The issuer defaults to GitHub Actions and the
    /// workflow path to `.github/workflows/release.yml`; no signer is implicit.
    pub fn builder() -> IdentityBuilder {
        IdentityBuilder::default()
    }

    /// Copy this identity into a builder without losing constraints.
    pub fn to_builder(&self) -> IdentityBuilder {
        let mut builder = Self::builder().oidc_issuer(self.issuer.clone());
        match &self.kind {
            IdentityKind::Exact(subject) => builder.subject(subject.clone()),
            IdentityKind::GitHub {
                repository,
                workflow_path,
                git_refs,
                range,
                tag_prefix,
            } => {
                builder.repository = Some(repository.clone());
                builder.workflow_path = workflow_path.clone();
                builder.git_refs = git_refs.clone();
                builder.range = range.clone().map(Ok);
                builder.tag_prefix = tag_prefix.clone();
                builder
            }
        }
    }

    /// Required exact OIDC issuer URI.
    pub fn oidc_issuer(&self) -> &str {
        &self.issuer
    }

    /// Exact SAN, if this is an exact URI/email identity.
    pub fn subject(&self) -> Option<&str> {
        match &self.kind {
            IdentityKind::Exact(subject) => Some(subject),
            _ => None,
        }
    }

    /// Canonical GitHub repository URI, if this is a workflow identity.
    pub fn repository(&self) -> Option<&str> {
        match &self.kind {
            IdentityKind::GitHub { repository, .. } => Some(repository),
            _ => None,
        }
    }

    /// Pinned workflow path, if this is a workflow identity.
    pub fn workflow_path(&self) -> Option<&str> {
        match &self.kind {
            IdentityKind::GitHub { workflow_path, .. } => Some(workflow_path),
            _ => None,
        }
    }

    /// Exact allowed refs. A version range, when present, is an additional way
    /// to authorize a ref, not an additional restriction on these exact refs.
    pub fn allowed_git_refs(&self) -> &[String] {
        match &self.kind {
            IdentityKind::GitHub { git_refs, .. } => git_refs,
            _ => &[],
        }
    }

    /// Parsed release-tag requirement, using Cargo-style semver semantics.
    pub fn semver_range(&self) -> Option<&VersionReq> {
        match &self.kind {
            IdentityKind::GitHub { range, .. } => range.as_ref(),
            _ => None,
        }
    }

    /// Literal prefix stripped from release tags before parsing their version.
    pub fn tag_prefix(&self) -> Option<&str> {
        match &self.kind {
            IdentityKind::GitHub { tag_prefix, .. } => Some(tag_prefix),
            _ => None,
        }
    }

    /// Compare a subject and issuer against this policy. This only evaluates
    /// expectations; it does not authenticate a certificate or signature.
    pub fn matches(&self, subject: &str, issuer: &str) -> bool {
        if issuer != self.issuer {
            return false;
        }
        match &self.kind {
            IdentityKind::Exact(expected) => subject == expected,
            IdentityKind::GitHub {
                repository,
                workflow_path,
                ..
            } => {
                let Some((workflow, git_ref)) = subject.rsplit_once('@') else {
                    return false;
                };
                workflow
                    .strip_prefix(repository)
                    .and_then(|rest| rest.strip_prefix('/'))
                    == Some(workflow_path.as_str())
                    && self.allows_git_ref(git_ref)
            }
        }
    }

    pub(crate) fn allows_git_ref(&self, git_ref: &str) -> bool {
        let IdentityKind::GitHub {
            git_refs,
            range,
            tag_prefix,
            ..
        } = &self.kind
        else {
            return false;
        };
        if !valid_ref(git_ref) {
            return false;
        }
        git_refs.iter().any(|r| r == git_ref)
            || range.as_ref().is_some_and(|requirement| {
                git_ref
                    .strip_prefix("refs/tags/")
                    .and_then(|tag| tag.strip_prefix(tag_prefix))
                    .and_then(|version| Version::parse(version).ok())
                    .is_some_and(|version| requirement.matches(&version))
            })
    }

    pub(crate) fn workflow_identity(&self, git_ref: &str) -> String {
        match &self.kind {
            IdentityKind::GitHub {
                repository,
                workflow_path,
                ..
            } => {
                format!("{repository}/{workflow_path}@{git_ref}")
            }
            IdentityKind::Exact(subject) => subject.clone(),
        }
    }
}

/// Builder for [`Identity`]. Values are owned and validated by [`Self::build`].
/// Exact subjects and structured workflow configuration cannot be mixed.
#[derive(Clone, Debug)]
#[must_use]
pub struct IdentityBuilder {
    subject: Option<String>,
    repository: Option<String>,
    workflow_path: String,
    git_refs: Vec<String>,
    range: Option<Result<VersionReq>>,
    tag_prefix: String,
    issuer: String,
}

impl Default for IdentityBuilder {
    fn default() -> Self {
        Self {
            subject: None,
            repository: None,
            workflow_path: ".github/workflows/release.yml".into(),
            git_refs: Vec::new(),
            range: None,
            tag_prefix: "v".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
        }
    }
}

impl IdentityBuilder {
    /// Require an exact certificate SAN (URI or email), without pattern matching.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Pin `owner/repo` or a canonical `https://github.com/owner/repo` URL.
    pub fn repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = Some(repository.into());
        self
    }

    /// Pin a workflow file in `.github/workflows/` in the same repository/ref.
    pub fn workflow_path(mut self, path: impl Into<String>) -> Self {
        self.workflow_path = path.into();
        self
    }

    /// Replace all ref constraints, including a semver range, with one exact ref.
    pub fn git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_refs = alloc::vec![git_ref.into()];
        self.range = None;
        self
    }

    /// Add an exact ref as an alternative to the existing refs/range. At most
    /// 32 exact refs may be supplied; duplicates are removed during validation.
    pub fn allow_git_ref(mut self, git_ref: impl Into<String>) -> Self {
        self.git_refs.push(git_ref.into());
        self
    }

    /// Replace ref constraints with an exact `refs/tags/<tag>`.
    pub fn release_tag(self, tag: impl AsRef<str>) -> Self {
        self.git_ref(format!("refs/tags/{}", tag.as_ref()))
    }

    /// Replace ref constraints with an exact `refs/heads/<branch>`.
    pub fn branch(self, branch: impl AsRef<str>) -> Self {
        self.git_ref(format!("refs/heads/{}", branch.as_ref()))
    }

    /// Replace ref constraints with a Cargo-style requirement, e.g. `^1.2` or
    /// `>=1.2.0, <2.0.0`. Only `refs/tags/` refs qualify. Prereleases require an
    /// explicit matching prerelease comparator; build metadata is ignored.
    /// Requirements must be nonempty and at most 1024 bytes.
    pub fn semver_range(mut self, requirement: impl Into<String>) -> Self {
        let requirement = requirement.into();
        self.range = Some(
            if requirement.trim().is_empty() || requirement.len() > 1024 {
                Err(Error::Policy)
            } else {
                VersionReq::parse(&requirement).map_err(|_| Error::Policy)
            },
        );
        self.git_refs.clear();
        self
    }

    /// Set the literal release-tag prefix (default `v`). Use `""` for unprefixed
    /// tags, or e.g. `releases/v` for nested tags. No prefix is inferred.
    pub fn tag_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.tag_prefix = prefix.into();
        self
    }

    /// Require an exact OIDC issuer URI (GitHub Actions by default).
    pub fn oidc_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Validate configuration. Missing or ambiguous subjects, malformed GitHub
    /// pins, refs, issuer URIs, or semver requirements return [`Error::Policy`].
    pub fn build(self) -> Result<Identity> {
        if !valid_issuer(&self.issuer) {
            return Err(Error::Policy);
        }
        let kind = if let Some(subject) = self.subject {
            if subject.is_empty()
                || subject.len() > 2048
                || !subject.bytes().all(|b| b.is_ascii_graphic())
                || self.repository.is_some()
                || !self.git_refs.is_empty()
                || self.range.is_some()
                || self.workflow_path != ".github/workflows/release.yml"
                || self.tag_prefix != "v"
            {
                return Err(Error::Policy);
            }
            IdentityKind::Exact(subject)
        } else {
            let input = self.repository.ok_or(Error::Policy)?;
            let repository = input.strip_prefix("https://github.com/").unwrap_or(&input);
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
            let file = self
                .workflow_path
                .strip_prefix(".github/workflows/")
                .ok_or(Error::Policy)?;
            if file.starts_with('.')
                || ![".yml", ".yaml"].iter().any(|s| file.ends_with(s))
                || self.workflow_path.len() > 255
                || !file
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || (self.git_refs.is_empty() && self.range.is_none())
                || self.git_refs.len() > 32
                || self.git_refs.iter().any(|r| !valid_ref(r))
                || !valid_ref(&format!("refs/tags/{}0.0.0", self.tag_prefix))
            {
                return Err(Error::Policy);
            }
            let range = self.range.transpose()?;
            let mut git_refs = self.git_refs;
            git_refs.sort();
            git_refs.dedup();
            IdentityKind::GitHub {
                repository: format!("https://github.com/{repository}"),
                workflow_path: self.workflow_path,
                git_refs,
                range,
                tag_prefix: self.tag_prefix,
            }
        };
        Ok(Identity {
            issuer: self.issuer,
            kind,
        })
    }
}

pub(crate) fn valid_ref(git_ref: &str) -> bool {
    git_ref.starts_with("refs/")
        && git_ref.len() <= 512
        && git_ref.split('/').count() >= 3
        && git_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/+".contains(&b))
        && !git_ref.contains("..")
        && git_ref.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('.') && !p.ends_with('.') && !p.ends_with(".lock")
        })
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
