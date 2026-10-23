use core::fmt;

/// Verification failure. No partially verified data is returned on failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Missing or invalid policy builder configuration.
    Policy,
    /// Input exceeds a documented resource limit.
    Limit,
    /// Malformed JSON, base64, DER, or an ambiguous repeated field.
    Encoding,
    /// A bundle, algorithm, or certificate feature is outside the supported profile.
    Unsupported,
    /// No supplied authority authenticates the signature at its signed time.
    Trust,
    /// A signature does not verify.
    Signature,
    /// Timestamp contents do not authenticate the artifact signature.
    Timestamp,
    /// The certificate or signed provenance does not match the requested release.
    Identity,
    /// The signed statement does not contain the requested artifact name and digest.
    Artifact,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Policy => "missing or invalid verification policy configuration",
            Self::Limit => "verification input exceeds a resource limit",
            Self::Encoding => "invalid or ambiguous encoding",
            Self::Unsupported => "unsupported verification profile",
            Self::Trust => "no trusted certificate chain valid at the signed time",
            Self::Signature => "invalid signature",
            Self::Timestamp => "invalid signature timestamp",
            Self::Identity => "release identity does not match policy",
            Self::Artifact => "artifact name or SHA-256 digest does not match",
        })
    }
}

impl core::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Self::Encoding
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Encoding
    }
}

pub(crate) type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use alloc::{collections::BTreeSet, string::ToString};

    #[test]
    fn every_error_has_a_distinct_message() {
        let messages: BTreeSet<_> = [
            Error::Policy,
            Error::Limit,
            Error::Encoding,
            Error::Unsupported,
            Error::Trust,
            Error::Signature,
            Error::Timestamp,
            Error::Identity,
            Error::Artifact,
        ]
        .iter()
        .map(|error| {
            let message = error.to_string();
            assert!(!message.is_empty(), "{error:?}");
            message
        })
        .collect();
        assert_eq!(messages.len(), 9);
        assert_eq!(Error::Signature.to_string(), "invalid signature");
    }
}
