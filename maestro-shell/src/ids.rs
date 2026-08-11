//! Filesystem-id validation for any identifier that becomes a path component.
//!
//! Record ids, workspace ids, and session ids are concatenated into app-support paths
//! (`<base>/<kind>/<id>.json`, `<base>/scratch/<session>`, `<base>/worktrees/<ws>/<session>`).
//! A raw id like `../../etc`, `a/b`, or an absolute path would let a caller escape the
//! intended directory. So every id that lands in a path is validated FIRST and rejected if it
//! is anything other than a conservative, single-component token.
//!
//! The allowed alphabet — ASCII alphanumerics plus `-` and `_` — is a strict subset of "safe
//! single path component on every supported filesystem": it contains no separator (`/`, `\`),
//! no `.` (so `.`/`..` are impossible), no whitespace, no drive/colon syntax, and no shell
//! metacharacters. UUIDv4 (the shell's id format) is a subset of this alphabet, so legitimate
//! ids always pass.

/// Maximum id length. Generous next to a UUIDv4 (36 chars) but bounded so a pathological id
/// cannot blow past filesystem name limits.
pub const MAX_ID_LEN: usize = 128;

/// Why an id was rejected as unsafe for use in a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdError {
    /// The id was empty.
    Empty,
    /// The id exceeded `MAX_ID_LEN`.
    TooLong { len: usize, max: usize },
    /// The id contained a byte outside `[A-Za-z0-9_-]`. `ch` is the first offender.
    IllegalChar { ch: char },
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdError::Empty => write!(f, "id is empty"),
            IdError::TooLong { len, max } => {
                write!(f, "id length {len} exceeds maximum {max}")
            }
            IdError::IllegalChar { ch } => write!(
                f,
                "id contains illegal character {ch:?}; only [A-Za-z0-9_-] are allowed"
            ),
        }
    }
}

impl std::error::Error for IdError {}

/// Is `c` allowed in a filesystem id? ASCII alphanumeric, `-`, or `_` only.
fn is_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Validate an id for use as a single path component. Returns the id unchanged on success so
/// it can be used inline (`validate_id(id)?`), or an `IdError` describing the first problem.
///
/// Rejects: empty, over-length, and any id containing a path separator, `.`/`..`, whitespace,
/// absolute-path or drive syntax, or any other punctuation — all of which fall outside the
/// `[A-Za-z0-9_-]` alphabet and so are caught by the per-char check.
pub fn validate_id(id: &str) -> Result<&str, IdError> {
    if id.is_empty() {
        return Err(IdError::Empty);
    }
    if id.len() > MAX_ID_LEN {
        return Err(IdError::TooLong {
            len: id.len(),
            max: MAX_ID_LEN,
        });
    }
    if let Some(ch) = id.chars().find(|c| !is_allowed(*c)) {
        return Err(IdError::IllegalChar { ch });
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_uuid_and_simple_tokens() {
        for ok in [
            "550e8400-e29b-41d4-a716-446655440000",
            "abc",
            "ABC_123",
            "a-b_c-1",
            "p1",
        ] {
            assert_eq!(validate_id(ok), Ok(ok), "{ok:?} should be accepted");
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_id(""), Err(IdError::Empty));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(MAX_ID_LEN + 1);
        assert_eq!(
            validate_id(&long),
            Err(IdError::TooLong {
                len: MAX_ID_LEN + 1,
                max: MAX_ID_LEN
            })
        );
    }

    #[test]
    fn rejects_traversal_and_separators() {
        // Each of these would, unchecked, escape or split the intended directory.
        for bad in [
            "..",
            ".",
            "../x",
            "a/b",
            "a\\b",
            "/abs",
            "./rel",
            "a/../b",
            "..\\..\\x",
        ] {
            assert!(
                matches!(validate_id(bad), Err(IdError::IllegalChar { .. })),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_whitespace_and_punctuation() {
        for bad in [
            "a b", "a\tb", "a\nb", "a.b", "a:b", "a;b", "a*b", "a|b", "a$b",
        ] {
            assert!(
                matches!(validate_id(bad), Err(IdError::IllegalChar { .. })),
                "{bad:?} must be rejected"
            );
        }
    }
}
