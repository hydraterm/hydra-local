//! Conservative, secret-aware redaction for ad-hoc launch arguments.
//!
//! Raw argv may carry secrets (`--api-key=sk-...`, a bearer token, a long high-entropy blob).
//! Persisting it verbatim would write secrets to a `0600` file and risk a silent replay on
//! restart. So an ad-hoc launch is redacted before it is ever stored, and if ANYTHING was
//! redacted the resulting `LaunchSpec::AdHocRedacted` carries `restart_requires_user = true`
//! so the shell prompts for the real values instead of replaying placeholders.
//!
//! Redaction is deliberately CONSERVATIVE: over-redacting (forcing a prompt on a benign flag)
//! is acceptable; under-redacting (leaking a secret to disk) is not.

use crate::records::LaunchSpec;

/// The placeholder substituted for a redacted secret value.
const PLACEHOLDER: &str = "<redacted>";

/// Result of redacting an argv: the sanitized tokens plus whether any redaction occurred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedLaunch {
    pub argv: Vec<String>,
    pub redacted_any: bool,
}

/// Flag names whose VALUE is treated as a secret. Matched case-insensitively against the part
/// before `=` (for `--flag=value`) or against a standalone flag whose following token is then
/// redacted. Kept broad on purpose.
const SECRET_FLAG_SUBSTRINGS: &[&str] = &[
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
    "apikey",
    "api-key",
    "access-key",
    "private",
    "bearer",
    "session",
];

/// Does this flag NAME (the bit before any `=`, leading dashes stripped) look secret-bearing?
fn flag_name_is_secret(name: &str) -> bool {
    let lname = name.trim_start_matches('-').to_ascii_lowercase();
    SECRET_FLAG_SUBSTRINGS.iter().any(|s| lname.contains(s))
}

/// Does a bare VALUE token look like a secret on its own (no flag context)? Conservative:
/// flags a long, high-entropy-ish run with no spaces, or common secret prefixes. This catches a
/// secret passed positionally without a recognizable flag.
fn value_looks_secret(value: &str) -> bool {
    // Common credential prefixes.
    const PREFIXES: &[&str] = &[
        "sk-", "pk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA", "Bearer ",
    ];
    if PREFIXES.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    // A long token mixing letters and digits with no whitespace is likely a key/hash.
    let len = value.len();
    if len >= 24 && !value.contains(char::is_whitespace) {
        let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
        let has_digit = value.chars().any(|c| c.is_ascii_digit());
        if has_alpha && has_digit {
            return true;
        }
    }
    false
}

/// Redact secret-shaped material from an argv. Handles three shapes:
/// 1. `--flag=value` where `flag` looks secret -> value replaced, key kept.
/// 2. `--flag value` where `flag` looks secret -> the NEXT token replaced.
/// 3. a bare token that itself looks like a secret -> replaced.
pub fn redact_args(argv: &[String]) -> RedactedLaunch {
    let mut out: Vec<String> = Vec::with_capacity(argv.len());
    let mut redacted_any = false;
    let mut redact_next = false;

    for tok in argv {
        if redact_next {
            out.push(PLACEHOLDER.to_string());
            redacted_any = true;
            redact_next = false;
            continue;
        }

        if let Some(eq) = tok.find('=') {
            let (name, _value) = tok.split_at(eq);
            if flag_name_is_secret(name) {
                out.push(format!("{name}={PLACEHOLDER}"));
                redacted_any = true;
                continue;
            }
        }

        // A standalone secret-bearing flag redacts the following value token.
        if tok.starts_with('-') && flag_name_is_secret(tok) {
            out.push(tok.clone());
            redact_next = true;
            continue;
        }

        // A bare value that looks like a secret on its own.
        if !tok.starts_with('-') && value_looks_secret(tok) {
            out.push(PLACEHOLDER.to_string());
            redacted_any = true;
            continue;
        }

        out.push(tok.clone());
    }

    RedactedLaunch {
        argv: out,
        redacted_any,
    }
}

/// Build an ad-hoc `LaunchSpec` from a raw argv, redacting first. If anything was redacted the
/// spec is flagged so restart-from-record will NOT silently replay it — the shell must prompt
/// the user to re-supply the redacted values. Even when nothing matched, the ad-hoc tier still
/// requires user confirmation on restart, because heuristic redaction can miss novel secret
/// shapes; only a `KnownSafe` spec earns one-click restart.
pub fn adhoc_launch_spec(argv: &[String]) -> LaunchSpec {
    let red = redact_args(argv);
    LaunchSpec::AdHocRedacted {
        argv: red.argv,
        redacted: red.redacted_any,
        restart_requires_user: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redacts_inline_key_value_keeps_flag_name() {
        let r = redact_args(&v(&["mytool", "--api-key=sk-secret123", "--verbose"]));
        assert_eq!(r.argv, v(&["mytool", "--api-key=<redacted>", "--verbose"]));
        assert!(r.redacted_any);
    }

    #[test]
    fn redacts_separated_secret_value() {
        let r = redact_args(&v(&["mytool", "--token", "abc123def456", "next"])); // gitleaks:allow -- synthetic redaction fixture
        assert_eq!(r.argv, v(&["mytool", "--token", "<redacted>", "next"]));
        assert!(r.redacted_any);
    }

    #[test]
    fn redacts_bare_high_entropy_value() {
        let r = redact_args(&v(&["deploy", "sk-livexyz0123456789abcdefGHIJ"]));
        assert_eq!(r.argv[0], "deploy");
        assert_eq!(r.argv[1], "<redacted>");
        assert!(r.redacted_any);
    }

    #[test]
    fn leaves_benign_args_untouched() {
        let r = redact_args(&v(&["claude", "--model", "opus", "--verbose"]));
        assert_eq!(r.argv, v(&["claude", "--model", "opus", "--verbose"]));
        assert!(!r.redacted_any);
    }

    #[test]
    fn adhoc_spec_always_requires_user_on_restart() {
        // Even a benign-looking ad-hoc command never earns silent restart.
        let spec = adhoc_launch_spec(&v(&["echo", "hello"]));
        match spec {
            LaunchSpec::AdHocRedacted {
                restart_requires_user,
                redacted,
                ..
            } => {
                assert!(
                    restart_requires_user,
                    "ad-hoc restart must require the user"
                );
                assert!(!redacted, "nothing secret-shaped here");
            }
            other => panic!("expected AdHocRedacted, got {other:?}"),
        }
    }

    #[test]
    fn adhoc_spec_flags_redaction_when_secret_present() {
        let spec = adhoc_launch_spec(&v(&["tool", "--password=hunter2longenough123"]));
        match spec {
            LaunchSpec::AdHocRedacted {
                argv,
                redacted,
                restart_requires_user,
            } => {
                assert!(redacted);
                assert!(restart_requires_user);
                assert!(argv.iter().any(|a| a.contains("<redacted>")));
                assert!(
                    !argv.iter().any(|a| a.contains("hunter2")),
                    "the secret value must not survive into the persisted argv"
                );
            }
            other => panic!("expected AdHocRedacted, got {other:?}"),
        }
    }
}
