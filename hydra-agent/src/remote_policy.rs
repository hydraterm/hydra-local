//! S4 — session-access policy. Decides whether an authenticated remote device may LIST / ATTACH a given
//! session. Two inputs combine:
//!
//!   1. The TOKEN scope (from `TokenClaims`): if the token carries a `session_id`, it is bound to exactly
//!      that session — attach to any other session is refused (least privilege; this is the path browser
//!      links will use). If it carries no `session_id`, it's an account/device-scoped token and the
//!      ownership policy below applies.
//!   2. The OWNERSHIP policy: the prototype policy is "same-as-local" — an authorized account/device may
//!      reach the same sessions the local user can. It is a HOOK (`SessionPolicy`) so we can later
//!      restrict by project / session / device WITHOUT reworking the bridge.
//!
//! No terminal bytes here — this is pure authorization over ids.

use crate::remote_token::TokenClaims;

/// A pluggable ownership policy. The prototype impl grants all local sessions; a future impl can scope by
/// project/device. Kept tiny + sync so the bridge can call it per attach/list cheaply.
pub trait SessionPolicy {
    /// May this account/device list sessions at all?
    fn may_list(&self, account_id: &str, device_id: &str) -> bool;
    /// May this account/device attach to `session_id` (ownership only — token-scope is checked separately)?
    fn may_attach(&self, account_id: &str, device_id: &str, session_id: &str) -> bool;
}

/// Prototype policy: an authenticated account/device may reach the same sessions as the local user (i.e.
/// any session the daemon exposes). Structured so a later policy can deny by project/session/device.
pub struct SameAsLocalPolicy;

impl SessionPolicy for SameAsLocalPolicy {
    fn may_list(&self, _account_id: &str, _device_id: &str) -> bool {
        true
    }
    fn may_attach(&self, _account_id: &str, _device_id: &str, _session_id: &str) -> bool {
        true
    }
}

/// Why an access decision was denied (bounded; mapped to a wire `error`/`auth_refused` reason).
#[derive(Debug, PartialEq, Eq)]
pub enum AccessDenied {
    /// The token is session-scoped and the requested session isn't the bound one.
    SessionScopeMismatch,
    /// The ownership policy denied it.
    PolicyDenied,
}

/// Decide ATTACH: combine the token scope with the ownership policy.
pub fn can_attach(
    claims: &TokenClaims,
    policy: &dyn SessionPolicy,
    session_id: &str,
) -> Result<(), AccessDenied> {
    // 1. session-scoped token → exact match required.
    if let Some(bound) = &claims.session_id {
        if bound != session_id {
            return Err(AccessDenied::SessionScopeMismatch);
        }
    }
    // 2. ownership policy.
    if policy.may_attach(&claims.account_id, &claims.device_id, session_id) {
        Ok(())
    } else {
        Err(AccessDenied::PolicyDenied)
    }
}

/// Decide LIST. A session-scoped token MAY still list (so a browser link can confirm its one session),
/// but the bridge filters the returned list to the bound session (caller's responsibility, see bridge).
pub fn can_list(claims: &TokenClaims, policy: &dyn SessionPolicy) -> Result<(), AccessDenied> {
    if policy.may_list(&claims.account_id, &claims.device_id) {
        Ok(())
    } else {
        Err(AccessDenied::PolicyDenied)
    }
}

/// Filter a session-id list for what a token may SEE: a session-scoped token sees only its bound session;
/// otherwise all (subject to may_attach for finer policies).
pub fn visible_sessions<'a>(
    claims: &TokenClaims,
    policy: &dyn SessionPolicy,
    all: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    all.into_iter()
        .filter(|s| {
            if let Some(bound) = &claims.session_id {
                if bound != s {
                    return false;
                }
            }
            policy.may_attach(&claims.account_id, &claims.device_id, s)
        })
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(session: Option<&str>) -> TokenClaims {
        TokenClaims {
            account_id: "acct".into(),
            device_id: "dev_a".into(),
            session_id: session.map(|s| s.to_string()),
            signal_session_id: None,
            target_device_id: None,
            browser_pubkey: None,
            browser_pubkey_alg: None,
            refresh_parent_sha256: None,
            iat_ms: 0,
            exp_ms: 1_000_000,
        }
    }

    #[test]
    fn account_scoped_token_may_attach_any_session_under_same_as_local() {
        let c = claims(None);
        assert_eq!(can_attach(&c, &SameAsLocalPolicy, "s1"), Ok(()));
        assert_eq!(can_attach(&c, &SameAsLocalPolicy, "s2"), Ok(()));
    }

    #[test]
    fn session_scoped_token_only_attaches_its_bound_session() {
        let c = claims(Some("s1"));
        assert_eq!(can_attach(&c, &SameAsLocalPolicy, "s1"), Ok(()));
        assert_eq!(
            can_attach(&c, &SameAsLocalPolicy, "s2"),
            Err(AccessDenied::SessionScopeMismatch)
        );
    }

    #[test]
    fn list_visibility_respects_session_scope() {
        let all = ["s1", "s2", "s3"];
        let unscoped = visible_sessions(&claims(None), &SameAsLocalPolicy, all);
        assert_eq!(unscoped, vec!["s1", "s2", "s3"]);
        let scoped = visible_sessions(&claims(Some("s2")), &SameAsLocalPolicy, all);
        assert_eq!(scoped, vec!["s2"]);
    }

    #[test]
    fn a_restrictive_policy_can_deny_even_an_unscoped_token() {
        struct DenyAll;
        impl SessionPolicy for DenyAll {
            fn may_list(&self, _: &str, _: &str) -> bool {
                false
            }
            fn may_attach(&self, _: &str, _: &str, _: &str) -> bool {
                false
            }
        }
        assert_eq!(
            can_attach(&claims(None), &DenyAll, "s1"),
            Err(AccessDenied::PolicyDenied)
        );
        assert_eq!(
            can_list(&claims(None), &DenyAll),
            Err(AccessDenied::PolicyDenied)
        );
        // proves the hook can tighten later by project/session/device.
    }
}
