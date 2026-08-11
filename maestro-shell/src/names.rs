//! Name uniqueness: keep project/window/pane names unique within their scope by auto-numbering collisions.
//!
//! [`unique_name`] returns `desired` unchanged when it's free, else appends `" N"` (a space + the smallest free
//! integer ≥ 2) so the first name stays as-is and duplicates get a numbered variant. A trailing number IS treated as a
//! counter (threshold ≥ 1), matching the default `"Pane N"`/`"Window N"` names: `"Pane 1"` colliding becomes `"Pane 2"`
//! (bump the counter), not `"Pane 1 2"`. Rename-to-self is a no-op when the caller EXCLUDES the target's current value
//! from `existing`. Enforced at the backend write points so the local dashboard AND the remote browser both benefit.

use std::collections::HashSet;

/// Return `desired` if it doesn't collide with `existing`; otherwise the same base with the smallest free ` N` suffix.
/// Comparison is on trimmed values. See the module doc for the numbering rule.
pub fn unique_name(desired: &str, existing: &[String]) -> String {
    let desired = desired.trim();
    let taken: HashSet<&str> = existing.iter().map(|e| e.trim()).collect();
    if !taken.contains(desired) {
        return desired.to_string();
    }
    // Split a trailing " <digits>" (n ≥ 1) counter off the base so "Pane 1" bumps to "Pane 2" (not "Pane 1 2").
    let (base, start) = match trailing_counter(desired) {
        Some((base, n)) => (base, n + 1),
        None => (desired, 2),
    };
    let mut n = start;
    loop {
        let candidate = format!("{base} {n}");
        if !taken.contains(candidate.as_str()) {
            return candidate;
        }
        n += 1;
    }
}

/// If `s` ends in " <digits>" where the digits parse to n ≥ 1, return (base-without-suffix, n). The base keeps any
/// interior text ("Pane 1" → ("Pane", 1); "My Tab 3" → ("My Tab", 3); "Pane" → None; "Pane 0" → None since 0 < 1).
fn trailing_counter(s: &str) -> Option<(&str, u64)> {
    let idx = s.rfind(' ')?;
    let (base, rest) = (&s[..idx], &s[idx + 1..]);
    if base.is_empty() || rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = rest.parse().ok()?;
    if n >= 1 {
        Some((base, n))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn absent_name_returned_verbatim_and_trimmed() {
        assert_eq!(unique_name("Pane", &v(&["Other"])), "Pane");
        assert_eq!(unique_name("  Pane  ", &v(&["Other"])), "Pane"); // trimmed
        assert_eq!(unique_name("Pane", &[]), "Pane");
    }

    #[test]
    fn first_collision_appends_2() {
        assert_eq!(unique_name("Pane", &v(&["Pane"])), "Pane 2");
    }

    #[test]
    fn increments_to_next_free() {
        assert_eq!(unique_name("Pane", &v(&["Pane", "Pane 2"])), "Pane 3");
        assert_eq!(unique_name("Pane", &v(&["Pane", "Pane 3"])), "Pane 2"); // fills the gap
    }

    #[test]
    fn trailing_number_is_a_counter() {
        // "Pane 1" colliding bumps the counter to 2 (matches the default "Pane N" naming).
        assert_eq!(unique_name("Pane 1", &v(&["Pane 1"])), "Pane 2");
        assert_eq!(unique_name("Pane 1", &v(&["Pane 1", "Pane 2"])), "Pane 3");
        assert_eq!(unique_name("Pane 2", &v(&["Pane 2"])), "Pane 3");
    }

    #[test]
    fn multi_word_base_keeps_interior() {
        assert_eq!(unique_name("My Tab", &v(&["My Tab"])), "My Tab 2");
        assert_eq!(unique_name("My Tab 3", &v(&["My Tab 3"])), "My Tab 4");
    }

    #[test]
    fn zero_is_not_a_counter() {
        // "Pane 0" is a base name, not a counter → first collision is "Pane 0 2".
        assert_eq!(unique_name("Pane 0", &v(&["Pane 0"])), "Pane 0 2");
    }

    #[test]
    fn rename_to_self_is_noop_when_self_excluded() {
        // Caller excludes the target's OWN current value → no collision → unchanged.
        assert_eq!(unique_name("Pane 2", &v(&["Pane 1", "Pane 3"])), "Pane 2");
    }
}
