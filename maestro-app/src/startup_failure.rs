//! Pure presentation for a foreground product launch that failed before renderer startup.
//! This supplies text only: no retry, daemon replacement, or retained-session mutation.

#[derive(Debug, PartialEq, Eq)]
pub struct StartupFailureDialog {
    pub title: &'static str,
    pub message: String,
}

pub fn startup_failure_dialog(
    product_startup: bool,
    no_run_renderer: bool,
    detach_renderer: bool,
    error_kind: &str,
    reason: &str,
) -> Option<StartupFailureDialog> {
    if !product_startup || no_run_renderer || detach_renderer {
        return None;
    }
    let (summary, outcome) = match error_kind {
        "daemon_probe_failed" | "stale_daemon" => (
            "Hydra could not connect to its retained terminal service.",
            "The retained daemon and its sessions were left untouched. No replacement daemon was started.",
        ),
        "daemon_spawn_failed" | "daemon_unreachable" => (
            "Hydra could not start its terminal service.",
            "No terminal session was opened by this launch.",
        ),
        _ => return None,
    };
    // Native labels are plain text, not markup. Represent an embedded NUL visibly rather than
    // passing an invalid C string into a platform toolkit; the structured failure stays unchanged.
    let reason = reason.replace('\0', "\u{fffd}");
    Some(StartupFailureDialog {
        title: "Hydra could not open",
        message: format!("{summary}\n\n{reason}\n\n{outcome}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [&str; 4] = [
        "daemon_probe_failed",
        "stale_daemon",
        "daemon_spawn_failed",
        "daemon_unreachable",
    ];

    #[test]
    fn only_foreground_product_startup_presents_each_supported_failure() {
        for kind in KINDS {
            for product in [false, true] {
                for headless in [false, true] {
                    for detached in [false, true] {
                        assert_eq!(
                            startup_failure_dialog(product, headless, detached, kind, "reason")
                                .is_some(),
                            product && !headless && !detached,
                            "{kind}: product={product}, headless={headless}, detached={detached}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unrelated_and_similar_error_kinds_never_open_a_dialog() {
        for kind in [
            "",
            "bad_usage",
            "binary_not_found",
            "product_startup_failed",
            "session_start_failed",
            "renderer_failed",
            "daemon_probe_failed_extra",
        ] {
            assert!(startup_failure_dialog(true, false, false, kind, "reason").is_none());
        }
    }

    #[test]
    fn retained_failures_explain_preservation_without_promising_recovery() {
        for kind in &KINDS[..2] {
            let dialog =
                startup_failure_dialog(true, false, false, kind, "identity timed out").unwrap();
            assert_eq!(dialog.title, "Hydra could not open");
            assert!(dialog.message.contains("identity timed out"));
            assert!(dialog
                .message
                .contains("The retained daemon and its sessions were left untouched."));
            assert!(dialog
                .message
                .contains("No replacement daemon was started."));
        }
    }

    #[test]
    fn fresh_failures_do_not_claim_a_retained_daemon_exists() {
        for kind in &KINDS[2..] {
            let dialog =
                startup_failure_dialog(true, false, false, kind, "exit status: 1").unwrap();
            assert!(dialog.message.contains("exit status: 1"));
            assert!(dialog
                .message
                .contains("No terminal session was opened by this launch."));
            assert!(!dialog.message.contains("retained"));
            assert!(!dialog.message.contains("replacement"));
        }
    }

    #[test]
    fn native_reason_is_plain_text_with_unicode_and_line_breaks_preserved() {
        let reason = "could not probe <daemon> & reply: bağlantı\nsecond line";
        let dialog = startup_failure_dialog(true, false, false, KINDS[0], reason).unwrap();
        assert!(dialog.message.contains(reason));
    }

    #[test]
    fn embedded_nul_is_visible_without_changing_the_original_reason() {
        let reason = "build\0version";
        let dialog = startup_failure_dialog(true, false, false, KINDS[1], reason).unwrap();
        assert!(dialog.message.contains("build\u{fffd}version"));
        assert!(!dialog.message.contains('\0'));
        assert_eq!(reason, "build\0version");
    }
}
