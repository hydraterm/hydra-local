//! macOS launchd plist generator. PURE: turns resolved options into the
//! `com.hydra.agent.plist` XML string. It NEVER writes files, calls `launchctl`, expands `~`, or reads the
//! environment — the caller resolves absolute paths and passes them in (keeps this unit-testable + golden-
//! stable). The plist invokes `supervise`; it carries no cloud trust. The
//! private agent binary owns that tuple at compile time.
//!
//! Local service contract:
//!   <binary> supervise --attach-daemon-only --sock <socket> [--sessions <id[,id...]>]
//! identity (cloud_base/device_id/account) auto-loads from device.json — never passed here, never a secret.

/// Compatibility names for code that renders binding metadata. They are aliases
/// of the compile-time private-agent tuple, never runtime defaults.
pub const DEFAULT_CLOUD_PUBKEY: &str = crate::release_trust::CLOUD_PUBKEY;
pub const DEFAULT_CLOUD_BASE: &str = crate::release_trust::CLOUD_BASE;
pub const DEFAULT_ALLOWED_ORIGIN: &str = crate::release_trust::ALLOWED_ORIGIN;
/// Frozen responsible-code association for macOS privacy consent inherited by the launch agent.
///
/// This is intentionally not configurable: changing it is an identity migration, not an
/// environment setting.
pub const ASSOCIATED_BUNDLE_IDENTIFIER: &str = "com.hydraterms.hydra";

/// Options for the launchd user-agent plist. All paths are ABSOLUTE + already resolved by the caller (no `~`,
/// no env lookups in this module).
#[derive(Debug, Clone)]
pub struct LaunchdPlistOptions {
    /// launchd job label, e.g. `com.hydra.agent`.
    pub label: String,
    /// Absolute path to the installed `hydra-agent` binary (NOT a repo `target/debug` path for real installs).
    pub binary_path: String,
    /// Public build identity embedded in the definition so an in-place binary upgrade makes the
    /// generated service differ and triggers one controlled restart.
    pub build_stamp: String,
    /// The independently retained pty-daemon Unix socket the agent attaches to.
    pub socket_path: String,
    /// Sessions to ensure exist (default `["s1"]`).
    pub sessions: Vec<String>,
    /// Absolute log directory (e.g. `~/Library/Logs/Hydra` resolved by the caller).
    pub log_dir: String,
    /// The user's home directory, emitted as `HOME` in the plist's EnvironmentVariables. launchd user-agents do NOT
    /// inherit `HOME`, so without this the agent's `default_agent_dir()` (which resolves via `$HOME/.local/share`)
    /// falls back to a cwd-relative `./hydra-agent` and CANNOT find the enrolled `device.json` — remote-peer then dies
    /// with "requires --cloud". Setting HOME is what lets the agent locate its enrollment record under launchd.
    pub home_dir: String,
    /// The reviewed desktop app support directory used for content/resource records.
    pub maestro_app_support_dir: String,
}

/// Escape the five XML special chars so paths/labels with `& < > " '` can't break (or inject into) the plist.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render the `<string>…</string>` arg lines of `ProgramArguments`, escaped + indented for the plist.
fn program_arguments(opts: &LaunchdPlistOptions) -> String {
    let mut args = vec![
        opts.binary_path.clone(),
        "supervise".to_string(),
        "--attach-daemon-only".to_string(),
    ];
    args.extend(["--sock".to_string(), opts.socket_path.clone()]);
    // E4: only emit `--sessions s1,s2` when sessions were explicitly configured; the default installed
    // service starts with NO pre-seeded sessions (the browser creates them on demand via New session).
    if !opts.sessions.is_empty() {
        args.push("--sessions".to_string());
        args.push(opts.sessions.join(","));
    }
    args.iter()
        .map(|a| format!("    <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Generate the full launchd user-agent plist. Deterministic for fixed options. No secrets.
pub fn generate_launchd_plist(opts: &LaunchdPlistOptions) -> String {
    let label = xml_escape(&opts.label);
    let out_log = xml_escape(&format!(
        "{}/agent.out.log",
        opts.log_dir.trim_end_matches('/')
    ));
    let err_log = xml_escape(&format!(
        "{}/agent.err.log",
        opts.log_dir.trim_end_matches('/')
    ));
    // Emit HOME so the agent's default_agent_dir() ($HOME/.local/share/hydra-agent) resolves under launchd (which does
    // NOT inherit HOME). Without it the agent can't find device.json → remote-peer dies "requires --cloud". Omitted
    // when home_dir is empty (keeps the dry-run/no-home path + prior goldens for callers that don't set it).
    let home_env = if opts.home_dir.is_empty() {
        String::new()
    } else {
        format!(
            "    <key>HOME</key>\n    <string>{}</string>\n",
            xml_escape(&opts.home_dir)
        )
    };
    let maestro_support_env = if opts.maestro_app_support_dir.is_empty() {
        String::new()
    } else {
        format!(
            "    <key>MAESTRO_APP_SUPPORT_DIR</key>\n    <string>{}</string>\n",
            xml_escape(&opts.maestro_app_support_dir)
        )
    };
    let build_stamp_env = if opts.build_stamp.is_empty() {
        String::new()
    } else {
        format!(
            "    <key>HYDRA_AGENT_BUILD_STAMP</key>\n    <string>{}</string>\n",
            xml_escape(&opts.build_stamp)
        )
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>AssociatedBundleIdentifiers</key>
  <array>
    <string>{associated_bundle_identifier}</string>
  </array>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>EnvironmentVariables</key>
  <dict>
{home_env}{maestro_support_env}{build_stamp_env}    <key>RUST_LOG</key>
    <string>hydra_agent=info</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{out_log}</string>
  <key>StandardErrorPath</key>
  <string>{err_log}</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"#,
        label = label,
        associated_bundle_identifier = ASSOCIATED_BUNDLE_IDENTIFIER,
        args = program_arguments(opts),
        home_env = home_env,
        maestro_support_env = maestro_support_env,
        build_stamp_env = build_stamp_env,
        out_log = out_log,
        err_log = err_log,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> LaunchdPlistOptions {
        LaunchdPlistOptions {
            label: "com.hydra.agent".to_string(),
            binary_path: "/usr/local/bin/hydra-agent".to_string(),
            build_stamp: "git-test@1700000000000".to_string(),
            socket_path: "/tmp/hydra-maestro-4242.sock".to_string(),
            sessions: vec!["s1".to_string()],
            log_dir: "/Users/test/Library/Logs/Hydra".to_string(),
            home_dir: "/Users/test/home".to_string(),
            maestro_app_support_dir: "/Users/test/Library/Application Support/Maestro-dev"
                .to_string(),
        }
    }

    #[test]
    fn golden_plist_for_fixed_options() {
        let plist = generate_launchd_plist(&opts());
        let expected = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.hydra.agent</string>
  <key>AssociatedBundleIdentifiers</key>
  <array>
    <string>com.hydraterms.hydra</string>
  </array>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/hydra-agent</string>
    <string>supervise</string>
    <string>--attach-daemon-only</string>
    <string>--sock</string>
    <string>/tmp/hydra-maestro-4242.sock</string>
    <string>--sessions</string>
    <string>s1</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/test/home</string>
    <key>MAESTRO_APP_SUPPORT_DIR</key>
    <string>/Users/test/Library/Application Support/Maestro-dev</string>
    <key>HYDRA_AGENT_BUILD_STAMP</key>
    <string>git-test@1700000000000</string>
    <key>RUST_LOG</key>
    <string>hydra_agent=info</string>
  </dict>
  <key>StandardOutPath</key>
  <string>/Users/test/Library/Logs/Hydra/agent.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/test/Library/Logs/Hydra/agent.err.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"#;
        assert_eq!(plist, expected);
    }

    #[test]
    fn xml_escapes_special_chars_in_paths_and_label() {
        let mut o = opts();
        o.label = "com.hydra.<agent> & \"co\"".to_string();
        o.binary_path = "/opt/My App/hydra-agent & tools".to_string();
        let plist = generate_launchd_plist(&o);
        // raw specials must NOT appear unescaped inside the rendered values
        assert!(plist.contains("com.hydra.&lt;agent&gt; &amp; &quot;co&quot;"));
        assert!(plist.contains("/opt/My App/hydra-agent &amp; tools"));
        assert!(!plist.contains("<agent>")); // the raw injected tag must be gone
    }

    #[test]
    fn multiple_sessions_join_with_comma() {
        let mut o = opts();
        o.sessions = vec!["s1".to_string(), "s2".to_string()];
        let plist = generate_launchd_plist(&o);
        assert!(plist.contains("<string>s1,s2</string>"));
    }

    #[test]
    fn service_definition_contains_no_runtime_trust_tuple() {
        let rendered = generate_launchd_plist(&opts());
        for forbidden in [
            "--environment",
            "--expected-cloud",
            "--cloud-pubkey",
            "--allowed-origin",
            DEFAULT_CLOUD_BASE,
            DEFAULT_ALLOWED_ORIGIN,
            DEFAULT_CLOUD_PUBKEY,
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn empty_sessions_omits_the_sessions_flag_e4() {
        // E4: the default installed service starts with NO pre-seeded sessions → no --sessions in the plist.
        let mut o = opts();
        o.sessions = vec![];
        let plist = generate_launchd_plist(&o);
        assert!(!plist.contains("--sessions"));
        // the rest of the supervise invocation is intact
        assert!(plist.contains("<string>supervise</string>"));
        assert!(plist.contains("<string>--sock</string>"));
    }

    #[test]
    fn contains_no_secrets() {
        let plist = generate_launchd_plist(&opts()).to_lowercase();
        for bad in [
            "token",
            "secret",
            "private",
            "device-key",
            "bearer",
            "password",
        ] {
            assert!(!plist.contains(bad), "plist must not contain {bad:?}");
        }
        assert!(!generate_launchd_plist(&opts()).contains(DEFAULT_CLOUD_PUBKEY));
    }

    #[test]
    fn invokes_the_supervise_subcommand_with_the_installed_binary() {
        let plist = generate_launchd_plist(&opts());
        assert!(plist.contains("<string>supervise</string>"));
        assert!(plist.contains("/usr/local/bin/hydra-agent"));
        assert!(!plist.contains("target/debug")); // real installs use the installed path
    }

    #[test]
    fn associates_exactly_one_frozen_responsible_bundle_identifier() {
        let plist = generate_launchd_plist(&opts());
        let expected = concat!(
            "<key>AssociatedBundleIdentifiers</key>\n",
            "  <array>\n",
            "    <string>com.hydraterms.hydra</string>\n",
            "  </array>"
        );
        assert!(plist.contains(expected));
        assert_eq!(
            plist
                .matches("<key>AssociatedBundleIdentifiers</key>")
                .count(),
            1
        );
        assert_eq!(
            plist
                .matches("<string>com.hydraterms.hydra</string>")
                .count(),
            1
        );
    }
}
