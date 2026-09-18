//! On-demand session creation (Slice E2). The `remote_control` channel owns protocol + auth policy; THIS
//! module owns the daemon side: id generation (random short ids, collision-checked), a `SessionCreator`
//! seam (so the daemon socket IO stays out of the sync message parser and is fakeable in tests), and the
//! orchestration that ties them together. Content-blind: only ids flow here; never terminal payload.
//!
//! Browser-provided launch context is metadata only: no free-form remote argv/command is accepted, but a
//! sanitized cwd can select the same project directory desktop uses. Specific-session resume is a structured
//! KnownSafe exception: an allowlisted agent plus an opaque id/path becomes a discrete argv vector through
//! `resume_launch`. The production remote adapter publishes that reviewed recipe through the daemon's exact
//! conditional-start ledger and waits for Grid proof; this module deliberately owns no raw wire producer.

use crate::resume_launch::{
    build_fresh_launch, build_resume_launch, ResumeAgent, ResumeDescriptor, ResumeLaunch,
};

/// Initial PTY geometry for a browser-created session.
///
/// Older browsers omit both dimensions, and unpaired/out-of-protocol dimensions must not create a
/// half-sized terminal. In either case the established 80×24 default is used. A valid browser
/// request is preserved exactly so the daemon creates the PTY at the viewed remote pane's size
/// instead of starting at 80×24 and correcting it after the first grid/history frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialTerminalSize {
    cols: u16,
    rows: u16,
}

impl InitialTerminalSize {
    pub const MIN_COLS: u16 = 2;
    pub const MIN_ROWS: u16 = 1;
    pub const MAX_COLS: u16 = 250;
    pub const MAX_ROWS: u16 = 100;
    pub const LEGACY: Self = Self { cols: 80, rows: 24 };

    pub fn from_optional_pair(cols: Option<u16>, rows: Option<u16>) -> Self {
        match (cols, rows) {
            (Some(cols), Some(rows))
                if (Self::MIN_COLS..=Self::MAX_COLS).contains(&cols)
                    && (Self::MIN_ROWS..=Self::MAX_ROWS).contains(&rows) =>
            {
                Self { cols, rows }
            }
            _ => Self::LEGACY,
        }
    }

    pub const fn cols(self) -> u16 {
        self.cols
    }

    pub const fn rows(self) -> u16 {
        self.rows
    }
}

impl Default for InitialTerminalSize {
    fn default() -> Self {
        Self::LEGACY
    }
}

/// Why a create failed → maps to the `session_create_error` code the browser sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateSessionError {
    /// The daemon channel is gone / send failed.
    DaemonUnavailable,
    /// Couldn't find a free id within the cap (too many sessions / unlucky collisions).
    LimitReached,
    /// A caller supplied an explicit provider outside the closed launch allowlist. This must never
    /// degrade to the bare-shell path: only an absent provider intentionally means "new terminal".
    UnsupportedProvider,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateSessionRequest {
    pub cwd: Option<String>,
    pub resume: Option<ResumeDescriptor>,
    /// Validated model NAME (see `remote_control::model_from_launch_flags`) — appended to providers with a
    /// typed `--model` contract as a discrete argv pair. Ignored for Amp (which exposes modes, not models) and
    /// when no launch is built (an agent-less create_session stays a bare shell).
    pub model: Option<String>,
    /// Provider capability toggle, already reduced to a boolean upstream. The exact allowlisted flag is selected
    /// from ResumeAgent; the browser never supplies raw dangerous argv.
    pub dangerous: bool,
    /// ALLOWLISTED agent for a FRESH launch (validated upstream and again in [`create_session`]).
    /// `None` intentionally means a bare shell. When no resume launch is built, the session starts as
    /// `<agent>` — the browser picked that agent explicitly, so the PTY must run it, not plain bash.
    pub agent: Option<String>,
}

impl CreateSessionError {
    pub fn code(&self) -> &'static str {
        match self {
            CreateSessionError::DaemonUnavailable => "daemon_unavailable",
            CreateSessionError::LimitReached => "limit_reached",
            CreateSessionError::UnsupportedProvider => "unsupported_provider",
        }
    }
}

/// The daemon side of session creation — injected so tests use a fake (no real socket). `remote_control`
/// holds a `&mut dyn SessionCreator` and calls `create()` only AFTER the auth/revoke gate.
pub trait SessionCreator {
    /// Session ids the daemon currently knows about (for collision-checking a fresh id).
    fn known_sessions(&self) -> Vec<String>;
    /// Start `session_id` through the implementation's authoritative daemon path. Production returns success only
    /// after exact conditional-start/Grid proof; fakes may implement the same logical boundary in memory.
    fn start_session(&mut self, session_id: &str, home: &str) -> Result<(), CreateSessionError>;
    /// Start a session with an optional validated KnownSafe resume launch. The default keeps existing fakes and
    /// non-resume creators fresh-session compatible.
    fn start_session_with_launch(
        &mut self,
        session_id: &str,
        home: &str,
        _launch: Option<&ResumeLaunch>,
    ) -> Result<(), CreateSessionError> {
        self.start_session(session_id, home)
    }
    /// Start with the browser's normalized initial geometry. The default deliberately delegates
    /// to the legacy method so existing local creators and test seams preserve their byte behavior.
    fn start_session_with_launch_and_size(
        &mut self,
        session_id: &str,
        home: &str,
        launch: Option<&ResumeLaunch>,
        _initial_size: InitialTerminalSize,
    ) -> Result<(), CreateSessionError> {
        self.start_session_with_launch(session_id, home, launch)
    }
    /// The home/cwd for new sessions when the request does not carry a valid project cwd.
    fn home(&self) -> String;
    /// Refreshable default cwd. Desktop/test implementations keep the historical cached value;
    /// a headless server overrides this to take one current passwd snapshot per create request.
    fn default_cwd(&self) -> Result<String, CreateSessionError> {
        Ok(self.home())
    }
    /// Max sessions allowed (cap so a runaway browser can't spawn unbounded shells).
    fn max_sessions(&self) -> usize {
        16
    }
}

/// Random short session id: `s-` + 6 lowercase base32-ish chars (no ambiguous chars). NOT sequential (a
/// counter races across reconnects/supervisor restarts). `rand_byte` is injected so tests are deterministic.
pub fn generate_session_id(mut rand_byte: impl FnMut() -> u8) -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789"; // 32 chars, no l/o/0/1
    let mut id = String::from("s-");
    for _ in 0..6 {
        id.push(ALPHABET[(rand_byte() as usize) % ALPHABET.len()] as char);
    }
    id
}

/// Pick an id not already in `known`, retrying up to `max_tries`. Returns None if every try collided (the
/// caller maps that to LimitReached). Pure + deterministic given the rng.
pub fn pick_unused_id(
    known: &[String],
    mut rand_byte: impl FnMut() -> u8,
    max_tries: usize,
) -> Option<String> {
    for _ in 0..max_tries {
        let id = generate_session_id(&mut rand_byte);
        if !known.iter().any(|k| k == &id) {
            return Some(id);
        }
    }
    None
}

/// Orchestrate a create: enforce the session cap, pick a fresh id, ask the daemon to start it, return the
/// id. Auth/revoke are already checked by the caller (`remote_control`). Uses OS randomness at runtime.
pub fn create_session(
    creator: &mut dyn SessionCreator,
    request: &CreateSessionRequest,
) -> Result<String, CreateSessionError> {
    create_session_with_initial_size(creator, request, InitialTerminalSize::default())
}

/// Remote-originated create with a viewport size that was normalized at the protocol boundary.
/// Keeping this separate from [`create_session`] preserves every existing local caller's legacy
/// 80×24 behavior without requiring local code to know about browser geometry.
pub fn create_session_with_initial_size(
    creator: &mut dyn SessionCreator,
    request: &CreateSessionRequest,
    initial_size: InitialTerminalSize,
) -> Result<String, CreateSessionError> {
    // Defense in depth: the remote protocol boundary validates this first, but this lower-level seam is
    // public inside the crate and must not turn a future/forged provider into an apparently successful
    // bare-shell session. Absence remains the deliberate legacy shell behavior.
    if request
        .agent
        .as_deref()
        .is_some_and(|agent| ResumeAgent::parse(agent).is_none())
    {
        return Err(CreateSessionError::UnsupportedProvider);
    }
    let known = creator.known_sessions();
    if known.len() >= creator.max_sessions() {
        return Err(CreateSessionError::LimitReached);
    }
    let id =
        pick_unused_id(&known, rand::random::<u8>, 10).ok_or(CreateSessionError::LimitReached)?;
    let home = creator.default_cwd()?;
    let cwd = request.cwd.as_deref().unwrap_or(&home);
    // Resume wins; else a FRESH explicit (allowlisted) agent launches as `<agent>` — previously the fresh
    // path always started a bare shell even when the browser picked an agent. Absent agent = bare shell.
    let provider = request
        .resume
        .as_ref()
        .map(|resume| resume.agent)
        .or_else(|| request.agent.as_deref().and_then(ResumeAgent::parse));
    let mut launch = request
        .resume
        .as_ref()
        .and_then(build_resume_launch)
        .or_else(|| {
            request
                .agent
                .as_deref()
                .and_then(ResumeAgent::parse)
                .map(build_fresh_launch)
        });
    if !matches!(provider, Some(ResumeAgent::Amp | ResumeAgent::Factory)) {
        if let (Some(launch), Some(model)) = (launch.as_mut(), request.model.as_deref()) {
            launch.args.push("--model".to_string());
            launch.args.push(model.to_string());
        }
    }
    if request.dangerous {
        if let (Some(launch), Some(provider)) = (launch.as_mut(), provider) {
            let flag = provider.dangerous_flag();
            if !launch.args.iter().any(|arg| arg == flag) {
                launch.args.push(flag.to_string());
            }
        }
    }
    creator.start_session_with_launch_and_size(&id, cwd, launch.as_ref(), initial_size)?;
    Ok(id)
}

/// Resolve the runtime recipe for an empty browser-created terminal. Linux
/// headless services do not inherit an attended launcher's `SHELL`/`PATH`, so
/// use the effective account's passwd shell as a login shell. Other platforms
/// retain the existing remote-desktop recipe byte for byte.
pub(crate) fn empty_session_launch(headless_server: bool) -> ResumeLaunch {
    #[cfg(target_os = "linux")]
    {
        if headless_server {
            return ResumeLaunch {
                command: crate::agent_dir::trusted_login_shell()
                    // `trusted_login_shell` already validates `/bin/sh` as its fallback. If even that
                    // platform contract is unavailable or unsafe, enqueue an unexecutable fixed device
                    // rather than undoing the validation by attempting `/bin/sh` anyway.
                    .unwrap_or_else(|_| "/dev/null".to_string()),
                args: vec!["-l".to_string()],
            };
        }
    }

    let _ = headless_server;
    ResumeLaunch {
        command: "bash".to_string(),
        args: vec!["--norc".to_string(), "-i".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A fake creator: records start_session calls; configurable known sessions, home, cap, and a
    /// daemon-unavailable mode.
    struct FakeCreator {
        known: Vec<String>,
        started: std::cell::RefCell<Vec<String>>,
        started_homes: std::cell::RefCell<Vec<String>>,
        started_launches: std::cell::RefCell<Vec<Option<ResumeLaunch>>>,
        started_sizes: std::cell::RefCell<Vec<InitialTerminalSize>>,
        unavailable: bool,
        default_cwd_unavailable: bool,
        cap: usize,
    }
    impl FakeCreator {
        fn new() -> Self {
            FakeCreator {
                known: vec![],
                started: Default::default(),
                started_homes: Default::default(),
                started_launches: Default::default(),
                started_sizes: Default::default(),
                unavailable: false,
                default_cwd_unavailable: false,
                cap: 16,
            }
        }
    }
    impl SessionCreator for FakeCreator {
        fn known_sessions(&self) -> Vec<String> {
            self.known.clone()
        }
        fn start_session(
            &mut self,
            session_id: &str,
            home: &str,
        ) -> Result<(), CreateSessionError> {
            if self.unavailable {
                return Err(CreateSessionError::DaemonUnavailable);
            }
            self.started.borrow_mut().push(session_id.to_string());
            self.started_homes.borrow_mut().push(home.to_string());
            self.started_launches.borrow_mut().push(None);
            self.started_sizes
                .borrow_mut()
                .push(InitialTerminalSize::default());
            Ok(())
        }
        fn start_session_with_launch(
            &mut self,
            session_id: &str,
            home: &str,
            launch: Option<&ResumeLaunch>,
        ) -> Result<(), CreateSessionError> {
            if self.unavailable {
                return Err(CreateSessionError::DaemonUnavailable);
            }
            self.started.borrow_mut().push(session_id.to_string());
            self.started_homes.borrow_mut().push(home.to_string());
            self.started_launches.borrow_mut().push(launch.cloned());
            self.started_sizes
                .borrow_mut()
                .push(InitialTerminalSize::default());
            Ok(())
        }
        fn start_session_with_launch_and_size(
            &mut self,
            session_id: &str,
            home: &str,
            launch: Option<&ResumeLaunch>,
            initial_size: InitialTerminalSize,
        ) -> Result<(), CreateSessionError> {
            if self.unavailable {
                return Err(CreateSessionError::DaemonUnavailable);
            }
            self.started.borrow_mut().push(session_id.to_string());
            self.started_homes.borrow_mut().push(home.to_string());
            self.started_launches.borrow_mut().push(launch.cloned());
            self.started_sizes.borrow_mut().push(initial_size);
            Ok(())
        }
        fn home(&self) -> String {
            "/Users/test/home".to_string()
        }
        fn default_cwd(&self) -> Result<String, CreateSessionError> {
            if self.default_cwd_unavailable {
                Err(CreateSessionError::DaemonUnavailable)
            } else {
                Ok(self.home())
            }
        }
        fn max_sessions(&self) -> usize {
            self.cap
        }
    }

    /// A deterministic byte source cycling through a fixed sequence.
    fn seq_rng(bytes: Vec<u8>) -> impl FnMut() -> u8 {
        let i = Cell::new(0usize);
        move || {
            let b = bytes[i.get() % bytes.len()];
            i.set(i.get() + 1);
            b
        }
    }

    #[test]
    fn generated_id_has_the_s_prefix_and_safe_alphabet() {
        let id = generate_session_id(seq_rng(vec![0, 1, 2, 3, 4, 5]));
        assert!(id.starts_with("s-"));
        assert_eq!(id.len(), 8); // "s-" + 6
        assert!(!id.contains('l') && !id.contains('o') && !id.contains('0') && !id.contains('1'));
    }

    #[test]
    fn pick_unused_id_avoids_known_sessions() {
        // first generated id will collide with a known one, so it must retry to a different id.
        let known = vec![generate_session_id(seq_rng(vec![0]))]; // the id from all-zero bytes
        let id =
            pick_unused_id(&known, seq_rng(vec![0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7]), 5).unwrap();
        assert!(!known.contains(&id));
    }

    #[test]
    fn pick_unused_id_returns_none_when_every_try_collides() {
        let only = generate_session_id(seq_rng(vec![0]));
        // rng always yields the SAME id (all-zero) → every try collides → None.
        let r = pick_unused_id(&[only], seq_rng(vec![0]), 4);
        assert!(r.is_none());
    }

    #[test]
    fn create_session_starts_a_fresh_session_and_returns_its_id() {
        let mut c = FakeCreator::new();
        let id = create_session(&mut c, &CreateSessionRequest::default()).unwrap();
        assert!(id.starts_with("s-"));
        assert_eq!(c.started.borrow().as_slice(), std::slice::from_ref(&id)); // exactly one start_session, for this id
        assert_eq!(c.started_homes.borrow().as_slice(), &["/Users/test/home"]);
        assert_eq!(c.started_launches.borrow().as_slice(), &[None]);
        assert_eq!(
            c.started_sizes.borrow().as_slice(),
            &[InitialTerminalSize::default()]
        );
        assert!(!c.known.contains(&id));
    }

    #[test]
    fn default_cwd_failure_happens_before_any_daemon_start() {
        let mut creator = FakeCreator::new();
        creator.default_cwd_unavailable = true;
        assert_eq!(
            create_session(&mut creator, &CreateSessionRequest::default()),
            Err(CreateSessionError::DaemonUnavailable)
        );
        assert!(creator.started.borrow().is_empty());
        assert!(creator.started_homes.borrow().is_empty());
        assert!(creator.started_launches.borrow().is_empty());
    }

    #[test]
    fn initial_terminal_size_requires_a_valid_pair_and_preserves_exact_geometry() {
        assert_eq!(
            InitialTerminalSize::from_optional_pair(Some(2), Some(1)),
            InitialTerminalSize { cols: 2, rows: 1 }
        );
        assert_eq!(
            InitialTerminalSize::from_optional_pair(Some(250), Some(100)),
            InitialTerminalSize {
                cols: 250,
                rows: 100
            }
        );
        assert_eq!(
            InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
            InitialTerminalSize {
                cols: 132,
                rows: 43
            }
        );
        for invalid in [
            InitialTerminalSize::from_optional_pair(None, None),
            InitialTerminalSize::from_optional_pair(Some(132), None),
            InitialTerminalSize::from_optional_pair(None, Some(43)),
            InitialTerminalSize::from_optional_pair(Some(0), Some(43)),
            InitialTerminalSize::from_optional_pair(Some(132), Some(0)),
            InitialTerminalSize::from_optional_pair(Some(1), Some(43)),
            InitialTerminalSize::from_optional_pair(Some(251), Some(43)),
            InitialTerminalSize::from_optional_pair(Some(132), Some(101)),
        ] {
            assert_eq!(invalid, InitialTerminalSize::default());
        }

        let mut c = FakeCreator::new();
        create_session_with_initial_size(
            &mut c,
            &CreateSessionRequest::default(),
            InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
        )
        .unwrap();
        assert_eq!(
            c.started_sizes.borrow().as_slice(),
            &[InitialTerminalSize {
                cols: 132,
                rows: 43
            }]
        );
    }

    #[test]
    fn create_session_threads_valid_resume_launch() {
        let mut c = FakeCreator::new();
        let id = create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: Some("/Users/test/project".into()),
                resume: Some(ResumeDescriptor {
                    agent: crate::resume_launch::ResumeAgent::Codex,
                    session_id: Some("50000000-0000-4000-8000-000000000001".into()),
                    session_file: None,
                }),
                model: None,
                dangerous: false,
                agent: None,
            },
        )
        .unwrap();
        assert!(id.starts_with("s-"));
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "codex".into(),
                args: vec![
                    "resume".into(),
                    "50000000-0000-4000-8000-000000000001".into(),
                ],
            })]
        );
    }

    #[test]
    fn create_session_appends_model_to_a_built_resume_launch() {
        // Record/launch parity for the model flag: a validated model name rides the SAME discrete argv as
        // the resume — ["resume", <id>, "--model", <name>] — never a shell string.
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: Some(ResumeDescriptor {
                    agent: crate::resume_launch::ResumeAgent::Codex,
                    session_id: Some("50000000-0000-4000-8000-000000000002".into()),
                    session_file: None,
                }),
                model: Some("gpt-5.2-codex".into()),
                dangerous: false,
                agent: None,
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "codex".into(),
                args: vec![
                    "resume".into(),
                    "50000000-0000-4000-8000-000000000002".into(),
                    "--model".into(),
                    "gpt-5.2-codex".into()
                ],
            })]
        );
    }

    #[test]
    fn create_session_model_without_a_launch_stays_a_fresh_shell() {
        // No resume launch is built → nothing to append --model to; the session starts as the bare shell.
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("opus-4.6".into()),
                dangerous: false,
                agent: None,
            },
        )
        .unwrap();
        assert_eq!(c.started_launches.borrow().as_slice(), &[None]);
    }

    #[test]
    fn create_session_fresh_explicit_agent_launches_that_agent() {
        // Record/launch parity (Bug A class): the browser picked an agent with no resume → the PTY must run
        // `<agent> [--model <name>]`, not a bare shell (previously a fresh create always started bash).
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("claude-opus-4-8".into()),
                dangerous: false,
                agent: Some("claude".into()),
            },
        )
        .unwrap();
        let launches = c.started_launches.borrow();
        let launch = launches[0].as_ref().expect("fresh Claude launch");
        assert_eq!(launch.command, "claude");
        assert_eq!(launch.args.len(), 4);
        assert_eq!(launch.args[0], "--session-id");
        let id = &launch.args[1];
        assert_eq!(
            uuid::Uuid::parse_str(id).unwrap().hyphenated().to_string(),
            *id
        );
        assert_eq!(&launch.args[2..], &["--model", "claude-opus-4-8"]);
    }

    #[test]
    fn create_session_fresh_copilot_records_a_canonical_provider_session_id() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("auto".into()),
                dangerous: true,
                agent: Some("copilot".into()),
            },
        )
        .unwrap();
        let launches = c.started_launches.borrow();
        let launch = launches[0].as_ref().unwrap();
        assert_eq!(launch.command, "copilot");
        assert_eq!(launch.args.len(), 4);
        let id = launch.args[0].strip_prefix("--session-id=").unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(id).unwrap().hyphenated().to_string(),
            id
        );
        assert_eq!(&launch.args[1..], &["--model", "auto", "--yolo"]);
    }

    #[test]
    fn create_session_fresh_antigravity_runs_agy_with_discrete_model_argv() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("Gemini 3.5 Flash (High)".into()),
                dangerous: false,
                agent: Some("antigravity".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "agy".into(),
                args: vec!["--model".into(), "Gemini 3.5 Flash (High)".into()],
            })]
        );
    }

    #[test]
    fn create_session_fresh_kiro_keeps_chat_first_and_uses_exact_trust_flag() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("claude-sonnet-4.5".into()),
                dangerous: true,
                agent: Some("kiro".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "kiro-cli".into(),
                args: vec![
                    "chat".into(),
                    "--model".into(),
                    "claude-sonnet-4.5".into(),
                    "--trust-all-tools".into(),
                ],
            })]
        );
    }

    #[test]
    fn create_session_fresh_cursor_uses_agent_model_and_exact_yolo_flag() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("composer-2.5".into()),
                dangerous: true,
                agent: Some("cursor".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "agent".into(),
                args: vec!["--model".into(), "composer-2.5".into(), "--yolo".into()],
            })]
        );
    }

    #[test]
    fn create_session_amp_ignores_generic_model_and_uses_exact_dangerous_flag() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("must-not-leak".into()),
                dangerous: true,
                agent: Some("amp".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "amp".into(),
                args: vec!["--dangerously-allow-all".into()],
            })]
        );

        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: Some(ResumeDescriptor {
                    agent: ResumeAgent::Amp,
                    session_id: Some("thread-id".into()),
                    session_file: None,
                }),
                model: Some("must-not-leak".into()),
                dangerous: true,
                agent: Some("amp".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "amp".into(),
                args: vec![
                    "threads".into(),
                    "continue".into(),
                    "thread-id".into(),
                    "--dangerously-allow-all".into(),
                ],
            })]
        );
    }

    #[test]
    fn create_session_devin_and_factory_use_canonical_launch_contracts() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("claude-sonnet-4".into()),
                dangerous: true,
                agent: Some("devin".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "devin".into(),
                args: vec![
                    "--model".into(),
                    "claude-sonnet-4".into(),
                    "--permission-mode=dangerous".into(),
                ],
            })]
        );

        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: Some("must-not-leak".into()),
                dangerous: true,
                agent: Some("factory".into()),
            },
        )
        .unwrap();
        assert_eq!(
            c.started_launches.borrow().as_slice(),
            &[Some(ResumeLaunch {
                command: "droid".into(),
                args: vec!["--auto=high".into()],
            })]
        );
    }

    #[test]
    fn create_session_rejects_unknown_fresh_agent_instead_of_starting_a_shell() {
        let mut c = FakeCreator::new();
        let error = create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: None,
                model: None,
                dangerous: false,
                agent: Some("bash".into()),
            },
        )
        .unwrap_err();
        assert_eq!(error, CreateSessionError::UnsupportedProvider);
        assert!(c.started_launches.borrow().is_empty());
        assert!(c.started.borrow().is_empty());
    }

    #[test]
    fn create_session_falls_back_to_fresh_when_resume_target_missing() {
        let mut c = FakeCreator::new();
        create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: None,
                resume: Some(ResumeDescriptor {
                    agent: crate::resume_launch::ResumeAgent::Gemini,
                    session_id: Some("wrong-shape".into()),
                    session_file: None,
                }),
                model: None,
                dangerous: false,
                agent: None,
            },
        )
        .unwrap();
        assert_eq!(c.started_launches.borrow().as_slice(), &[None]);
    }

    #[test]
    fn create_session_uses_requested_cwd_when_present() {
        let mut c = FakeCreator::new();
        let id = create_session(
            &mut c,
            &CreateSessionRequest {
                cwd: Some("/Users/test/project".into()),
                resume: None,
                model: None,
                dangerous: false,
                agent: None,
            },
        )
        .unwrap();
        assert!(id.starts_with("s-"));
        assert_eq!(
            c.started_homes.borrow().as_slice(),
            &["/Users/test/project"]
        );
    }

    #[test]
    fn create_session_daemon_unavailable_maps_through() {
        let mut c = FakeCreator::new();
        c.unavailable = true;
        assert_eq!(
            create_session(&mut c, &CreateSessionRequest::default()).unwrap_err(),
            CreateSessionError::DaemonUnavailable
        );
        assert!(c.started.borrow().is_empty());
    }

    #[test]
    fn create_session_respects_the_cap() {
        let mut c = FakeCreator::new();
        c.cap = 2;
        c.known = vec!["s1".into(), "s2".into()];
        assert_eq!(
            create_session(&mut c, &CreateSessionRequest::default()).unwrap_err(),
            CreateSessionError::LimitReached
        );
        assert!(c.started.borrow().is_empty()); // no daemon op when capped
    }

    #[test]
    fn error_codes_match_the_protocol() {
        assert_eq!(
            CreateSessionError::DaemonUnavailable.code(),
            "daemon_unavailable"
        );
        assert_eq!(CreateSessionError::LimitReached.code(), "limit_reached");
        assert_eq!(
            CreateSessionError::UnsupportedProvider.code(),
            "unsupported_provider"
        );
    }

    #[test]
    fn desktop_empty_session_launch_preserves_the_legacy_shell_policy() {
        let launch = empty_session_launch(false);
        assert_eq!(launch.command, "bash");
        assert_eq!(launch.args, vec!["--norc", "-i"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_empty_session_launch_uses_the_trusted_account_login_shell() {
        let launch = empty_session_launch(true);
        #[cfg(target_os = "linux")]
        {
            assert!(std::path::Path::new(&launch.command).is_absolute());
            assert_eq!(launch.args, vec!["-l"]);
            assert_eq!(
                launch.command,
                crate::agent_dir::trusted_login_shell().unwrap_or_else(|_| "/dev/null".to_string())
            );
        }
    }
}
