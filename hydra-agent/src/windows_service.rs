//! Per-user Windows Task Scheduler adapter. Only connectivity is managed; the daemon is external.
//! Public stamps in argv are checked against the running binary before supervision starts.
use crate::service::{ServiceAction, ServicePaths, ServicePlan};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

#[cfg(windows)]
#[path = "windows_service/native.rs"]
mod native;
#[cfg(windows)]
pub use native::*;

const NS: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";
pub const MAX_DEFINITION_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsServiceOptions {
    pub binary_path: String,
    pub build_stamp: String,
    pub binding_stamp: String,
    pub user_sid: String,
    pub agent_dir: PathBuf,
    pub app_support_dir: PathBuf,
    pub socket_path: String,
    pub sessions: Vec<String>,
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Windows CRT argv quoting, including trailing backslashes before the closing quote.
pub fn quote_argument(value: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(
            '\\',
            if c == '"' { slashes * 2 + 1 } else { slashes },
        ));
        result.push(c);
        slashes = 0;
    }
    result.extend(std::iter::repeat_n('\\', slashes * 2));
    result.push('"');
    result
}

pub fn parse_arguments(value: &str) -> Result<Vec<String>> {
    if value.len() > MAX_DEFINITION_BYTES || value.contains('\0') {
        bail!("invalid Windows argument size");
    }
    let mut chars = value.chars().peekable();
    let mut args = Vec::new();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut argument = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            if !quoted && (c == ' ' || c == '\t') {
                break;
            }
            let mut slashes = 0;
            while chars.peek() == Some(&'\\') {
                chars.next();
                slashes += 1;
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                argument.extend(std::iter::repeat_n('\\', slashes / 2));
                if slashes % 2 == 1 {
                    argument.push('"');
                } else {
                    quoted = !quoted;
                }
            } else {
                argument.extend(std::iter::repeat_n('\\', slashes));
                if !quoted && chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
                    break;
                }
                if let Some(c) = chars.next() {
                    argument.push(c);
                }
            }
        }
        if quoted {
            bail!("unclosed Windows argument quote");
        }
        args.push(argument);
        if args.len() > 64 {
            bail!("too many Windows service arguments");
        }
    }
    Ok(args)
}

impl WindowsServiceOptions {
    pub fn arguments(&self) -> Vec<String> {
        let mut args = vec![
            "supervise".into(),
            "--attach-daemon-only".into(),
            "--dir".into(),
            self.agent_dir.to_string_lossy().into_owned(),
            "--sock".into(),
            self.socket_path.clone(),
            "--app-support-dir".into(),
            self.app_support_dir.to_string_lossy().into_owned(),
            "--service-build-stamp".into(),
            self.build_stamp.clone(),
            "--service-binding-stamp".into(),
            self.binding_stamp.clone(),
        ];
        if !self.sessions.is_empty() {
            args.extend(["--sessions".into(), self.sessions.join(",")]);
        }
        args
    }
    pub fn validate(&self) -> Result<()> {
        for value in [
            self.binary_path.as_str(),
            self.build_stamp.as_str(),
            self.binding_stamp.as_str(),
            self.user_sid.as_str(),
            self.socket_path.as_str(),
        ] {
            if value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control) {
                bail!("invalid Windows service definition value");
            }
        }
        if !self.user_sid.starts_with("S-1-")
            || !self.user_sid[4..]
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-')
        {
            bail!("Windows service principal is not a SID");
        }
        if self.binding_stamp.len() != 64
            || !self
                .binding_stamp
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("Windows service binding is not SHA-256");
        }
        for path in [
            Path::new(&self.binary_path),
            self.agent_dir.as_path(),
            self.app_support_dir.as_path(),
        ] {
            let text = path
                .to_str()
                .context("Windows service path is not Unicode")?;
            if text.is_empty() || text.chars().any(char::is_control) {
                bail!("invalid Windows service path");
            }
            #[cfg(windows)]
            if !crate::agent_dir::is_canonically_encoded_absolute_path(path) {
                bail!("Windows service path is not canonical absolute");
            }
        }
        if self.sessions.len() > 64
            || self
                .sessions
                .iter()
                .any(|s| s.is_empty() || s.contains(',') || s.chars().any(char::is_control))
        {
            bail!("invalid Windows service sessions");
        }
        Ok(())
    }
}

pub fn generate_task_xml(opts: &WindowsServiceOptions) -> Result<String> {
    opts.validate()?;
    let arguments = opts
        .arguments()
        .iter()
        .map(|a| quote_argument(a))
        .collect::<Vec<_>>()
        .join(" ");
    let output = format!(
        r#"<?xml version="1.0"?>
<Task version="1.4" xmlns="{NS}">
  <RegistrationInfo><Description>Hydra desktop remote connectivity</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="HydraUser"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
  <Actions Context="HydraUser"><Exec><Command>{binary}</Command><Arguments>{args}</Arguments><WorkingDirectory>{directory}</WorkingDirectory></Exec></Actions>
</Task>
"#,
        sid = xml(&opts.user_sid),
        binary = xml(&opts.binary_path),
        args = xml(&arguments),
        directory = xml(opts
            .agent_dir
            .to_str()
            .context("Windows directory is not Unicode")?)
    );
    if output.len() > MAX_DEFINITION_BYTES {
        bail!("Windows service definition exceeds bound");
    }
    Ok(output)
}

/// Parse a closed Task Scheduler shape, then compare all XML elements/attributes to our generator.
/// Namespace prefixes, schema-all ordering and Scheduler-added metadata/defaults do not carry
/// authority. Extra actions/triggers, changed principal or nondefault execution settings do.
pub fn parse_task_xml(source: &str) -> Result<WindowsServiceOptions> {
    parse_task_xml_with_account_resolver(source, |name| {
        #[cfg(windows)]
        return native::account_name_sid(name);
        #[cfg(not(windows))]
        {
            let _ = name;
            bail!("Windows account-name resolution requires Windows");
        }
    })
}

fn parse_task_xml_with_account_resolver(
    source: &str,
    resolve_account: impl FnOnce(&str) -> Result<String>,
) -> Result<WindowsServiceOptions> {
    if source.len() > MAX_DEFINITION_BYTES {
        bail!("Windows service definition exceeds bound");
    }
    let doc = roxmltree::Document::parse(source).context("parse Windows service XML")?;
    let root = doc.root_element();
    let get = |path: &[&str]| -> Result<String> {
        let mut node = root;
        for name in path {
            let nodes = node
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == *name)
                .collect::<Vec<_>>();
            if nodes.len() != 1 {
                bail!("Windows task has missing or duplicate field");
            }
            node = nodes[0];
        }
        Ok(node.text().unwrap_or("").to_owned())
    };
    let args = parse_arguments(&get(&["Actions", "Exec", "Arguments"])?)?;
    if args.first().map(String::as_str) != Some("supervise")
        || args.get(1).map(String::as_str) != Some("--attach-daemon-only")
    {
        bail!("Windows task is not attach-only supervisor");
    }
    let mut fields = std::collections::BTreeMap::new();
    for pair in args[2..].chunks(2) {
        if pair.len() != 2 || fields.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            bail!("ambiguous Windows supervisor arguments");
        }
    }
    let mut required = |name| {
        fields
            .remove(name)
            .map(str::to_owned)
            .with_context(|| format!("Windows supervisor omits {name}"))
    };
    let opts = WindowsServiceOptions {
        binary_path: get(&["Actions", "Exec", "Command"])?,
        user_sid: get(&["Principals", "Principal", "UserId"])?,
        agent_dir: required("--dir")?.into(),
        app_support_dir: required("--app-support-dir")?.into(),
        socket_path: required("--sock")?,
        build_stamp: required("--service-build-stamp")?,
        binding_stamp: required("--service-binding-stamp")?,
        sessions: fields
            .remove("--sessions")
            .map(|s| s.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
    };
    if !fields.is_empty() {
        bail!("Windows supervisor has unreviewed arguments");
    }
    let canonical = generate_task_xml(&opts)?;
    let trigger_user = get(&["Triggers", "LogonTrigger", "UserId"])?;
    // Scheduler may export the trigger as DOMAIN\\name while retaining the principal SID.
    // Resolve that spelling through Windows, never infer identity from a display name.
    if trigger_user != opts.user_sid && resolve_account(&trigger_user)? != opts.user_sid {
        bail!("Windows logon trigger belongs to a different principal");
    }
    let expected = roxmltree::Document::parse(&canonical)?;
    fn equivalent(a: roxmltree::Node<'_, '_>, b: roxmltree::Node<'_, '_>) -> bool {
        fn mismatch(a: roxmltree::Node<'_, '_>, b: roxmltree::Node<'_, '_>, reason: &str) -> bool {
            #[cfg(test)]
            {
                let mut path = a
                    .ancestors()
                    .filter(|n| n.is_element())
                    .map(|n| n.tag_name().name())
                    .collect::<Vec<_>>();
                path.reverse();
                let at = a.text().unwrap_or("");
                let bt = b.text().unwrap_or("");
                eprintln!("XML mismatch path={} reason={reason} namespace_equal={} attribute_counts={}/{} text_lengths={}/{} control_counts={}/{} trim_equal={}",
                    path.join("/"), a.tag_name().namespace() == b.tag_name().namespace(),
                    a.attributes().len(), b.attributes().len(), at.len(), bt.len(),
                    at.chars().filter(|c| c.is_control()).count(), bt.chars().filter(|c| c.is_control()).count(), at.trim() == bt.trim());
            }
            #[cfg(not(test))]
            let _ = (a, b, reason);
            false
        }
        if a.tag_name() != b.tag_name() || a.attributes().len() != b.attributes().len() {
            return mismatch(a, b, "tag/namespace/attribute-count");
        }
        if a.attributes().any(|attr| {
            !b.attributes().any(|other| {
                other.namespace() == attr.namespace()
                    && other.name() == attr.name()
                    && other.value() == attr.value()
            })
        }) {
            return mismatch(a, b, "attribute-name/namespace/value");
        }
        let ac: Vec<_> = a.children().filter(|n| n.is_element()).collect();
        let mut bc: Vec<_> = b.children().filter(|n| n.is_element()).collect();
        if ac.is_empty() && bc.is_empty() {
            let verified_trigger_user = a.tag_name().name() == "UserId"
                && a.parent_element()
                    .is_some_and(|p| p.tag_name().name() == "LogonTrigger");
            let manually_disabled = a.tag_name().name() == "Enabled"
                && a.parent_element()
                    .is_some_and(|p| p.tag_name().name() == "Settings")
                && a.text() == Some("false")
                && b.text() == Some("true");
            return verified_trigger_user
                || manually_disabled
                || a.text().unwrap_or("") == b.text().unwrap_or("")
                || mismatch(a, b, "leaf-text");
        }
        // Every supported container has unique child names (one action and one trigger).
        // Removing each matched child preserves cardinality even when Scheduler reorders xs:all.
        let mut seen = std::collections::BTreeSet::new();
        for child in ac {
            if !seen.insert((child.tag_name().namespace(), child.tag_name().name())) {
                return mismatch(child, b, "duplicate-child");
            }
            if let Some(index) = bc
                .iter()
                .position(|expected| expected.tag_name() == child.tag_name())
            {
                if !equivalent(child, bc.remove(index)) {
                    return false;
                }
                continue;
            }
            // Documented Scheduler schema defaults and non-authority registration metadata:
            // https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-schema
            if child.tag_name().namespace() != Some(NS)
                || child.attributes().len() != 0
                || child.children().any(|n| n.is_element())
            {
                return mismatch(child, b, "extra-node-namespace/attributes/children");
            }
            let text = child.text().unwrap_or("");
            let allowed = match (a.tag_name().name(), child.tag_name().name()) {
                ("RegistrationInfo", "URI" | "Date" | "Author" | "SecurityDescriptor") => {
                    // Native observation separately validates the actual registered DACL.
                    text.len() <= 1024 && !text.chars().any(char::is_control)
                }
                ("IdleSettings", "Duration") => text == "PT10M",
                ("IdleSettings", "WaitTimeout") => text == "PT1H",
                ("Settings", "DisallowStartOnRemoteAppSession" | "Volatile") => text == "false",
                ("Settings", "UseUnifiedSchedulingEngine") => matches!(text, "true" | "false"),
                _ => false,
            };
            if !allowed {
                return mismatch(child, b, "extra-node-value/control/length");
            }
        }
        // Native readback omits these schema defaults; it must not omit a nondefault constraint
        // or an execution-authority field. In particular SID, logon type and action stay exact.
        bc.into_iter().all(|node| {
            matches!(
                (a.tag_name().name(), node.tag_name().name(), node.text()),
                ("Principal", "RunLevel", Some("LeastPrivilege"))
                    | ("LogonTrigger", "Enabled", Some("true"))
                    | (
                        "Settings",
                        "AllowHardTerminate" | "AllowStartOnDemand" | "Enabled",
                        Some("true")
                    )
                    | (
                        "Settings",
                        "RunOnlyIfNetworkAvailable" | "Hidden" | "RunOnlyIfIdle" | "WakeToRun",
                        Some("false")
                    )
                    | ("Settings", "Priority", Some("7"))
            ) || mismatch(node, a, "omitted-nondefault-node")
        })
    }
    if !equivalent(root, expected.root_element()) {
        #[cfg(test)]
        {
            fn safe_value(text: &str) -> &str {
                if matches!(
                    text,
                    "true"
                        | "false"
                        | "1.4"
                        | "1.3"
                        | "7"
                        | "999"
                        | "HydraUser"
                        | "Author"
                        | "InteractiveToken"
                        | "LeastPrivilege"
                        | "IgnoreNew"
                ) || (text.starts_with('P')
                    && text.len() <= 32
                    && text
                        .bytes()
                        .all(|c| c.is_ascii_digit() || b"PDTHMS".contains(&c)))
                {
                    text
                } else {
                    "<redacted>"
                }
            }
            fn shape(root: roxmltree::Node<'_, '_>) -> String {
                root.descendants()
                    .filter(|n| n.is_element())
                    .take(128)
                    .map(|node| {
                        let mut path = node
                            .ancestors()
                            .filter(|n| n.is_element())
                            .map(|n| n.tag_name().name())
                            .collect::<Vec<_>>();
                        path.reverse();
                        let attributes = node
                            .attributes()
                            .map(|a| format!(" {}={}", a.name(), safe_value(a.value())))
                            .collect::<String>();
                        let text = if node.children().any(|n| n.is_element()) {
                            ""
                        } else {
                            safe_value(node.text().unwrap_or(""))
                        };
                        format!("{}{}={text}", path.join("/"), attributes)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            eprintln!(
                "actual Scheduler XML shape (private values redacted):\n{}",
                shape(root)
            );
            eprintln!(
                "expected Scheduler XML shape (private values redacted):\n{}",
                shape(expected.root_element())
            );
        }
        bail!("Windows task differs from reviewed private attach-only shape");
    }
    Ok(opts)
}

pub fn definition_path(paths: &ServicePaths) -> PathBuf {
    paths.launch_agents_dir.join("hydra-agent.service")
}
pub fn default_paths(agent_dir: &Path, sid: &str) -> ServicePaths {
    ServicePaths {
        launch_agents_dir: agent_dir.join("service"),
        log_dir: agent_dir.join("logs"),
        agent_dir: agent_dir.to_path_buf(),
        label: "hydra-agent".into(),
        uid: sid.into(),
    }
}

fn action(paths: &ServicePaths, operation: &str, executable: &Path) -> ServiceAction {
    ServiceAction::RunCommand {
        program: executable.to_string_lossy().into_owned(),
        args: vec![
            "windows-service-manager".into(),
            operation.into(),
            "--dir".into(),
            paths.agent_dir.to_string_lossy().into_owned(),
        ],
    }
}
pub fn plan_install(paths: &ServicePaths, options: &WindowsServiceOptions) -> Result<ServicePlan> {
    Ok(ServicePlan {
        title: "Install per-user Windows remote connectivity task".into(),
        actions: vec![
            ServiceAction::CreatePrivateDir(paths.agent_dir.clone()),
            ServiceAction::CreatePrivateDir(paths.launch_agents_dir.clone()),
            ServiceAction::CreatePrivateDir(paths.log_dir.clone()),
            ServiceAction::WriteFile {
                path: definition_path(paths),
                contents: generate_task_xml(options)?,
            },
            action(paths, "install", Path::new(&options.binary_path)),
            action(paths, "start", Path::new(&options.binary_path)),
        ],
    })
}
pub fn plan_start(paths: &ServicePaths, executable: &Path) -> ServicePlan {
    ServicePlan {
        title: "Start per-user Windows remote connectivity task".into(),
        actions: vec![action(paths, "start", executable)],
    }
}
pub fn plan_uninstall(paths: &ServicePaths, executable: &Path) -> ServicePlan {
    ServicePlan {
        title: "Remove per-user Windows remote connectivity task".into(),
        actions: vec![
            action(paths, "uninstall", executable),
            ServiceAction::RemoveFile(definition_path(paths)),
        ],
    }
}
pub fn plan_status(paths: &ServicePaths, executable: &Path) -> ServicePlan {
    ServicePlan {
        title: "Inspect per-user Windows remote connectivity task".into(),
        actions: vec![action(paths, "query", executable)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options() -> WindowsServiceOptions {
        WindowsServiceOptions {
            binary_path: r"C:\Program Files\Hydra\hydra-agent.exe".into(),
            build_stamp: "synthetic-build".into(),
            binding_stamp: "a".repeat(64),
            user_sid: "S-1-5-21-123-456-789-1001".into(),
            agent_dir: r"C:\Fixture\Fixture\hydra-agent".into(),
            app_support_dir: r"C:\Fixture\Fixture\Hydra & Desktop".into(),
            socket_path: r"\\.\pipe\Hydra.Maestro.fixture".into(),
            sessions: vec![],
        }
    }
    #[test]
    fn scheduler_trigger_account_name_requires_exact_resolved_sid() {
        let opts = options();
        let xml = generate_task_xml(&opts).unwrap();
        let xml = xml.replacen(
            &format!(
                "<LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId>",
                opts.user_sid
            ),
            "<LogonTrigger><Enabled>true</Enabled><UserId>FIXTURE\\user</UserId>",
            1,
        );
        assert!(xml.contains("FIXTURE\\user"));
        assert_eq!(
            parse_task_xml_with_account_resolver(&xml, |name| {
                assert_eq!(name, "FIXTURE\\user");
                Ok(opts.user_sid.clone())
            })
            .unwrap(),
            opts
        );
        assert!(parse_task_xml_with_account_resolver(&xml, |_| Ok("S-1-5-18".into())).is_err());
        assert!(
            parse_task_xml_with_account_resolver(&xml, |_| bail!("lookup unavailable")).is_err()
        );
    }
    #[test]
    fn arguments_roundtrip_backslashes_quotes_and_unicode() {
        for value in [
            "",
            "ordinary",
            "quoted\"value",
            "two words",
            "trailing\\",
            "a\\\\\"b",
            "café",
        ] {
            assert_eq!(
                parse_arguments(&quote_argument(value)).unwrap(),
                vec![value]
            );
        }
    }
    #[test]
    fn task_roundtrip_is_interactive_least_privilege_and_attach_only() {
        let opts = options();
        let definition = generate_task_xml(&opts).unwrap();
        // Disk bytes are UTF-8; RegisterTask receives UTF-16 BSTR. Omitting the encoding
        // declaration lets each transport supply its actual encoding without contradiction.
        assert!(definition.starts_with("<?xml version=\"1.0\"?>"));
        assert!(!definition.contains("encoding="));
        assert_eq!(parse_task_xml(&definition).unwrap(), opts);
        for (from, to) in [
            ("LeastPrivilege", "HighestAvailable"),
            ("InteractiveToken", "Password"),
            ("--attach-daemon-only", "--own-daemon"),
            ("IgnoreNew", "Parallel"),
        ] {
            assert!(parse_task_xml(&definition.replace(from, to)).is_err());
        }
        assert!(parse_task_xml(&definition.replace(
            "</Actions>",
            "<Exec><Command>untrusted</Command></Exec></Actions>"
        ))
        .is_err());
    }
    #[test]
    fn scheduler_metadata_order_and_disabled_state_do_not_change_execution_authority() {
        let opts = options();
        let definition = generate_task_xml(&opts).unwrap();
        let normalized = definition
            .replace(
                "</RegistrationInfo>",
                "<URI>\\Synthetic\\Task</URI><Date>2026-10-04T12:00:00</Date></RegistrationInfo>",
            )
            .replace(
                "<IdleSettings>",
                "<IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout>",
            )
            .replace(
                "<Settings>",
                "<Settings><UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>",
            )
            .replace(
                "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled>",
                "<Enabled>false</Enabled><AllowStartOnDemand>true</AllowStartOnDemand>",
            );
        assert_eq!(parse_task_xml(&normalized).unwrap(), opts);
        for changed in [
            normalized.replace("<Duration>PT10M", "<Duration>PT20M"),
            normalized.replace(
                "<UseUnifiedSchedulingEngine>false",
                "<UseUnifiedSchedulingEngine>invalid",
            ),
            normalized.replace(
                "</RegistrationInfo>",
                "<URI>duplicate</URI></RegistrationInfo>",
            ),
            normalized.replace("<IdleSettings>", "<IdleSettings><Unknown>false</Unknown>"),
        ] {
            assert!(parse_task_xml(&changed).is_err());
        }
    }
    #[test]
    fn native_scheduler_omitted_defaults_preserve_exact_action_and_principal() {
        let opts = options();
        let mut exported = generate_task_xml(&opts).unwrap();
        for node in [
            "<RunLevel>LeastPrivilege</RunLevel>",
            "<Enabled>true</Enabled>",
            "<AllowHardTerminate>true</AllowHardTerminate>",
            "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
            "<AllowStartOnDemand>true</AllowStartOnDemand>",
            "<Hidden>false</Hidden>",
            "<RunOnlyIfIdle>false</RunOnlyIfIdle>",
            "<WakeToRun>false</WakeToRun>",
            "<Priority>7</Priority>",
        ] {
            exported = exported.replace(node, "");
        }
        exported = exported.replace("<Settings>", "<Settings><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>")
            .replace("<RegistrationInfo>", "<RegistrationInfo><SecurityDescriptor>D:P(A;;FA;;;SY)</SecurityDescriptor><URI>\\Synthetic\\Task</URI>");
        assert_eq!(parse_task_xml(&exported).unwrap(), opts);
        for required in [
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopOnIdleEnd>false</StopOnIdleEnd>",
            "<StartWhenAvailable>true</StartWhenAvailable>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<LogonType>InteractiveToken</LogonType>",
        ] {
            assert!(parse_task_xml(&exported.replace(required, "")).is_err());
        }
    }
    #[test]
    fn uninstall_never_names_a_daemon_or_identity_file() {
        let opts = options();
        let paths = default_paths(&opts.agent_dir, &opts.user_sid);
        let plan = plan_uninstall(&paths, Path::new(&opts.binary_path));
        assert_eq!(plan.actions.len(), 2);
        assert!(
            matches!(&plan.actions[1], ServiceAction::RemoveFile(path) if *path == definition_path(&paths))
        );
    }
}
