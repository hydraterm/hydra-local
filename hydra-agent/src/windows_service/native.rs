//! Native half of the Task Scheduler adapter. Manager COM is confined to a bounded helper
//! process. Process authority stays in retained handles, never a reusable PID alone.
use super::*;
use std::{
    fs::File,
    io::Read,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::OnceLock,
};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::{
    core::{BSTR, PCWSTR},
    Win32::{
        Foundation::*,
        Security::{Authorization::ConvertSidToStringSidW, *},
        System::{
            Com::*,
            Diagnostics::{Debug::ReadProcessMemory, ToolHelp::*},
            JobObjects::*,
            TaskScheduler::*,
            Threading::*,
            Variant::VARIANT,
        },
    },
};

fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}
fn owned(handle: HANDLE) -> OwnedHandle {
    // Every caller passes a uniquely owned successful Win32 result.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}
fn process_sid(process: HANDLE) -> Result<String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token)?;
    }
    let token = owned(token);
    let mut needed = 0;
    let _ = unsafe { GetTokenInformation(raw(&token), TokenUser, None, 0, &mut needed) };
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        bail!("invalid process token size");
    }
    let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            raw(&token),
            TokenUser,
            Some(words.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )?;
    }
    let user = unsafe { &*words.as_ptr().cast::<TOKEN_USER>() };
    let mut text = windows::core::PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(user.User.Sid, &mut text)?;
    }
    let result = unsafe { text.to_string() };
    unsafe {
        LocalFree(Some(HLOCAL(text.0.cast())));
    }
    result.context("process SID is not Unicode")
}
pub fn current_user_sid() -> Result<String> {
    process_sid(unsafe { GetCurrentProcess() })
}

pub(super) fn account_name_sid(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > 1024 || name.chars().any(char::is_control) {
        bail!("invalid task account-name spelling");
    }
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut sid_bytes = 0;
    let mut domain_chars = 0;
    let mut kind = SID_NAME_USE::default();
    let first = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            None,
            &mut sid_bytes,
            None,
            &mut domain_chars,
            &mut kind,
        )
    };
    if first.is_ok()
        || first.as_ref().err().is_none_or(|error| {
            error.code() != windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
        })
        || !(8..=1024).contains(&sid_bytes)
        || domain_chars > 1024
    {
        bail!("could not size task account identity");
    }
    let mut sid = vec![0usize; (sid_bytes as usize).div_ceil(size_of::<usize>())];
    let mut domain = vec![0u16; domain_chars as usize];
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_bytes,
            Some(windows::core::PWSTR(domain.as_mut_ptr())),
            &mut domain_chars,
            &mut kind,
        )?;
    }
    if kind != SidTypeUser || !unsafe { IsValidSid(PSID(sid.as_ptr().cast_mut().cast())) }.as_bool()
    {
        bail!("task account does not resolve to a user SID");
    }
    let mut text = windows::core::PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(PSID(sid.as_ptr().cast_mut().cast()), &mut text)?;
    }
    let result = unsafe { text.to_string() };
    unsafe {
        LocalFree(Some(HLOCAL(text.0.cast())));
    }
    result.context("task account SID is not Unicode")
}

/// Same Windows LocalAppData/Hydra convention as the desktop, resolved from the current token's
/// known folder (including OS folder redirection), not an ambient caller-controlled variable.
pub fn local_app_support_dir() -> Result<PathBuf> {
    use windows::Win32::UI::Shell::{
        FOLDERID_LocalAppData, SHGetKnownFolderPath, KNOWN_FOLDER_FLAG,
    };
    let value =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG(0), None)? };
    let path = unsafe { value.to_string() };
    unsafe {
        CoTaskMemFree(Some(value.0.cast()));
    }
    Ok(PathBuf::from(path?).join("Hydra"))
}

#[derive(Debug)]
pub struct ProcessWitness {
    process: OwnedHandle,
    pub pid: u32,
    pub created: u64,
    pub image: PathBuf,
}
#[derive(Debug)]
pub struct ProcessAlreadyExited;
impl std::fmt::Display for ProcessAlreadyExited {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the exact opened process has already exited")
    }
}
impl std::error::Error for ProcessAlreadyExited {}
fn handle_is_live(process: &OwnedHandle) -> Result<bool> {
    match unsafe { WaitForSingleObject(raw(process), 0) } {
        WAIT_OBJECT_0 => Ok(false),
        WAIT_TIMEOUT => Ok(true),
        _ => Err(std::io::Error::last_os_error()).context("query exact process handle"),
    }
}
fn creation_time(process: HANDLE) -> Result<u64> {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe {
        GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user)?;
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}
impl ProcessWitness {
    pub fn open(pid: u32) -> Result<Self> {
        if pid == 0 {
            bail!("zero process identity");
        }
        let process = owned(unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )?
        });
        if !handle_is_live(&process)? {
            return Err(ProcessAlreadyExited.into());
        }
        let metadata = (|| -> Result<_> {
            if process_sid(raw(&process))? != current_user_sid()? {
                bail!("process is not owned by the current Windows user");
            }
            let created = creation_time(raw(&process))?;
            let mut image = vec![0u16; 32768];
            let mut count = image.len() as u32;
            unsafe {
                QueryFullProcessImageNameW(
                    raw(&process),
                    PROCESS_NAME_WIN32,
                    windows::core::PWSTR(image.as_mut_ptr()),
                    &mut count,
                )?;
            }
            Ok((
                created,
                PathBuf::from(String::from_utf16(&image[..count as usize])?),
            ))
        })();
        // Image/token queries may fail during teardown (including ERROR_GEN_FAILURE). Only
        // this retained handle's signaled state can classify that failure as exact exit.
        if !handle_is_live(&process)? {
            return Err(ProcessAlreadyExited.into());
        }
        let (created, image) = metadata?;
        let witness = Self {
            process,
            pid,
            created,
            image,
        };
        Ok(witness)
    }
    pub fn is_live(&self) -> Result<bool> {
        handle_is_live(&self.process)
    }
    pub fn snapshot_if_live(&self) -> Result<Option<ProcessSnapshot>> {
        let snapshot = self.snapshot();
        if !self.is_live()? {
            return Ok(None);
        }
        snapshot.map(Some)
    }
    pub fn matches_live(&self, other: &Self) -> Result<bool> {
        Ok(self.pid == other.pid
            && self.created == other.created
            && self.image == other.image
            && self.is_live()?
            && other.is_live()?)
    }
    fn read_value<T: Copy + Default>(&self, address: *const T) -> Result<T> {
        if address.is_null() {
            bail!("process parameter pointer is null");
        }
        let mut value = T::default();
        let mut count = 0;
        unsafe {
            ReadProcessMemory(
                raw(&self.process),
                address.cast(),
                (&mut value as *mut T).cast(),
                size_of::<T>(),
                Some(&mut count),
            )?;
        }
        if count != size_of::<T>() {
            bail!("short process parameter read");
        }
        Ok(value)
    }
    /// Use the documented PEB/RTL_USER_PROCESS_PARAMETERS command-line fields only. No private
    /// environment block layout or secret-bearing process environment is read.
    pub fn snapshot(&self) -> Result<ProcessSnapshot> {
        let mut info = PROCESS_BASIC_INFORMATION::default();
        let mut count = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                raw(&self.process),
                ProcessBasicInformation,
                (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut count,
            )
        };
        if status.0 < 0
            || count as usize != size_of::<PROCESS_BASIC_INFORMATION>()
            || info.UniqueProcessId != self.pid as usize
        {
            bail!("process basic identity query failed");
        }
        let peb: PEB = self.read_value(info.PebBaseAddress)?;
        let parameters: RTL_USER_PROCESS_PARAMETERS = self.read_value(peb.ProcessParameters)?;
        let command = parameters.CommandLine;
        if command.Length == 0
            || !command.Length.is_multiple_of(2)
            || command.Length > command.MaximumLength
        {
            bail!("invalid process command-line bounds");
        }
        let mut wide = vec![0u16; command.Length as usize / 2];
        let mut read = 0;
        unsafe {
            ReadProcessMemory(
                raw(&self.process),
                command.Buffer.0.cast(),
                wide.as_mut_ptr().cast(),
                command.Length as usize,
                Some(&mut read),
            )?;
        }
        if read != command.Length as usize || !self.is_live()? {
            bail!("process command line changed or exited during inspection");
        }
        let command = String::from_utf16(&wide)?;
        let arguments = super::parse_arguments(&command)?;
        if arguments.is_empty() {
            bail!("process arguments are empty");
        }
        Ok(ProcessSnapshot {
            pid: self.pid,
            parent_pid: info.InheritedFromUniqueProcessId.try_into()?,
            created: self.created,
            image: self.image.clone(),
            arguments,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub parent_pid: u32,
    pub created: u64,
    pub image: PathBuf,
    pub arguments: Vec<String>,
}

pub fn agent_processes() -> Result<Vec<ProcessWitness>> {
    let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? });
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut result = Vec::new();
    let mut seen = 0;
    let mut next = unsafe { Process32FirstW(raw(&snapshot), &mut entry) };
    while next.is_ok() {
        seen += 1;
        if seen > 16384 {
            bail!("Windows process inventory exceeds bound");
        }
        let length = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16(&entry.szExeFile[..length])?;
        if name.eq_ignore_ascii_case("hydra-agent.exe")
            || name.eq_ignore_ascii_case("hydra-agent-service.exe")
        {
            // Query ownership with a limited handle before attempting command-line access.
            match unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    false,
                    entry.th32ProcessID,
                )
            } {
                Ok(handle) => {
                    let handle = owned(handle);
                    let inspected = (|| -> Result<Option<ProcessWitness>> {
                        if !handle_is_live(&handle)?
                            || process_sid(raw(&handle))? != current_user_sid()?
                        {
                            return Ok(None);
                        }
                        let witnessed = ProcessWitness::open(entry.th32ProcessID)?;
                        if creation_time(raw(&handle))? != witnessed.created {
                            bail!("Windows process changed during inventory");
                        }
                        Ok(Some(witnessed))
                    })();
                    if handle_is_live(&handle)? {
                        match inspected {
                            Ok(Some(witnessed)) => result.push(witnessed),
                            Ok(None) => (),
                            Err(error) if error.is::<ProcessAlreadyExited>() => (),
                            Err(error) => return Err(error),
                        }
                    }
                }
                Err(error)
                    if error.code()
                        == windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) => {}
                Err(error) => return Err(error).context("inspect candidate agent ownership"),
            }
        }
        next = unsafe { Process32NextW(raw(&snapshot), &mut entry) };
    }
    if let Err(error) = next {
        if error.code() != windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
            return Err(error).context("enumerate Windows processes");
        }
    }
    Ok(result)
}

static CONNECTIVITY_JOB: OnceLock<OwnedHandle> = OnceLock::new();
/// Call only in the attach-only supervisor, before it creates any child. The noninheritable
/// handle stays in that process; normal and abrupt process exit close it. Kernel child-job
/// inheritance admits every peer atomically, while the independently existing daemon is untouched.
pub fn contain_attach_only_supervisor() -> Result<()> {
    if CONNECTIVITY_JOB.get().is_some() {
        return Ok(());
    }
    let job = owned(unsafe { CreateJobObjectW(None, PCWSTR::null())? });
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            raw(&job),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
        AssignProcessToJobObject(raw(&job), GetCurrentProcess())?;
    }
    // This function runs before supervisor threads/children. Once assigned, never close the last
    // handle within the supervisor: that would terminate the caller itself before normal cleanup.
    CONNECTIVITY_JOB
        .set(job)
        .map_err(|_| anyhow::anyhow!("connectivity job initialized twice"))?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskInstance {
    pub instance_id: String,
    pub engine_pid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskState {
    pub registered: bool,
    pub state: i32,
    pub definition: Option<WindowsServiceOptions>,
    pub instances: Vec<TaskInstance>,
}
impl TaskState {
    pub fn absent(&self) -> bool {
        !self.registered && self.definition.is_none() && self.instances.is_empty()
    }
    pub fn dormant(&self) -> bool {
        self.registered
            && self.definition.is_some()
            && [TASK_STATE_READY.0, TASK_STATE_DISABLED.0].contains(&self.state)
            && self.instances.is_empty()
    }
}
fn task_name(sid: &str) -> String {
    format!("Hydra.Remote.{sid}")
}
struct ComApartment;
impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}
fn connect_manager() -> Result<(ComApartment, ITaskFolder)> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }
    let apartment = ComApartment;
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)? };
    unsafe {
        service.Connect(
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
        )?;
    }
    Ok((apartment, unsafe { service.GetFolder(&BSTR::from("\\"))? }))
}
fn registered(folder: &ITaskFolder, sid: &str) -> Result<Option<IRegisteredTask>> {
    match unsafe { folder.GetTask(&BSTR::from(task_name(sid))) } {
        Ok(task) => Ok(Some(task)),
        Err(error)
            if error.code() == windows::core::HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("query current-user Windows task"),
    }
}

/// Task Scheduler exports its security descriptor in XML, but only this independently queried
/// object DACL authorizes observation/mutation. This is not an exact SDDL-template comparison.
fn validate_task_security(task: &IRegisteredTask, sid: &str) -> Result<()> {
    let sddl = unsafe {
        task.GetSecurityDescriptor(
            (OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0) as i32,
        )?
    };
    validate_task_security_descriptor(&sddl.to_string(), sid)
}
fn validate_task_security_descriptor(sddl: &str, sid: &str) -> Result<()> {
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    if sddl.len() > 16 * 1024 || sddl.contains('\0') {
        bail!("invalid task descriptor bound");
    }
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            1,
            &mut descriptor,
            None,
        )?;
    }
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
    let descriptor = Descriptor(descriptor);
    let sid_text = |sid: PSID| -> Result<String> {
        if !unsafe { IsValidSid(sid) }.as_bool() {
            bail!("invalid task trustee");
        }
        let mut text = windows::core::PWSTR::null();
        unsafe {
            ConvertSidToStringSidW(sid, &mut text)?;
        }
        let result = unsafe { text.to_string() };
        unsafe {
            LocalFree(Some(HLOCAL(text.0.cast())));
        }
        Ok(result?)
    };
    let trusted = |trustee: &str| trustee == sid || matches!(trustee, "S-1-5-18" | "S-1-5-32-544");
    let mut owner = PSID::default();
    let mut defaulted = windows::core::BOOL::default();
    unsafe {
        GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted)?;
    }
    if !trusted(&sid_text(owner)?) {
        bail!("task has an untrusted owner");
    }
    let mut present = windows::core::BOOL::default();
    let mut acl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted)?;
    }
    if !present.as_bool() || acl.is_null() || !unsafe { IsValidAcl(acl) }.as_bool() {
        bail!("task has no valid restrictive DACL");
    }
    for index in 0..u32::from(unsafe { (*acl).AceCount }) {
        let mut raw_ace = std::ptr::null_mut();
        unsafe {
            GetAce(acl, index, &mut raw_ace)?;
        }
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0 {
            continue;
        }
        // ACCESS_DENIED_ACE cannot grant authority; unknown conditional/object allow forms
        // are not interpreted as ordinary grants.
        if header.AceType == 1 {
            continue;
        }
        if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            bail!("task uses an unreviewed access-control entry");
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let trustee = sid_text(PSID((&ace.SidStart as *const u32).cast_mut().cast()))?;
        if trusted(&trustee) || trustee == "S-1-3-4" {
            continue;
        }
        // Definitions contain only public stamps/paths, as on Unix. Read-only task metadata
        // does not grant execution, modification, deletion, WRITE_DAC or WRITE_OWNER.
        const HARMLESS_TASK_READ: u32 = 0x8000_0000 | 0x0012_0089; // GENERIC_READ | FILE_GENERIC_READ
        if ace.Mask & !HARMLESS_TASK_READ != 0 {
            bail!("task grants foreign execution or mutation authority");
        }
    }
    Ok(())
}
fn observe(folder: &ITaskFolder, agent_dir: &Path, sid: &str) -> Result<TaskState> {
    let Some(task) = registered(folder, sid)? else {
        return Ok(TaskState {
            registered: false,
            state: 0,
            definition: None,
            instances: vec![],
        });
    };
    validate_task_security(&task, sid)?;
    let definition = parse_task_xml(&unsafe { task.Xml()? }.to_string())?;
    if definition.user_sid != sid || definition.agent_dir != agent_dir {
        bail!("Windows task belongs to another principal or authority root");
    }
    let state = unsafe { task.State()? }.0;
    if ![
        TASK_STATE_DISABLED.0,
        TASK_STATE_QUEUED.0,
        TASK_STATE_READY.0,
        TASK_STATE_RUNNING.0,
    ]
    .contains(&state)
    {
        bail!("Windows task state is unknown");
    }
    let instances = unsafe { task.GetInstances(0)? };
    let count = unsafe { instances.Count()? };
    if !(0..=1).contains(&count) {
        bail!("Windows task has multiple or invalid instances");
    }
    let mut running = Vec::new();
    for i in 1..=count {
        let instance = unsafe { instances.get_Item(&VARIANT::from(i))? };
        running.push(TaskInstance {
            instance_id: unsafe { instance.InstanceGuid()? }.to_string(),
            engine_pid: unsafe { instance.EnginePID()? },
        });
    }
    Ok(TaskState {
        registered: true,
        state,
        definition: Some(definition),
        instances: running,
    })
}

pub fn read_definition(paths: &ServicePaths) -> Result<Option<WindowsServiceOptions>> {
    let path = definition_path(paths);
    if !path.try_exists()? {
        return Ok(None);
    }
    let parent = maestro_shell::WindowsPrivateDirectory::open(
        path.parent().context("task definition has no parent")?,
    )?;
    let mut file: File = parent.open_file(
        path.file_name().context("task definition has no name")?,
        false,
    )?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_DEFINITION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DEFINITION_BYTES {
        bail!("Windows task definition exceeds bound");
    }
    maestro_shell::WindowsPrivateDirectory::validate_file(&file)?;
    parse_task_xml(std::str::from_utf8(&bytes)?).map(Some)
}

/// Fixed internal CLI command; the parent executes it with the existing five-second manager
/// deadline. No arbitrary command/script dispatch or live remote authority is added.
pub fn run_manager_helper(operation: &str, agent_dir: &Path) -> Result<TaskState> {
    let sid = current_user_sid()?;
    let (_apartment, folder) = connect_manager()?;
    run_manager_operation(&folder, operation, agent_dir, &sid)
}

fn run_manager_operation(
    folder: &ITaskFolder,
    operation: &str,
    agent_dir: &Path,
    sid: &str,
) -> Result<TaskState> {
    let paths = default_paths(agent_dir, sid);
    let before = observe(folder, agent_dir, sid)?;
    match operation {
        "query" => return Ok(before),
        "install" => {
            let options = read_definition(&paths)?.context("Windows task definition is absent")?;
            if options.user_sid != sid || options.agent_dir != agent_dir {
                bail!("Windows task install authority mismatch");
            }
            if let Some(task) = registered(folder, sid)? {
                if !before.instances.is_empty() {
                    unsafe {
                        task.Stop(0)?;
                    }
                }
                wait_dormant(folder, agent_dir, sid)?;
            }
            let descriptor = format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)");
            unsafe {
                folder.RegisterTask(
                    &BSTR::from(task_name(sid)),
                    &BSTR::from(generate_task_xml(&options)?),
                    TASK_CREATE_OR_UPDATE.0,
                    &VARIANT::from(BSTR::from(sid)),
                    &VARIANT::default(),
                    TASK_LOGON_INTERACTIVE_TOKEN,
                    &VARIANT::from(BSTR::from(descriptor)),
                )?;
            }
        }
        "start" => {
            let expected = read_definition(&paths)?.context("Windows task definition is absent")?;
            if before.definition.as_ref() != Some(&expected) {
                bail!("loaded Windows task differs from exact installed definition");
            }
            if before.instances.is_empty() {
                let task = registered(folder, sid)?.context("Windows task is absent")?;
                unsafe {
                    // An explicit Open repairs a manually disabled, otherwise exact task.
                    task.SetEnabled(VARIANT_TRUE)?;
                    task.Run(&VARIANT::default())?;
                }
            }
        }
        "uninstall" => {
            if let Some(task) = registered(folder, sid)? {
                if !before.instances.is_empty() {
                    unsafe {
                        task.Stop(0)?;
                    }
                }
                wait_dormant(folder, agent_dir, sid)?;
                unsafe {
                    folder.DeleteTask(&BSTR::from(task_name(sid)), 0)?;
                }
            }
        }
        _ => bail!("unknown Windows manager operation"),
    }
    observe(folder, agent_dir, sid)
}
fn wait_dormant(folder: &ITaskFolder, agent_dir: &Path, sid: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let state = observe(folder, agent_dir, sid)?;
        if state.absent() || state.dormant() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("Windows task did not become dormant after stop");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}
pub fn query(paths: &ServicePaths) -> Result<TaskState> {
    let executable = std::env::current_exe()?;
    let args = vec![
        "windows-service-manager".into(),
        "query".into(),
        "--dir".into(),
        paths.agent_dir.to_string_lossy().into_owned(),
    ];
    let output = crate::service::manager_output_bounded(
        executable
            .to_str()
            .context("agent executable is not Unicode")?,
        &args,
    )?;
    if !output.status.success() {
        bail!("Windows Task Scheduler query failed");
    }
    serde_json::from_slice(&output.stdout).context("Windows manager returned invalid bounded state")
}

/// EnginePID is never assumed to be the action PID. Bind the matching action's exact process
/// handle to either that exact engine process or its direct child, with creation-order proof.
pub fn supervisor_for_state(state: &TaskState) -> Result<Option<ProcessWitness>> {
    if state.absent() || state.dormant() {
        return Ok(None);
    }
    let definition = state
        .definition
        .as_ref()
        .context("Windows task has no verified definition")?;
    if state.state != TASK_STATE_RUNNING.0 || state.instances.len() != 1 {
        bail!("Windows task is not exact running or structurally absent");
    }
    let instance = &state.instances[0];
    let engine = ProcessWitness::open(instance.engine_pid)?;
    let expected = std::fs::canonicalize(&definition.binary_path)?;
    let mut matches = Vec::new();
    for candidate in agent_processes()? {
        let Some(snapshot) = candidate.snapshot_if_live()? else {
            continue;
        };
        if std::fs::canonicalize(&snapshot.image)? != expected
            || snapshot.arguments.get(1..) != Some(definition.arguments().as_slice())
        {
            continue;
        }
        if (candidate.pid == engine.pid
            || (snapshot.parent_pid == engine.pid && candidate.created >= engine.created))
            && candidate.is_live()?
            && engine.is_live()?
        {
            matches.push(candidate);
        }
    }
    if matches.len() != 1 {
        bail!("Windows task does not identify exactly one live supervisor action");
    }
    Ok(matches.pop())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    const FIXTURE: &str = "windows_service::native::tests::owned_job_fixture";
    #[test]
    fn registered_task_security_is_semantic_and_rejects_foreign_mutation() {
        let sid = current_user_sid().unwrap();
        for acl in [
            format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"),
            format!("O:{sid}D:(D;;FW;;;WD)(A;;FR;;;{sid})(A;;FW;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"),
            format!("O:SYD:P(A;;FA;;;{sid})(A;;RC;;;WD)"),
            format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FR;;;WD)"),
        ] {
            validate_task_security_descriptor(&acl, &sid).unwrap();
        }
        for acl in [
            format!("O:{sid}D:(A;;FA;;;WD)"),
            format!("O:{sid}D:(A;;WDWO;;;WD)(A;;FA;;;{sid})"),
            format!("O:{sid}D:(A;;FX;;;WD)(A;;FA;;;{sid})"),
            format!("O:WDD:(A;;FA;;;{sid})"),
            format!("O:{sid}"),
        ] {
            assert!(validate_task_security_descriptor(&acl, &sid).is_err());
        }
    }
    const MANAGER_FIXTURE: &str = "windows_service::native::tests::isolated_manager_helper_fixture";
    fn isolated_manager(folder: &str, root: &Path, operation: &str) -> Result<Option<TaskState>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", MANAGER_FIXTURE, "--ignored", "--nocapture"])
            .env("HYDRA_TEST_TASK_FOLDER", folder)
            .env("HYDRA_TEST_TASK_ROOT", root)
            .env("HYDRA_TEST_TASK_OPERATION", operation);
        let output = crate::service::manager_output_bounded_command_with_limits(
            command,
            std::time::Duration::from_secs(5),
            256 * 1024,
        )?;
        if !output.status.success() {
            bail!(
                "isolated manager {operation} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let stdout = String::from_utf8(output.stdout)?;
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix("isolated-state:"))
            .context("isolated manager omitted its result")?;
        Ok(serde_json::from_str(line)?)
    }
    struct IsolatedTask {
        folder: String,
        root: PathBuf,
    }
    impl Drop for IsolatedTask {
        fn drop(&mut self) {
            if isolated_manager(&self.folder, &self.root, "cleanup").is_err() {
                eprintln!("isolated Task Scheduler fixture cleanup failed");
            }
        }
    }
    #[test]
    #[ignore = "owned bounded helper for isolated Task Scheduler folder only"]
    fn isolated_manager_helper_fixture() {
        let result = (|| -> Result<Option<TaskState>> {
            contain_attach_only_supervisor()?;
            let folder_name = std::env::var("HYDRA_TEST_TASK_FOLDER")?;
            let suffix = folder_name
                .strip_prefix("Hydra.Qualification.")
                .context("not an isolated test folder")?;
            if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                bail!("invalid isolated task folder");
            }
            let root = PathBuf::from(
                std::env::var_os("HYDRA_TEST_TASK_ROOT").context("missing isolated root")?,
            );
            let operation = std::env::var("HYDRA_TEST_TASK_OPERATION")?;
            let sid = current_user_sid()?;
            let (_apartment, scheduler_root) = connect_manager()?;
            if operation == "create" {
                let security = VARIANT::from(BSTR::from(format!(
                    "D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
                )));
                unsafe {
                    scheduler_root.CreateFolder(&BSTR::from(&folder_name), &security)?;
                }
                return Ok(None);
            }
            let folder = unsafe { scheduler_root.GetFolder(&BSTR::from(&folder_name))? };
            if operation == "disable" {
                let task = registered(&folder, &sid)?.context("isolated task missing")?;
                unsafe {
                    task.SetEnabled(VARIANT_FALSE)?;
                }
                return observe(&folder, &root, &sid).map(Some);
            }
            if operation == "cleanup" {
                // Only this unique test folder is targeted; cleanup must also work if the
                // production parser refused Scheduler's exported XML during the assertion.
                if let Some(task) = registered(&folder, &sid)? {
                    unsafe {
                        if task.GetInstances(0)?.Count()? > 0 {
                            task.Stop(0)?;
                        }
                        folder.DeleteTask(&BSTR::from(task_name(&sid)), 0)?;
                    }
                }
                drop(folder);
                unsafe {
                    scheduler_root.DeleteFolder(&BSTR::from(&folder_name), 0)?;
                }
                return Ok(None);
            }
            run_manager_operation(&folder, &operation, &root, &sid).map(Some)
        })();
        match result {
            Ok(value) => {
                println!("isolated-state:{}", serde_json::to_string(&value).unwrap());
                std::process::exit(0);
            }
            Err(error) => {
                eprintln!("isolated manager fixture: {error:#}");
                std::process::exit(1);
            }
        }
    }
    #[test]
    fn isolated_scheduler_install_query_reinstall_uninstall_uses_bounded_real_manager() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("agent");
        let sid = current_user_sid().unwrap();
        let paths = default_paths(&root, &sid);
        let directory =
            maestro_shell::WindowsPrivateDirectory::ensure(&paths.launch_agents_dir).unwrap();
        let options = WindowsServiceOptions {
            binary_path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            build_stamp: "git=0123abcd built=1786000000000".into(),
            binding_stamp: "a".repeat(64),
            user_sid: sid,
            agent_dir: root.clone(),
            app_support_dir: root.join("desktop"),
            socket_path: r"\\.\pipe\Hydra.Maestro.qualification".into(),
            sessions: vec![],
        };
        directory
            .publish(
                std::ffi::OsStr::new("hydra-agent.service"),
                generate_task_xml(&options).unwrap().as_bytes(),
                false,
            )
            .unwrap();
        let task = IsolatedTask {
            folder: format!(
                "Hydra.Qualification.{}.{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            root,
        };
        isolated_manager(&task.folder, &task.root, "create").unwrap();
        assert!(isolated_manager(&task.folder, &task.root, "query")
            .unwrap()
            .unwrap()
            .absent());
        for _ in 0..2 {
            let installed = isolated_manager(&task.folder, &task.root, "install")
                .unwrap()
                .unwrap();
            assert!(installed.dormant());
            assert_eq!(installed.definition.as_ref(), Some(&options));
            assert_eq!(
                isolated_manager(&task.folder, &task.root, "query").unwrap(),
                Some(installed)
            );
            let disabled = isolated_manager(&task.folder, &task.root, "disable")
                .unwrap()
                .unwrap();
            assert_eq!(disabled.state, TASK_STATE_DISABLED.0);
            assert!(disabled.dormant());
        }
        assert!(isolated_manager(&task.folder, &task.root, "uninstall")
            .unwrap()
            .unwrap()
            .absent());
        assert!(isolated_manager(&task.folder, &task.root, "query")
            .unwrap()
            .unwrap()
            .absent());
    }
    /// Separate native integration gate, not a substitute for the ordinary unit suite. The caller
    /// supplies an actual built product; no production manager selector or runtime trust override.
    #[test]
    #[ignore = "requires HYDRA_TEST_PRODUCT_BINARY pointing to the separately built GUI service agent"]
    fn isolated_product_supervisor_start_bind_stop_preserves_independent_daemon() {
        product_lifecycle_fixture(false);
    }
    #[test]
    #[ignore = "requires GUI service and real pty-daemon artifacts; compiled .invalid test release only"]
    fn isolated_product_daemon_readiness_stop_reopen_retains_real_session() {
        product_lifecycle_fixture(true);
    }
    fn product_lifecycle_fixture(with_real_daemon: bool) {
        if with_real_daemon {
            let trust = crate::release_trust::active();
            assert_eq!(trust.environment, "self-managed");
            for origin in [trust.cloud_base, trust.allowed_origin] {
                let host = origin.strip_prefix("https://").unwrap();
                assert!(
                    host.ends_with(".invalid") && !host.contains(['/', '@', ':']),
                    "daemon-backed fixture requires compile-time reserved .invalid origins"
                );
            }
        }
        let binary = PathBuf::from(
            std::env::var_os("HYDRA_TEST_PRODUCT_BINARY")
                .expect("set the actual hydra-agent-service.exe artifact path"),
        );
        assert!(binary.is_absolute() && binary.is_file());
        // Architectural console-creation proof before any scheduled launch. GUI PE subsystem
        // avoids the flash that hiding a console after process startup cannot prevent.
        use std::io::{Seek, SeekFrom};
        let mut image = File::open(&binary).unwrap();
        let mut dos = [0u8; 64];
        image.read_exact(&mut dos).unwrap();
        assert_eq!(&dos[..2], b"MZ");
        let pe_offset = u32::from_le_bytes(dos[60..64].try_into().unwrap());
        assert!((64..=1024 * 1024).contains(&pe_offset));
        image.seek(SeekFrom::Start(pe_offset.into())).unwrap();
        let mut pe = [0u8; 24 + 70];
        image.read_exact(&mut pe).unwrap();
        assert_eq!(&pe[..4], b"PE\0\0");
        assert!(u16::from_le_bytes(pe[20..22].try_into().unwrap()) >= 70);
        assert!(matches!(
            u16::from_le_bytes(pe[24..26].try_into().unwrap()),
            0x10b | 0x20b
        ));
        assert_eq!(
            u16::from_le_bytes(pe[92..94].try_into().unwrap()),
            2,
            "scheduled product must be a Windows GUI-subsystem executable"
        );
        eprintln!("scheduled product console-creation metadata: PE subsystem=WINDOWS_GUI");
        let metadata = |argument: &str| {
            let output = crate::service::manager_output_bounded(
                binary.to_str().unwrap(),
                &[argument.to_string()],
            )
            .unwrap();
            assert!(output.status.success(), "product metadata command failed");
            String::from_utf8(output.stdout).unwrap()
        };
        let binding: serde_json::Value =
            serde_json::from_str(&metadata("release-binding")).unwrap();
        assert_eq!(
            binding,
            serde_json::from_str::<serde_json::Value>(crate::release_trust::binding_json())
                .unwrap(),
            "product and fixture must use the same release trust"
        );
        let version = metadata("version");
        let stamp = version
            .trim()
            .strip_prefix("hydra-agent ")
            .unwrap()
            .to_string();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("agent");
        let sid = current_user_sid().unwrap();
        let paths = default_paths(&root, &sid);
        let directory =
            maestro_shell::WindowsPrivateDirectory::ensure(&paths.launch_agents_dir).unwrap();
        let desktop = root.join("isolated-desktop");
        let _desktop = maestro_shell::WindowsPrivateDirectory::ensure(&desktop).unwrap();
        crate::device_identity::save_record(
            &root,
            &crate::device_identity::DeviceRecord {
                device_id: "synthetic-scheduler-fixture".into(),
                account_id: "synthetic-account".into(),
                cloud_base: crate::release_trust::active().cloud_base.into(),
                passkey: Some(crate::browser_cert::PasskeyPublicKey {
                    spki_b64: "AAAA".into(),
                    alg: "es256".into(),
                    rp_id: "fixture.invalid".into(),
                }),
            },
        )
        .unwrap();
        if with_real_daemon {
            crate::device_identity::load_or_create_key(&root).unwrap();
            assert!(crate::device_identity::load_key(&root).unwrap().is_some());
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket = format!(
            r"\\.\pipe\Hydra.Maestro.scheduler-test-{}-{nonce}",
            std::process::id()
        );
        let assert_endpoint_absent = |endpoint: &str| {
            assert_eq!(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(endpoint)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
        };
        assert_endpoint_absent(&socket);
        let options = WindowsServiceOptions {
            binary_path: binary.to_str().unwrap().to_string(),
            build_stamp: stamp,
            binding_stamp: crate::supervise::service_binding_stamp(),
            user_sid: sid,
            agent_dir: root.clone(),
            app_support_dir: desktop,
            socket_path: socket,
            sessions: vec![],
        };
        directory
            .publish(
                std::ffi::OsStr::new("hydra-agent.service"),
                generate_task_xml(&options).unwrap().as_bytes(),
                false,
            )
            .unwrap();
        let task = IsolatedTask {
            folder: format!("Hydra.Qualification.{}.{nonce}", std::process::id()),
            root,
        };
        let real_daemon = with_real_daemon.then(|| RealDaemonFixture::start(&options));
        let sentinel = fixture("peer");
        let independent_daemon = ProcessWitness::open(sentinel.0.id()).unwrap();
        isolated_manager(&task.folder, &task.root, "create").unwrap();
        isolated_manager(&task.folder, &task.root, "install").unwrap();
        isolated_manager(&task.folder, &task.root, "start").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let process = loop {
            let state = isolated_manager(&task.folder, &task.root, "query")
                .unwrap()
                .unwrap();
            let candidate = supervisor_for_state(&state);
            if let Ok(Some(witness)) = candidate.as_ref() {
                if isolated_manager(&task.folder, &task.root, "query")
                    .unwrap()
                    .as_ref()
                    == Some(&state)
                    && witness.is_live().unwrap()
                {
                    break candidate.unwrap().unwrap();
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "scheduled product did not bind its exact live supervisor: {candidate:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert_eq!(
            std::fs::canonicalize(&process.image).unwrap(),
            std::fs::canonicalize(&binary).unwrap()
        );
        assert_eq!(
            process.snapshot().unwrap().arguments.get(1..),
            Some(options.arguments().as_slice())
        );
        if let Some(daemon) = real_daemon.as_ref() {
            let peer = product_readiness(&task, &options, &process, daemon);
            stop_product_and_prove_retired(&task, &process, &peer);
            daemon.assert_retained();
            isolated_manager(&task.folder, &task.root, "install").unwrap();
            isolated_manager(&task.folder, &task.root, "start").unwrap();
            let reopened = await_product_supervisor(&task);
            assert!(reopened.pid != process.pid || reopened.created != process.created);
            let reopened_peer = product_readiness(&task, &options, &reopened, daemon);
            assert!(reopened_peer.pid != peer.pid || reopened_peer.created != peer.created);
            stop_product_and_prove_retired(&task, &reopened, &reopened_peer);
            daemon.assert_retained();
            assert!(independent_daemon.is_live().unwrap());
            eprintln!("isolated product: actual daemon and ConPTY generation retained across exact supervisor/peer stop and reopen; fresh scoped readiness twice; compiled .invalid origins only");
            return;
        }
        // No daemon exists at this unique endpoint: the actual product must wait attach-only,
        // publish no readiness, spawn no remote-peer, and therefore perform no cloud operation.
        assert!(crate::service_readiness::load_service_readiness(&task.root)
            .unwrap()
            .is_none());
        assert_endpoint_absent(&options.socket_path);
        assert!(agent_processes()
            .unwrap()
            .into_iter()
            .all(|candidate| candidate.snapshot().unwrap().parent_pid != process.pid));
        assert!(independent_daemon.is_live().unwrap());
        assert!(isolated_manager(&task.folder, &task.root, "uninstall")
            .unwrap()
            .unwrap()
            .absent());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while process.is_live().unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "exact supervisor did not retire"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            independent_daemon.is_live().unwrap(),
            "manager removal killed independent sentinel"
        );
        eprintln!("isolated product: exact manager/process binding and retirement passed; independent sentinel live; absent endpoint; readiness absent");
    }

    struct RealDaemonFixture {
        _child: DiagnosticDaemonChild,
        process: ProcessWitness,
        socket: PathBuf,
        session: maestro_shell::AttachedSession,
    }
    impl RealDaemonFixture {
        fn start(options: &WindowsServiceOptions) -> Self {
            use std::os::windows::process::CommandExt as _;
            let binary = PathBuf::from(
                std::env::var_os("HYDRA_TEST_DAEMON_BINARY")
                    .expect("supply actual pty-daemon.exe with its adjacent ConPTY runtime"),
            );
            assert!(binary.is_absolute() && binary.is_file());
            let mut child = OwnedChild(
                Command::new(binary)
                    .arg(&options.socket_path)
                    .creation_flags(0x08000000)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let mut stderr = child.0.stderr.take().unwrap();
            let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let captured = bytes.clone();
            let reader = std::thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                while let Ok(count) = stderr.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    let mut bytes = captured.lock().unwrap();
                    let keep = count.min((16 * 1024usize).saturating_sub(bytes.len()));
                    bytes.extend_from_slice(&buffer[..keep]);
                    // Continue draining after the capture cap so diagnostics cannot block startup.
                }
            });
            let mut child = DiagnosticDaemonChild {
                child,
                bytes,
                reader: Some(reader),
            };
            let process = ProcessWitness::open(child.child.0.id()).unwrap_or_else(|_| {
                panic!(
                    "owned actual daemon exited before witness: {}",
                    child.failure_summary()
                )
            });
            let socket = PathBuf::from(&options.socket_path);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if let Ok(mut client) = maestro_shell::DaemonClient::connect_with_timeout(
                    &socket,
                    std::time::Duration::from_millis(500),
                ) {
                    if client.list_sessions().is_ok() {
                        assert_eq!(client.server_pid(), Some(process.pid));
                        break;
                    }
                }
                assert!(
                    process.is_live().unwrap() && std::time::Instant::now() < deadline,
                    "owned actual daemon did not become ready: {}",
                    child.failure_summary()
                );
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            let mut client = maestro_shell::DaemonClient::connect_with_timeout(
                &socket,
                std::time::Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(client.server_pid(), Some(process.pid));
            let command = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("cmd.exe");
            let (session, _recovery) = client
                .start_and_attach(
                    maestro_protocol::SessionId("scheduler-retained-fixture".into()),
                    options.agent_dir.to_str().unwrap(),
                    command.to_str().unwrap(),
                    &["/d".into(), "/q".into(), "/k".into()],
                    80,
                    24,
                )
                .unwrap();
            let fixture = Self {
                _child: child,
                process,
                socket,
                session,
            };
            fixture.assert_retained();
            fixture
        }
        fn assert_retained(&self) {
            assert!(
                self.process.is_live().unwrap(),
                "actual independent daemon was retired"
            );
            let mut client = maestro_shell::DaemonClient::connect_with_timeout(
                &self.socket,
                std::time::Duration::from_secs(2),
            )
            .unwrap();
            assert_eq!(client.server_pid(), Some(self.process.pid));
            let sessions = client.list_sessions_snapshot().unwrap();
            let session = sessions
                .sessions
                .iter()
                .find(|s| s.id == self.session.id)
                .expect("real terminal session must survive connectivity lifecycle");
            assert_eq!(
                session.generation.as_deref(),
                Some(self.session.generation.as_str())
            );
        }
    }
    struct DiagnosticDaemonChild {
        child: OwnedChild,
        bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        reader: Option<std::thread::JoinHandle<()>>,
    }
    impl DiagnosticDaemonChild {
        fn failure_summary(&mut self) -> String {
            let status = self.child.0.try_wait();
            let bytes = self.bytes.lock().unwrap();
            let text = String::from_utf8_lossy(&bytes);
            // Preserve bounded machine-readable failure evidence, never raw paths/argv/log text.
            let codes = text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| {
                    word.starts_with("0x")
                        && (3..=10).contains(&word.len())
                        && word[2..].bytes().all(|b| b.is_ascii_hexdigit())
                })
                .take(8)
                .collect::<Vec<_>>();
            format!("status={status:?}; captured_stderr_bytes={}; hex_codes={codes:?}; mentions_conpty={}; mentions_pipe={}; mentions_process={}",
                bytes.len(), text.to_ascii_lowercase().contains("conpty"),
                text.to_ascii_lowercase().contains("pipe"), text.to_ascii_lowercase().contains("process"))
        }
    }
    impl Drop for DiagnosticDaemonChild {
        fn drop(&mut self) {
            let _ = self.child.0.kill();
            let _ = self.child.0.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }
    fn await_product_supervisor(task: &IsolatedTask) -> ProcessWitness {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let state = isolated_manager(&task.folder, &task.root, "query")
                .unwrap()
                .unwrap();
            if let Ok(Some(process)) = supervisor_for_state(&state) {
                if process.is_live().unwrap()
                    && isolated_manager(&task.folder, &task.root, "query")
                        .unwrap()
                        .as_ref()
                        == Some(&state)
                {
                    return process;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "exact scheduled supervisor unavailable"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    fn product_readiness(
        task: &IsolatedTask,
        options: &WindowsServiceOptions,
        supervisor: &ProcessWitness,
        daemon: &RealDaemonFixture,
    ) -> ProcessWitness {
        use crate::service_readiness::*;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let request = ServiceReadinessRequest::new(
            supervisor.pid,
            daemon.socket.clone(),
            options.build_stamp.clone(),
            options.binding_stamp.clone(),
            now,
        );
        remove_all_service_readiness(&task.root).unwrap();
        write_service_readiness_request(&task.root, &request).unwrap();
        let mut progress = ServiceReadinessProgress::default();
        let mut retained_peer: Option<ProcessWitness> = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
        loop {
            let state = isolated_manager(&task.folder, &task.root, "query")
                .unwrap()
                .unwrap();
            let observed = supervisor_for_state(&state).unwrap().unwrap();
            assert!(supervisor.matches_live(&observed).unwrap());
            restore_service_readiness_request_if_empty(&task.root, &request).unwrap();
            let record = load_service_readiness(&task.root).unwrap();
            if let Some(record) = record.as_ref() {
                assert!(matches_expected_service(record, &request, supervisor.pid));
                let peer = ProcessWitness::open(record.peer_pid).unwrap();
                let snapshot = peer.snapshot().unwrap();
                assert_eq!(snapshot.parent_pid, supervisor.pid);
                assert_eq!(
                    std::fs::canonicalize(&snapshot.image).unwrap(),
                    std::fs::canonicalize(&options.binary_path).unwrap()
                );
                assert_eq!(
                    snapshot.arguments.get(1).map(String::as_str),
                    Some("remote-peer")
                );
                let pairs = snapshot.arguments.windows(2).collect::<Vec<_>>();
                assert_eq!(pairs.iter().filter(|p| p[0] == "--dir").count(), 1);
                assert_eq!(
                    pairs.iter().find(|p| p[0] == "--dir").unwrap()[1],
                    options.agent_dir.to_str().unwrap()
                );
                assert_eq!(pairs.iter().filter(|p| p[0] == "--sock").count(), 1);
                assert_eq!(
                    pairs.iter().find(|p| p[0] == "--sock").unwrap()[1],
                    options.socket_path
                );
                if let Some(previous) = retained_peer.as_ref() {
                    assert!(
                        previous.matches_live(&peer).unwrap(),
                        "peer changed within readiness proof"
                    );
                } else {
                    retained_peer = Some(peer);
                }
            }
            daemon.assert_retained();
            if progress.observe(
                record.as_ref(),
                &request,
                supervisor.pid,
                retained_peer.as_ref().is_some_and(|p| p.is_live().unwrap()),
            ) {
                remove_all_service_readiness(&task.root).unwrap();
                return retained_peer.unwrap();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fresh scoped peer readiness unavailable"
            );
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    fn stop_product_and_prove_retired(
        task: &IsolatedTask,
        supervisor: &ProcessWitness,
        peer: &ProcessWitness,
    ) {
        assert!(isolated_manager(&task.folder, &task.root, "uninstall")
            .unwrap()
            .unwrap()
            .absent());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while supervisor.is_live().unwrap() || peer.is_live().unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "exact supervisor or peer survived stop"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(crate::service_readiness::load_service_readiness(&task.root)
            .unwrap()
            .is_none());
    }

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn fixture(kind: &str) -> OwnedChild {
        use std::os::windows::process::CommandExt as _;
        OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .creation_flags(0x08000000)
                .args(["--exact", FIXTURE, "--ignored", "--nocapture"])
                .env("HYDRA_WINDOWS_SERVICE_TEST_CHILD", kind)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    #[test]
    fn exact_process_snapshot_matches_own_argv_and_creation_identity() {
        let first = ProcessWitness::open(std::process::id()).unwrap();
        let second = ProcessWitness::open(std::process::id()).unwrap();
        assert!(first.matches_live(&second).unwrap());
        assert_eq!(
            first.snapshot().unwrap().arguments,
            std::env::args().collect::<Vec<_>>()
        );
    }
    #[test]
    fn exact_dead_process_is_skipped_but_live_unreadable_process_remains_error() {
        let mut child = fixture("peer");
        let witnessed = ProcessWitness::open(child.0.id()).unwrap();
        let limited = owned(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                child.0.id(),
            )
            .unwrap()
        });
        let unreadable = ProcessWitness {
            process: limited,
            pid: witnessed.pid,
            created: witnessed.created,
            image: witnessed.image.clone(),
        };
        assert!(unreadable.is_live().unwrap());
        assert!(
            unreadable.snapshot_if_live().is_err(),
            "live unreadable is not absence"
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!witnessed.is_live().unwrap());
        assert!(witnessed.snapshot_if_live().unwrap().is_none());
        assert!(unreadable.snapshot_if_live().unwrap().is_none());
        let error = ProcessWitness::open(child.0.id()).unwrap_err();
        assert!(
            error.is::<ProcessAlreadyExited>()
                || error
                    .downcast_ref::<windows::core::Error>()
                    .is_some_and(|error| error.code()
                        == windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0))
        );
    }
    #[test]
    #[ignore = "owned child entry point, invoked only by the bounded native fixture"]
    fn owned_job_fixture() {
        match std::env::var("HYDRA_WINDOWS_SERVICE_TEST_CHILD").as_deref() {
            Ok("supervisor") => {
                contain_attach_only_supervisor().unwrap();
                let child = fixture("peer");
                println!("owned-peer:{}", child.0.id());
                use std::io::Write as _;
                std::io::stdout().flush().unwrap();
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
            Ok("peer") => std::thread::sleep(std::time::Duration::from_secs(30)),
            _ => {}
        }
    }
    #[test]
    fn abrupt_supervisor_exit_retires_peer_but_not_independent_daemon_sentinel() {
        let sentinel = fixture("peer");
        let daemon = ProcessWitness::open(sentinel.0.id()).unwrap();
        let mut supervisor = fixture("supervisor");
        let stdout = supervisor.0.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines().take(32) {
                let line = line.unwrap();
                assert!(line.len() <= 4096);
                if let Some(pid) = line.strip_prefix("owned-peer:") {
                    let _ = send.send(pid.parse::<u32>().unwrap());
                    return;
                }
            }
        });
        let pid = receive
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("owned supervisor did not publish peer readiness");
        reader.join().unwrap();
        let peer = ProcessWitness::open(pid).unwrap();
        assert!(peer.is_live().unwrap());
        supervisor.0.kill().unwrap();
        supervisor.0.wait().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while peer.is_live().unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "exact peer survived supervisor's last Job handle"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            daemon.is_live().unwrap(),
            "independent daemon sentinel was affected"
        );
    }
}
