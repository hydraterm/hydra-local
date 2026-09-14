//! Native startup presentation before a renderer/window event loop exists.

/// Show one error with a Close action on the process main thread, before renderer startup.
/// No daemon, session, filesystem, or retry operations are performed. Linux reports display
/// initialization failure; macOS rfd has no distinct unavailable-display error. The caller
/// keeps its original structured launch failure after this function returns.
pub fn show_startup_error_dialog(title: &str, message: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        rfd::MessageDialog::new()
            .set_title(title)
            .set_description(message)
            .set_level(rfd::MessageLevel::Error)
            .set_buttons(rfd::MessageButtons::OkCustom("Close".into()))
            .show();
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux_host::startup_error::show(title, message)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, message);
        Err("native startup error presentation is unavailable on this platform".into())
    }
}
