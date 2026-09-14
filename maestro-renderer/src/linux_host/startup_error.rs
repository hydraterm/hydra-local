//! One-shot startup error, before any Tao/renderer owner loop has been created.

use gtk::prelude::*;

pub(crate) fn show(title: &str, message: &str) -> Result<(), String> {
    super::window_host::initialize_xlib_threads().map_err(|error| error.to_string())?;
    gtk::init().map_err(|error| error.to_string())?;

    let dialog = gtk::MessageDialog::new(
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Error,
        gtk::ButtonsType::Close,
        message,
    );
    dialog.set_title(title);
    dialog.set_default_response(gtk::ResponseType::Close);
    let main_loop = glib::MainLoop::new(None, false);
    let close_loop = main_loop.clone();
    dialog.connect_response(move |dialog, _| {
        dialog.hide();
        close_loop.quit();
    });
    let destroy_loop = main_loop.clone();
    dialog.connect_destroy(move |_| destroy_loop.quit());
    dialog.show_all();
    dialog.present();
    // This is the initial (not nested) GTK loop: startup failed before the renderer ran.
    // The caller exits with the existing structured failure immediately after this returns.
    main_loop.run();
    Ok(())
}
