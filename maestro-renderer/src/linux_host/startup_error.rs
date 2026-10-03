//! One-shot startup error, before any Tao/renderer owner loop has been created.

use gtk::prelude::*;

pub(crate) fn show(title: &str, message: &str) -> Result<(), String> {
    present(title, message, false).map(|_| ())
}

pub(crate) fn confirm_recovery(title: &str, message: &str) -> Result<bool, String> {
    present(title, message, true)
}

fn present(title: &str, message: &str, recovery: bool) -> Result<bool, String> {
    super::window_host::initialize_xlib_threads().map_err(|error| error.to_string())?;
    gtk::init().map_err(|error| error.to_string())?;

    let dialog = gtk::MessageDialog::new(
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Error,
        gtk::ButtonsType::None,
        message,
    );
    dialog.set_title(title);
    if recovery {
        dialog.add_button("Cancel", gtk::ResponseType::Cancel);
        dialog.add_button("Restart Terminal Service", gtk::ResponseType::Accept);
        dialog.set_default_response(gtk::ResponseType::Cancel);
    } else {
        dialog.add_button("Close", gtk::ResponseType::Close);
        dialog.set_default_response(gtk::ResponseType::Close);
    }
    let confirmed = std::rc::Rc::new(std::cell::Cell::new(false));
    let response_confirmed = confirmed.clone();
    let main_loop = glib::MainLoop::new(None, false);
    let close_loop = main_loop.clone();
    dialog.connect_response(move |dialog, response| {
        response_confirmed.set(recovery && response == gtk::ResponseType::Accept);
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
    Ok(confirmed.get())
}
