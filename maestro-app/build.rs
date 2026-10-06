#[path = "../packaging/windows/build_icon.rs"]
mod windows_icon;

fn main() {
    windows_icon::compile("maestro-app").expect("build Windows application icon resource");
}
