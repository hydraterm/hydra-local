#[path = "../packaging/windows/build_icon.rs"]
mod windows_icon;

fn main() {
    windows_icon::compile("hydra-launcher").expect("build Windows launcher icon resource");
}
