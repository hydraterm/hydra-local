# Third-party notices

Hydra Local is Apache-2.0 licensed. It depends on third-party software under the terms
listed below. This inventory is generated from the exact locked Rust and dashboard
dependency graphs; it does not change or replace any upstream licence.

- `Cargo.lock` SHA-256: `5c1a6a5750386110a42e7957f36cc4c094205c705780e3ca54c1f17c6aa65ed5`
- `dashboard-ui/package-lock.json` SHA-256: `f797f86b630338688c0357e0aa9980300d403bb92b768e92dc6457d73a087073`
- Rust dependency versions: 543
- npm dependency versions: 197

The source repository does not vendor these dependencies. Package managers retrieve each
dependency from its named upstream, where the complete corresponding licence and copyright
notices remain available. Binary distributors must carry forward every notice and source
obligation that applies to the exact dependency set they ship.

## Licence choices and notable obligations

- Where an upstream declares alternatives with `OR`, Hydra Local elects a permissive
  Apache-2.0, MIT, BSD, ISC, Zlib, BSL-1.0, CC0-1.0, MIT-0 or Unlicense option where
  one is offered; it does not elect a GPL or LGPL alternative.
- The Rust graph includes MPL-2.0 components (`cssparser`, `cssparser-macros`,
  `dtoa-short`, `option-ext` and `selectors`). They are fetched as unmodified upstream
  dependencies. MPL-covered source remains available from the links below.
- The dashboard build graph includes `caniuse-lite`, created by Ben Briggs and maintained
  by the Browserslist project, under CC-BY-4.0. It is build-time compatibility data and is
  not provider artwork or Hydra demo media.
- Linux uses Tao/GTK as its owner loop and builds the residual winit dependency X11-only.
  Its reviewed normal/build closure consumes no Wayland XML code-generation inputs and
  excludes wayland-client, wayland-protocols, Plasma, WLR and Smithay client-toolkit.
- The `serial 0.4.0` archive has no root licence file. Binary notices preserve its README
  copyright for David Cuddeback and pair it with the exact reviewed MIT fallback text.
- No third-party coding-agent logos, provider icons, screenshots, recordings or demo media
  are included in this prepared public tree.

## Locked Rust dependencies

| Package | Version | Declared licence | Upstream |
|---|---:|---|---|
| `ahash` | `0.8.12` | `MIT OR Apache-2.0` | [source](https://github.com/tkaitchuck/ahash) |
| `aho-corasick` | `1.1.4` | `Unlicense OR MIT` | [source](https://github.com/BurntSushi/aho-corasick) |
| `alacritty_terminal` | `0.26.0` | `Apache-2.0` | [source](https://github.com/alacritty/alacritty) |
| `android-activity` | `0.6.1` | `MIT OR Apache-2.0` | [source](https://github.com/rust-mobile/android-activity) |
| `android-properties` | `0.2.2` | `MIT` | [source](https://github.com/miklelappo/android-properties) |
| `android_system_properties` | `0.1.5` | `MIT/Apache-2.0` | [source](https://github.com/nical/android_system_properties) |
| `anyhow` | `1.0.103` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/anyhow) |
| `arboard` | `3.4.1` | `MIT OR Apache-2.0` | [source](https://github.com/1Password/arboard) |
| `arrayvec` | `0.7.6` | `MIT OR Apache-2.0` | [source](https://github.com/bluss/arrayvec) |
| `as-raw-xcb-connection` | `1.0.1` | `MIT OR Apache-2.0` | [source](https://github.com/psychon/as-raw-xcb-connection) |
| `ash` | `0.38.0+1.3.281` | `MIT OR Apache-2.0` | [source](https://github.com/ash-rs/ash) |
| `ashpd` | `0.11.1` | `MIT` | [source](https://github.com/bilelmoussaoui/ashpd) |
| `async-broadcast` | `0.7.2` | `MIT OR Apache-2.0` | [source](https://github.com/smol-rs/async-broadcast) |
| `async-channel` | `2.5.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-channel) |
| `async-executor` | `1.14.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-executor) |
| `async-fs` | `2.2.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-fs) |
| `async-io` | `2.6.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-io) |
| `async-lock` | `3.4.2` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-lock) |
| `async-net` | `2.0.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-net) |
| `async-process` | `2.5.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-process) |
| `async-recursion` | `1.1.1` | `MIT OR Apache-2.0` | [source](https://github.com/dcchut/async-recursion) |
| `async-signal` | `0.2.14` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-signal) |
| `async-task` | `4.7.1` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/async-task) |
| `async-trait` | `0.1.89` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/async-trait) |
| `atk` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `atk-sys` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `atomic-waker` | `1.1.2` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/atomic-waker) |
| `autocfg` | `1.5.1` | `Apache-2.0 OR MIT` | [source](https://github.com/cuviper/autocfg) |
| `base64` | `0.22.1` | `MIT OR Apache-2.0` | [source](https://github.com/marshallpierce/rust-base64) |
| `bit-set` | `0.8.0` | `Apache-2.0 OR MIT` | [source](https://github.com/contain-rs/bit-set) |
| `bit-vec` | `0.8.0` | `Apache-2.0 OR MIT` | [source](https://github.com/contain-rs/bit-vec) |
| `bitflags` | `1.3.2` | `MIT/Apache-2.0` | [source](https://github.com/bitflags/bitflags) |
| `bitflags` | `2.13.0` | `MIT OR Apache-2.0` | [source](https://github.com/bitflags/bitflags) |
| `block` | `0.1.6` | `MIT` | [source](http://github.com/SSheldon/rust-block) |
| `block-buffer` | `0.10.4` | `MIT OR Apache-2.0` | [source](https://github.com/RustCrypto/utils) |
| `block2` | `0.5.1` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `block2` | `0.6.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `blocking` | `1.6.2` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/blocking) |
| `bumpalo` | `3.20.3` | `MIT OR Apache-2.0` | [source](https://github.com/fitzgen/bumpalo) |
| `bytemuck` | `1.25.0` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/Lokathor/bytemuck) |
| `bytemuck_derive` | `1.10.2` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/Lokathor/bytemuck) |
| `bytes` | `1.11.1` | `MIT` | [source](https://github.com/tokio-rs/bytes) |
| `cairo-rs` | `0.18.5` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `cairo-sys-rs` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `calloop` | `0.13.0` | `MIT` | [source](https://github.com/Smithay/calloop) |
| `castaway` | `0.2.4` | `MIT` | [source](https://github.com/sagebind/castaway) |
| `cc` | `1.2.63` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/cc-rs) |
| `cesu8` | `1.1.0` | `Apache-2.0/MIT` | [source](https://github.com/emk/cesu8-rs) |
| `cfg-expr` | `0.15.8` | `MIT OR Apache-2.0` | [source](https://github.com/EmbarkStudios/cfg-expr) |
| `cfg-if` | `1.0.4` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/cfg-if) |
| `cfg_aliases` | `0.1.1` | `MIT` | [source](https://github.com/katharostech/cfg_aliases) |
| `cfg_aliases` | `0.2.1` | `MIT` | [source](https://github.com/katharostech/cfg_aliases) |
| `clipboard-win` | `5.4.1` | `BSL-1.0` | [source](https://github.com/DoumanAsh/clipboard-win) |
| `codespan-reporting` | `0.11.1` | `Apache-2.0` | [source](https://github.com/brendanzab/codespan) |
| `combine` | `4.6.7` | `MIT` | [source](https://github.com/Marwes/combine) |
| `compact_str` | `0.8.2` | `MIT` | [source](https://github.com/ParkMyCar/compact_str) |
| `concurrent-queue` | `2.5.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/concurrent-queue) |
| `cookie` | `0.18.1` | `MIT OR Apache-2.0` | [source](https://github.com/SergioBenitez/cookie-rs) |
| `core-foundation` | `0.10.1` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `core-foundation` | `0.9.4` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `core-foundation-sys` | `0.8.7` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `core-graphics` | `0.23.2` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `core-graphics` | `0.25.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `core-graphics-types` | `0.1.3` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `core-graphics-types` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/core-foundation-rs) |
| `cosmic-text` | `0.12.1` | `MIT OR Apache-2.0` | [source](https://github.com/pop-os/cosmic-text) |
| `cpufeatures` | `0.2.17` | `MIT OR Apache-2.0` | [source](https://github.com/RustCrypto/utils) |
| `crossbeam-channel` | `0.5.15` | `MIT OR Apache-2.0` | [source](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-deque` | `0.8.6` | `MIT OR Apache-2.0` | [source](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-epoch` | `0.9.20` | `MIT OR Apache-2.0` | [source](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-utils` | `0.8.21` | `MIT OR Apache-2.0` | [source](https://github.com/crossbeam-rs/crossbeam) |
| `crypto-common` | `0.1.7` | `MIT OR Apache-2.0` | [source](https://github.com/RustCrypto/traits) |
| `cssparser` | `0.36.0` | `MPL-2.0` | [source](https://github.com/servo/rust-cssparser) |
| `cssparser-macros` | `0.6.1` | `MPL-2.0` | [source](https://github.com/servo/rust-cssparser) |
| `cursor-icon` | `1.2.0` | `MIT OR Apache-2.0 OR Zlib` | [source](https://github.com/rust-windowing/cursor-icon) |
| `deranged` | `0.5.8` | `MIT OR Apache-2.0` | [source](https://github.com/jhpratt/deranged) |
| `derive_more` | `2.1.1` | `MIT` | [source](https://github.com/JelteF/derive_more) |
| `derive_more-impl` | `2.1.1` | `MIT` | [source](https://github.com/JelteF/derive_more) |
| `digest` | `0.10.7` | `MIT OR Apache-2.0` | [source](https://github.com/RustCrypto/traits) |
| `dirs` | `6.0.0` | `MIT OR Apache-2.0` | [source](https://github.com/soc/dirs-rs) |
| `dirs-sys` | `0.5.0` | `MIT OR Apache-2.0` | [source](https://github.com/dirs-dev/dirs-sys-rs) |
| `dispatch` | `0.2.0` | `MIT` | [source](http://github.com/SSheldon/rust-dispatch) |
| `dispatch2` | `0.3.1` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/madsmtm/objc2) |
| `displaydoc` | `0.2.6` | `MIT OR Apache-2.0` | [source](https://github.com/yaahc/displaydoc) |
| `dlib` | `0.5.3` | `MIT` | [source](https://github.com/elinorbgr/dlib) |
| `dlopen2` | `0.8.2` | `MIT` | [source](https://github.com/OpenByteDev/dlopen2) |
| `dlopen2_derive` | `0.4.3` | `MIT` | [source](https://github.com/OpenByteDev/dlopen2) |
| `document-features` | `0.2.12` | `MIT OR Apache-2.0` | [source](https://github.com/slint-ui/document-features) |
| `dom_query` | `0.27.0` | `MIT` | [source](https://github.com/niklak/dom_query) |
| `downcast-rs` | `1.2.1` | `MIT/Apache-2.0` | [source](https://github.com/marcianx/downcast-rs) |
| `dpi` | `0.1.2` | `Apache-2.0 AND MIT` | [source](https://github.com/rust-windowing/winit) |
| `dtoa` | `1.0.11` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/dtoa) |
| `dtoa-short` | `0.3.5` | `MPL-2.0` | [source](https://github.com/upsuper/dtoa-short) |
| `dunce` | `1.0.5` | `CC0-1.0 OR MIT-0 OR Apache-2.0` | [source](https://gitlab.com/kornelski/dunce) |
| `either` | `1.16.0` | `MIT OR Apache-2.0` | [source](https://github.com/rayon-rs/either) |
| `endi` | `1.1.1` | `MIT` | [source](https://github.com/zeenix/endi) |
| `enumflags2` | `0.7.12` | `MIT OR Apache-2.0` | [source](https://github.com/meithecatte/enumflags2) |
| `enumflags2_derive` | `0.7.12` | `MIT OR Apache-2.0` | [source](https://github.com/meithecatte/enumflags2) |
| `equivalent` | `1.0.2` | `Apache-2.0 OR MIT` | [source](https://github.com/indexmap-rs/equivalent) |
| `errno` | `0.3.14` | `MIT OR Apache-2.0` | [source](https://github.com/lambda-fairy/rust-errno) |
| `error-code` | `3.3.2` | `BSL-1.0` | [source](https://github.com/DoumanAsh/error-code) |
| `etagere` | `0.2.15` | `MIT/Apache-2.0` | [source](https://github.com/nical/etagere) |
| `euclid` | `0.22.14` | `MIT OR Apache-2.0` | [source](https://github.com/servo/euclid) |
| `event-listener` | `5.4.2` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/event-listener) |
| `event-listener-strategy` | `0.5.4` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/event-listener-strategy) |
| `fallible-iterator` | `0.3.0` | `MIT/Apache-2.0` | [source](https://github.com/sfackler/rust-fallible-iterator) |
| `fallible-streaming-iterator` | `0.1.9` | `MIT/Apache-2.0` | [source](https://github.com/sfackler/fallible-streaming-iterator) |
| `fastrand` | `2.4.1` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/fastrand) |
| `field-offset` | `0.3.6` | `MIT OR Apache-2.0` | [source](https://github.com/Diggsey/rust-field-offset) |
| `filedescriptor` | `0.8.3` | `MIT` | [source](https://github.com/wezterm/wezterm) |
| `find-msvc-tools` | `0.1.9` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/cc-rs) |
| `foldhash` | `0.1.5` | `Zlib` | [source](https://github.com/orlp/foldhash) |
| `foldhash` | `0.2.0` | `Zlib` | [source](https://github.com/orlp/foldhash) |
| `font-types` | `0.7.3` | `MIT OR Apache-2.0` | [source](https://github.com/googlefonts/fontations) |
| `fontconfig-parser` | `0.5.8` | `MIT` | [source](https://github.com/Riey/fontconfig-parser) |
| `fontdb` | `0.16.2` | `MIT` | [source](https://github.com/RazrFalcon/fontdb) |
| `foreign-types` | `0.5.0` | `MIT/Apache-2.0` | [source](https://github.com/sfackler/foreign-types) |
| `foreign-types-macros` | `0.2.3` | `MIT/Apache-2.0` | [source](https://github.com/sfackler/foreign-types) |
| `foreign-types-shared` | `0.3.1` | `MIT/Apache-2.0` | [source](https://github.com/sfackler/foreign-types) |
| `form_urlencoded` | `1.2.2` | `MIT OR Apache-2.0` | [source](https://github.com/servo/rust-url) |
| `futures-channel` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `futures-core` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `futures-executor` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `futures-io` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `futures-lite` | `2.6.1` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/futures-lite) |
| `futures-macro` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `futures-task` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `futures-util` | `0.3.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/futures-rs) |
| `gdk` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `gdk-pixbuf` | `0.18.5` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `gdk-pixbuf-sys` | `0.18.0` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `gdk-sys` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `gdkwayland-sys` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `gdkx11` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `gdkx11-sys` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `generic-array` | `0.14.7` | `MIT` | [source](https://github.com/fizyk20/generic-array.git) |
| `gethostname` | `1.1.0` | `Apache-2.0` | [source](https://codeberg.org/swsnr/gethostname.rs.git) |
| `getrandom` | `0.2.17` | `MIT OR Apache-2.0` | [source](https://github.com/rust-random/getrandom) |
| `getrandom` | `0.3.4` | `MIT OR Apache-2.0` | [source](https://github.com/rust-random/getrandom) |
| `getrandom` | `0.4.2` | `MIT OR Apache-2.0` | [source](https://github.com/rust-random/getrandom) |
| `gio` | `0.18.4` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `gio-sys` | `0.18.1` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `gl_generator` | `0.14.0` | `Apache-2.0` | [source](https://github.com/brendanzab/gl-rs/) |
| `glib` | `0.18.5` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `glib-macros` | `0.18.5` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `glib-sys` | `0.18.1` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `glow` | `0.14.2` | `MIT OR Apache-2.0 OR Zlib` | [source](https://github.com/grovesNL/glow) |
| `glutin_wgl_sys` | `0.6.1` | `Apache-2.0` | [source](https://github.com/rust-windowing/glutin) |
| `glyphon` | `0.7.0` | `MIT OR Apache-2.0 OR Zlib` | [source](https://github.com/grovesNL/glyphon) |
| `gobject-sys` | `0.18.0` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `gpu-alloc` | `0.6.0` | `MIT OR Apache-2.0` | [source](https://github.com/zakarumych/gpu-alloc) |
| `gpu-alloc-types` | `0.3.0` | `MIT OR Apache-2.0` | [source](https://github.com/zakarumych/gpu-alloc) |
| `gpu-allocator` | `0.27.0` | `MIT OR Apache-2.0` | [source](https://github.com/Traverse-Research/gpu-allocator) |
| `gpu-descriptor` | `0.3.2` | `MIT OR Apache-2.0` | [source](https://github.com/zakarumych/gpu-descriptor) |
| `gpu-descriptor-types` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/zakarumych/gpu-descriptor) |
| `gtk` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `gtk-sys` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `gtk3-macros` | `0.18.2` | `MIT` | [source](https://github.com/gtk-rs/gtk3-rs) |
| `hashbrown` | `0.14.5` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/hashbrown) |
| `hashbrown` | `0.15.5` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/hashbrown) |
| `hashbrown` | `0.17.1` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/hashbrown) |
| `hashlink` | `0.9.1` | `MIT OR Apache-2.0` | [source](https://github.com/kyren/hashlink) |
| `heck` | `0.4.1` | `MIT OR Apache-2.0` | [source](https://github.com/withoutboats/heck) |
| `heck` | `0.5.0` | `MIT OR Apache-2.0` | [source](https://github.com/withoutboats/heck) |
| `hermit-abi` | `0.5.2` | `MIT OR Apache-2.0` | [source](https://github.com/hermit-os/hermit-rs) |
| `hex` | `0.4.3` | `MIT OR Apache-2.0` | [source](https://github.com/KokaKiwi/rust-hex) |
| `hexf-parse` | `0.2.1` | `CC0-1.0` | [source](https://github.com/lifthrasiir/hexf) |
| `home` | `0.5.12` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/cargo) |
| `html5ever` | `0.38.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/html5ever) |
| `http` | `1.4.2` | `MIT OR Apache-2.0` | [source](https://github.com/hyperium/http) |
| `icu_collections` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `icu_locale_core` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `icu_normalizer` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `icu_normalizer_data` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `icu_properties` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `icu_properties_data` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `icu_provider` | `2.2.0` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `id-arena` | `2.3.0` | `MIT/Apache-2.0` | [source](https://github.com/fitzgen/id-arena) |
| `idna` | `1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/rust-url/) |
| `idna_adapter` | `1.2.2` | `Apache-2.0 OR MIT` | [source](https://github.com/hsivonen/idna_adapter) |
| `indexmap` | `2.14.0` | `Apache-2.0 OR MIT` | [source](https://github.com/indexmap-rs/indexmap) |
| `ioctl-rs` | `0.1.6` | `MIT` | [source](https://github.com/dcuddeback/ioctl-rs) |
| `itoa` | `1.0.18` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/itoa) |
| `javascriptcore-rs` | `1.1.2` | `MIT` | [source](https://github.com/tauri-apps/javascriptcore-rs) |
| `javascriptcore-rs-sys` | `1.1.1` | `MIT` | [source](https://github.com/tauri-apps/javascriptcore-rs) |
| `jni` | `0.21.1` | `MIT/Apache-2.0` | [source](https://github.com/jni-rs/jni-rs) |
| `jni` | `0.22.4` | `MIT OR Apache-2.0` | [source](https://github.com/jni-rs/jni-rs) |
| `jni-macros` | `0.22.4` | `MIT OR Apache-2.0` | [source](https://github.com/jni-rs/jni-rs) |
| `jni-sys` | `0.3.1` | `MIT OR Apache-2.0` | [source](https://github.com/jni-rs/jni-sys) |
| `jni-sys` | `0.4.1` | `MIT OR Apache-2.0` | [source](https://github.com/jni-rs/jni-sys) |
| `jni-sys-macros` | `0.4.1` | `MIT OR Apache-2.0` | [source](https://github.com/jni-rs/jni-sys) |
| `jobserver` | `0.1.34` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/jobserver-rs) |
| `js-sys` | `0.3.99` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) |
| `khronos-egl` | `6.0.0` | `MIT/Apache-2.0` | [source](https://github.com/timothee-haudebourg/khronos-egl) |
| `khronos_api` | `3.1.0` | `Apache-2.0` | [source](https://github.com/brendanzab/gl-rs/) |
| `lazy_static` | `1.5.0` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang-nursery/lazy-static.rs) |
| `leb128fmt` | `0.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/bluk/leb128fmt) |
| `libc` | `0.2.186` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/libc) |
| `libloading` | `0.8.9` | `ISC` | [source](https://github.com/nagisa/rust_libloading/) |
| `libm` | `0.2.16` | `MIT` | [source](https://github.com/rust-lang/compiler-builtins) |
| `libredox` | `0.1.17` | `MIT` | [source](https://gitlab.redox-os.org/redox-os/libredox.git) |
| `libsqlite3-sys` | `0.30.1` | `MIT` | [source](https://github.com/rusqlite/rusqlite) |
| `linux-raw-sys` | `0.12.1` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/sunfishcode/linux-raw-sys) |
| `linux-raw-sys` | `0.4.15` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/sunfishcode/linux-raw-sys) |
| `litemap` | `0.8.2` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `litrs` | `1.0.0` | `MIT OR Apache-2.0` | [source](https://github.com/LukasKalbertodt/litrs) |
| `lock_api` | `0.4.14` | `MIT OR Apache-2.0` | [source](https://github.com/Amanieu/parking_lot) |
| `log` | `0.4.32` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/log) |
| `lru` | `0.12.5` | `MIT` | [source](https://github.com/jeromefroe/lru-rs.git) |
| `malloc_buf` | `0.0.6` | `MIT` | [source](https://github.com/SSheldon/malloc_buf) |
| `markup5ever` | `0.38.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/html5ever) |
| `matchers` | `0.2.0` | `MIT` | [source](https://github.com/hawkw/matchers) |
| `memchr` | `2.8.1` | `Unlicense OR MIT` | [source](https://github.com/BurntSushi/memchr) |
| `memmap2` | `0.9.11` | `MIT OR Apache-2.0` | [source](https://github.com/RazrFalcon/memmap2-rs) |
| `memoffset` | `0.6.5` | `MIT` | [source](https://github.com/Gilnaa/memoffset) |
| `memoffset` | `0.9.1` | `MIT` | [source](https://github.com/Gilnaa/memoffset) |
| `metal` | `0.29.0` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/metal-rs) |
| `mio` | `1.2.1` | `MIT` | [source](https://github.com/tokio-rs/mio) |
| `miow` | `0.6.1` | `MIT OR Apache-2.0` | [source](https://github.com/yoshuawuyts/miow) |
| `naga` | `23.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/wgpu/tree/trunk/naga) |
| `ndk` | `0.9.0` | `MIT OR Apache-2.0` | [source](https://github.com/rust-mobile/ndk) |
| `ndk-context` | `0.1.1` | `MIT OR Apache-2.0` | [source](https://github.com/rust-windowing/android-ndk-rs) |
| `ndk-sys` | `0.5.0+25.2.9519653` | `MIT OR Apache-2.0` | [source](https://github.com/rust-mobile/ndk) |
| `ndk-sys` | `0.6.0+11769913` | `MIT OR Apache-2.0` | [source](https://github.com/rust-mobile/ndk) |
| `new_debug_unreachable` | `1.0.6` | `MIT` | [source](https://github.com/mbrubeck/rust-debug-unreachable) |
| `nix` | `0.25.1` | `MIT` | [source](https://github.com/nix-rust/nix) |
| `nu-ansi-term` | `0.50.3` | `MIT` | [source](https://github.com/nushell/nu-ansi-term) |
| `num-conv` | `0.2.2` | `MIT OR Apache-2.0` | [source](https://github.com/jhpratt/num-conv) |
| `num-traits` | `0.2.19` | `MIT OR Apache-2.0` | [source](https://github.com/rust-num/num-traits) |
| `num_enum` | `0.7.6` | `BSD-3-Clause OR MIT OR Apache-2.0` | [source](https://github.com/illicitonion/num_enum) |
| `num_enum_derive` | `0.7.6` | `BSD-3-Clause OR MIT OR Apache-2.0` | [source](https://github.com/illicitonion/num_enum) |
| `objc` | `0.2.7` | `MIT` | [source](http://github.com/SSheldon/rust-objc) |
| `objc-sys` | `0.3.5` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2` | `0.5.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2` | `0.6.4` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-app-kit` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-app-kit` | `0.3.2` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-cloud-kit` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-contacts` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-core-data` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-core-foundation` | `0.3.2` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-core-image` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-core-location` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-encode` | `4.1.0` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-exception-helper` | `0.1.1` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-foundation` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-foundation` | `0.3.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-link-presentation` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-metal` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-quartz-core` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-symbols` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-ui-kit` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-ui-kit` | `0.3.2` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-uniform-type-identifiers` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-user-notifications` | `0.2.2` | `MIT` | [source](https://github.com/madsmtm/objc2) |
| `objc2-web-kit` | `0.3.2` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/madsmtm/objc2) |
| `once_cell` | `1.21.4` | `MIT OR Apache-2.0` | [source](https://github.com/matklad/once_cell) |
| `option-ext` | `0.2.0` | `MPL-2.0` | [source](https://github.com/soc/option-ext.git) |
| `orbclient` | `0.3.55` | `MIT` | [source](https://gitlab.redox-os.org/redox-os/orbclient) |
| `ordered-stream` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/danieldg/ordered-stream) |
| `pango` | `0.18.3` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `pango-sys` | `0.18.0` | `MIT` | [source](https://github.com/gtk-rs/gtk-rs-core) |
| `parking` | `2.2.1` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/parking) |
| `parking_lot` | `0.12.5` | `MIT OR Apache-2.0` | [source](https://github.com/Amanieu/parking_lot) |
| `parking_lot_core` | `0.9.12` | `MIT OR Apache-2.0` | [source](https://github.com/Amanieu/parking_lot) |
| `paste` | `1.0.15` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/paste) |
| `percent-encoding` | `2.3.2` | `MIT OR Apache-2.0` | [source](https://github.com/servo/rust-url/) |
| `phf` | `0.13.1` | `MIT` | [source](https://github.com/rust-phf/rust-phf) |
| `phf_codegen` | `0.13.1` | `MIT` | [source](https://github.com/rust-phf/rust-phf) |
| `phf_generator` | `0.13.1` | `MIT` | [source](https://github.com/rust-phf/rust-phf) |
| `phf_macros` | `0.13.1` | `MIT` | [source](https://github.com/rust-phf/rust-phf) |
| `phf_shared` | `0.13.1` | `MIT` | [source](https://github.com/rust-phf/rust-phf) |
| `pin-project` | `1.1.13` | `Apache-2.0 OR MIT` | [source](https://github.com/taiki-e/pin-project) |
| `pin-project-internal` | `1.1.13` | `Apache-2.0 OR MIT` | [source](https://github.com/taiki-e/pin-project) |
| `pin-project-lite` | `0.2.17` | `Apache-2.0 OR MIT` | [source](https://github.com/taiki-e/pin-project-lite) |
| `pin-utils` | `0.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang-nursery/pin-utils) |
| `piper` | `0.2.5` | `MIT OR Apache-2.0` | [source](https://github.com/smol-rs/piper) |
| `pkg-config` | `0.3.33` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/pkg-config-rs) |
| `plain` | `0.2.3` | `MIT/Apache-2.0` | [source](https://github.com/randomites/plain) |
| `polling` | `3.11.0` | `Apache-2.0 OR MIT` | [source](https://github.com/smol-rs/polling) |
| `pollster` | `0.3.0` | `Apache-2.0/MIT` | [source](https://github.com/zesterer/pollster) |
| `pollster` | `0.4.0` | `Apache-2.0/MIT` | [source](https://github.com/zesterer/pollster) |
| `portable-pty` | `0.8.1` | `MIT` | [source](https://github.com/wez/wezterm) |
| `potential_utf` | `0.1.5` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `powerfmt` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/jhpratt/powerfmt) |
| `ppv-lite86` | `0.2.21` | `MIT OR Apache-2.0` | [source](https://github.com/cryptocorrosion/cryptocorrosion) |
| `precomputed-hash` | `0.1.1` | `MIT` | [source](https://github.com/emilio/precomputed-hash) |
| `presser` | `0.3.1` | `MIT OR Apache-2.0` | [source](https://github.com/EmbarkStudios/presser) |
| `prettyplease` | `0.2.37` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/prettyplease) |
| `proc-macro-crate` | `1.3.1` | `MIT OR Apache-2.0` | [source](https://github.com/bkchr/proc-macro-crate) |
| `proc-macro-crate` | `2.0.2` | `MIT OR Apache-2.0` | [source](https://github.com/bkchr/proc-macro-crate) |
| `proc-macro-crate` | `3.5.0` | `MIT OR Apache-2.0` | [source](https://github.com/bkchr/proc-macro-crate) |
| `proc-macro-error` | `1.0.4` | `MIT OR Apache-2.0` | [source](https://gitlab.com/CreepySkeleton/proc-macro-error) |
| `proc-macro-error-attr` | `1.0.4` | `MIT OR Apache-2.0` | [source](https://gitlab.com/CreepySkeleton/proc-macro-error) |
| `proc-macro2` | `1.0.106` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/proc-macro2) |
| `profiling` | `1.0.18` | `MIT OR Apache-2.0` | [source](https://github.com/aclysma/profiling) |
| `quick-xml` | `0.41.0` | `MIT` | [source](https://github.com/tafia/quick-xml) |
| `quote` | `1.0.45` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/quote) |
| `r-efi` | `5.3.0` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | [source](https://github.com/r-efi/r-efi) |
| `r-efi` | `6.0.0` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | [source](https://github.com/r-efi/r-efi) |
| `rand` | `0.9.4` | `MIT OR Apache-2.0` | [source](https://github.com/rust-random/rand) |
| `rand_chacha` | `0.9.0` | `MIT OR Apache-2.0` | [source](https://github.com/rust-random/rand) |
| `rand_core` | `0.9.5` | `MIT OR Apache-2.0` | [source](https://github.com/rust-random/rand) |
| `range-alloc` | `0.1.5` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/range-alloc) |
| `rangemap` | `1.7.1` | `MIT/Apache-2.0` | [source](https://github.com/jeffparsons/rangemap) |
| `raw-window-handle` | `0.6.2` | `MIT OR Apache-2.0 OR Zlib` | [source](https://github.com/rust-windowing/raw-window-handle) |
| `rayon` | `1.12.0` | `MIT OR Apache-2.0` | [source](https://github.com/rayon-rs/rayon) |
| `rayon-core` | `1.13.0` | `MIT OR Apache-2.0` | [source](https://github.com/rayon-rs/rayon) |
| `read-fonts` | `0.22.7` | `MIT OR Apache-2.0` | [source](https://github.com/googlefonts/fontations) |
| `redox_syscall` | `0.4.1` | `MIT` | [source](https://gitlab.redox-os.org/redox-os/syscall) |
| `redox_syscall` | `0.5.18` | `MIT` | [source](https://gitlab.redox-os.org/redox-os/syscall) |
| `redox_syscall` | `0.8.1` | `MIT` | [source](https://gitlab.redox-os.org/redox-os/syscall) |
| `redox_users` | `0.5.2` | `MIT` | [source](https://gitlab.redox-os.org/redox-os/users) |
| `regex-automata` | `0.4.14` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/regex) |
| `regex-syntax` | `0.8.10` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/regex) |
| `renderdoc-sys` | `1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/ebkalderon/renderdoc-rs) |
| `rfd` | `0.15.4` | `MIT` | [source](https://github.com/PolyMeilex/rfd) |
| `roxmltree` | `0.20.0` | `MIT OR Apache-2.0` | [source](https://github.com/RazrFalcon/roxmltree) |
| `rusqlite` | `0.32.1` | `MIT` | [source](https://github.com/rusqlite/rusqlite) |
| `rustc-hash` | `1.1.0` | `Apache-2.0/MIT` | [source](https://github.com/rust-lang-nursery/rustc-hash) |
| `rustc-hash` | `2.1.2` | `Apache-2.0 OR MIT` | [source](https://github.com/rust-lang/rustc-hash) |
| `rustc_version` | `0.4.1` | `MIT OR Apache-2.0` | [source](https://github.com/djc/rustc-version-rs) |
| `rustix` | `0.38.44` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/rustix) |
| `rustix` | `1.1.4` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/rustix) |
| `rustix-openpty` | `0.2.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/sunfishcode/rustix-openpty) |
| `rustversion` | `1.0.22` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/rustversion) |
| `rustybuzz` | `0.14.1` | `MIT` | [source](https://github.com/RazrFalcon/rustybuzz) |
| `ryu` | `1.0.23` | `Apache-2.0 OR BSL-1.0` | [source](https://github.com/dtolnay/ryu) |
| `same-file` | `1.0.6` | `Unlicense/MIT` | [source](https://github.com/BurntSushi/same-file) |
| `scoped-tls` | `1.0.1` | `MIT/Apache-2.0` | [source](https://github.com/alexcrichton/scoped-tls) |
| `scopeguard` | `1.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/bluss/scopeguard) |
| `selectors` | `0.36.1` | `MPL-2.0` | [source](https://github.com/servo/stylo) |
| `self_cell` | `1.2.2` | `Apache-2.0 OR GPL-2.0-only` | [source](https://github.com/Voultapher/self_cell) |
| `semver` | `1.0.28` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/semver) |
| `serde` | `1.0.228` | `MIT OR Apache-2.0` | [source](https://github.com/serde-rs/serde) |
| `serde_core` | `1.0.228` | `MIT OR Apache-2.0` | [source](https://github.com/serde-rs/serde) |
| `serde_derive` | `1.0.228` | `MIT OR Apache-2.0` | [source](https://github.com/serde-rs/serde) |
| `serde_json` | `1.0.150` | `MIT OR Apache-2.0` | [source](https://github.com/serde-rs/json) |
| `serde_repr` | `0.1.20` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/serde-repr) |
| `serde_spanned` | `0.6.9` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `serial` | `0.4.0` | `MIT` | [source](https://github.com/dcuddeback/serial-rs) |
| `serial-core` | `0.4.0` | `MIT` | [source](https://github.com/dcuddeback/serial-rs) |
| `serial-unix` | `0.4.0` | `MIT` | [source](https://github.com/dcuddeback/serial-rs) |
| `serial-windows` | `0.4.0` | `MIT` | [source](https://github.com/dcuddeback/serial-rs) |
| `servo_arc` | `0.4.3` | `MIT OR Apache-2.0` | [source](https://github.com/servo/stylo) |
| `sha2` | `0.10.9` | `MIT OR Apache-2.0` | [source](https://github.com/RustCrypto/hashes) |
| `sharded-slab` | `0.1.7` | `MIT` | [source](https://github.com/hawkw/sharded-slab) |
| `shared_library` | `0.1.9` | `Apache-2.0/MIT` | [source](https://github.com/tomaka/shared_library/) |
| `shell-words` | `1.1.1` | `MIT/Apache-2.0` | [source](https://github.com/tmiasko/shell-words) |
| `shlex` | `2.0.1` | `MIT OR Apache-2.0` | [source](https://github.com/comex/rust-shlex) |
| `signal-hook` | `0.4.4` | `MIT OR Apache-2.0` | [source](https://github.com/vorner/signal-hook) |
| `signal-hook-registry` | `1.4.8` | `MIT OR Apache-2.0` | [source](https://github.com/vorner/signal-hook) |
| `simd_cesu8` | `1.1.1` | `Apache-2.0 OR MIT` | [source](https://github.com/seancroach/simd_cesu8) |
| `simdutf8` | `0.1.5` | `MIT OR Apache-2.0` | [source](https://github.com/rusticstuff/simdutf8) |
| `siphasher` | `1.0.3` | `MIT/Apache-2.0` | [source](https://github.com/jedisct1/rust-siphash) |
| `skrifa` | `0.22.3` | `MIT OR Apache-2.0` | [source](https://github.com/googlefonts/fontations) |
| `slab` | `0.4.12` | `MIT` | [source](https://github.com/tokio-rs/slab) |
| `slotmap` | `1.1.1` | `Zlib` | [source](https://github.com/orlp/slotmap) |
| `smallvec` | `1.15.1` | `MIT OR Apache-2.0` | [source](https://github.com/servo/rust-smallvec) |
| `smol_str` | `0.2.2` | `MIT OR Apache-2.0` | [source](https://github.com/rust-analyzer/smol_str) |
| `socket2` | `0.6.4` | `MIT OR Apache-2.0` | [source](https://github.com/rust-lang/socket2) |
| `soup3` | `0.5.0` | `MIT` | [source](https://gitlab.gnome.org/World/Rust/soup3-rs) |
| `soup3-sys` | `0.5.0` | `MIT` | [source](https://gitlab.gnome.org/World/Rust/soup3-rs) |
| `spirv` | `0.3.0+sdk-1.3.268.0` | `Apache-2.0` | [source](https://github.com/gfx-rs/rspirv) |
| `stable_deref_trait` | `1.2.1` | `MIT OR Apache-2.0` | [source](https://github.com/storyyeller/stable_deref_trait) |
| `static_assertions` | `1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/nvzqz/static-assertions-rs) |
| `string_cache` | `0.9.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/string-cache) |
| `string_cache_codegen` | `0.6.1` | `MIT OR Apache-2.0` | [source](https://github.com/servo/string-cache) |
| `svg_fmt` | `0.4.5` | `MIT/Apache-2.0` | [source](https://github.com/nical/rust_debug) |
| `swash` | `0.1.19` | `Apache-2.0 OR MIT` | [source](https://github.com/dfrg/swash) |
| `syn` | `1.0.109` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/syn) |
| `syn` | `2.0.117` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/syn) |
| `synstructure` | `0.13.2` | `MIT` | [source](https://github.com/mystor/synstructure) |
| `sys-locale` | `0.3.2` | `MIT OR Apache-2.0` | [source](https://github.com/1Password/sys-locale) |
| `system-deps` | `6.2.2` | `MIT OR Apache-2.0` | [source](https://github.com/gdesmott/system-deps) |
| `tao` | `0.34.8` | `Apache-2.0` | [source](https://github.com/tauri-apps/tao) |
| `tao-macros` | `0.1.3` | `MIT OR Apache-2.0` | [source](https://github.com/tauri-apps/tao) |
| `target-lexicon` | `0.12.16` | `Apache-2.0 WITH LLVM-exception` | [source](https://github.com/bytecodealliance/target-lexicon) |
| `tempfile` | `3.27.0` | `MIT OR Apache-2.0` | [source](https://github.com/Stebalien/tempfile) |
| `tendril` | `0.5.0` | `MIT OR Apache-2.0` | [source](https://github.com/servo/html5ever) |
| `termcolor` | `1.4.1` | `Unlicense OR MIT` | [source](https://github.com/BurntSushi/termcolor) |
| `termios` | `0.2.2` | `MIT` | [source](https://github.com/dcuddeback/termios-rs) |
| `thiserror` | `1.0.69` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/thiserror) |
| `thiserror` | `2.0.18` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/thiserror) |
| `thiserror-impl` | `1.0.69` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/thiserror) |
| `thiserror-impl` | `2.0.18` | `MIT OR Apache-2.0` | [source](https://github.com/dtolnay/thiserror) |
| `thread_local` | `1.1.9` | `MIT OR Apache-2.0` | [source](https://github.com/Amanieu/thread_local-rs) |
| `time` | `0.3.49` | `MIT OR Apache-2.0` | [source](https://github.com/time-rs/time) |
| `time-core` | `0.1.9` | `MIT OR Apache-2.0` | [source](https://github.com/time-rs/time) |
| `time-macros` | `0.2.29` | `MIT OR Apache-2.0` | [source](https://github.com/time-rs/time) |
| `tinystr` | `0.8.3` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `tinyvec` | `1.11.0` | `Zlib OR Apache-2.0 OR MIT` | [source](https://github.com/Lokathor/tinyvec) |
| `tinyvec_macros` | `0.1.1` | `MIT OR Apache-2.0 OR Zlib` | [source](https://github.com/Soveu/tinyvec_macros) |
| `tokio` | `1.52.3` | `MIT` | [source](https://github.com/tokio-rs/tokio) |
| `tokio-macros` | `2.7.0` | `MIT` | [source](https://github.com/tokio-rs/tokio) |
| `toml` | `0.8.2` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `toml_datetime` | `0.6.3` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `toml_datetime` | `1.1.1+spec-1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `toml_edit` | `0.19.15` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `toml_edit` | `0.20.2` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `toml_edit` | `0.25.12+spec-1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `toml_parser` | `1.1.2+spec-1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/toml-rs/toml) |
| `tracing` | `0.1.44` | `MIT` | [source](https://github.com/tokio-rs/tracing) |
| `tracing-attributes` | `0.1.31` | `MIT` | [source](https://github.com/tokio-rs/tracing) |
| `tracing-core` | `0.1.36` | `MIT` | [source](https://github.com/tokio-rs/tracing) |
| `tracing-log` | `0.2.0` | `MIT` | [source](https://github.com/tokio-rs/tracing) |
| `tracing-subscriber` | `0.3.23` | `MIT` | [source](https://github.com/tokio-rs/tracing) |
| `ttf-parser` | `0.20.0` | `MIT OR Apache-2.0` | [source](https://github.com/RazrFalcon/ttf-parser) |
| `ttf-parser` | `0.21.1` | `MIT OR Apache-2.0` | [source](https://github.com/RazrFalcon/ttf-parser) |
| `typenum` | `1.20.1` | `MIT OR Apache-2.0` | [source](https://github.com/paholg/typenum) |
| `uds_windows` | `1.2.1` | `MIT` | [source](https://github.com/haraldh/rust_uds_windows) |
| `unicode-bidi` | `0.3.18` | `MIT OR Apache-2.0` | [source](https://github.com/servo/unicode-bidi) |
| `unicode-bidi-mirroring` | `0.2.0` | `MIT/Apache-2.0` | [source](https://github.com/RazrFalcon/unicode-bidi-mirroring) |
| `unicode-ccc` | `0.2.0` | `MIT/Apache-2.0` | [source](https://github.com/RazrFalcon/unicode-ccc) |
| `unicode-ident` | `1.0.24` | `(MIT OR Apache-2.0) AND Unicode-3.0` | [source](https://github.com/dtolnay/unicode-ident) |
| `unicode-linebreak` | `0.1.5` | `Apache-2.0` | [source](https://github.com/axelf4/unicode-linebreak) |
| `unicode-properties` | `0.1.4` | `MIT/Apache-2.0` | [source](https://github.com/unicode-rs/unicode-properties) |
| `unicode-script` | `0.5.8` | `MIT OR Apache-2.0` | [source](https://github.com/unicode-rs/unicode-script) |
| `unicode-segmentation` | `1.13.3` | `MIT OR Apache-2.0` | [source](https://github.com/unicode-rs/unicode-segmentation) |
| `unicode-width` | `0.1.14` | `MIT OR Apache-2.0` | [source](https://github.com/unicode-rs/unicode-width) |
| `unicode-width` | `0.2.2` | `MIT OR Apache-2.0` | [source](https://github.com/unicode-rs/unicode-width) |
| `unicode-xid` | `0.2.6` | `MIT OR Apache-2.0` | [source](https://github.com/unicode-rs/unicode-xid) |
| `url` | `2.5.8` | `MIT OR Apache-2.0` | [source](https://github.com/servo/rust-url) |
| `urlencoding` | `2.1.3` | `MIT` | [source](https://github.com/kornelski/rust_urlencoding) |
| `utf-8` | `0.7.6` | `MIT OR Apache-2.0` | [source](https://github.com/SimonSapin/rust-utf8) |
| `utf8_iter` | `1.0.4` | `Apache-2.0 OR MIT` | [source](https://github.com/hsivonen/utf8_iter) |
| `uuid` | `1.23.2` | `Apache-2.0 OR MIT` | [source](https://github.com/uuid-rs/uuid) |
| `valuable` | `0.1.1` | `MIT` | [source](https://github.com/tokio-rs/valuable) |
| `vcpkg` | `0.2.15` | `MIT/Apache-2.0` | [source](https://github.com/mcgoo/vcpkg-rs) |
| `version-compare` | `0.2.1` | `MIT` | [source](https://gitlab.com/timvisee/version-compare) |
| `version_check` | `0.9.5` | `MIT/Apache-2.0` | [source](https://github.com/SergioBenitez/version_check) |
| `vte` | `0.15.0` | `Apache-2.0 OR MIT` | [source](https://github.com/alacritty/vte) |
| `walkdir` | `2.5.0` | `Unlicense/MIT` | [source](https://github.com/BurntSushi/walkdir) |
| `wasi` | `0.11.1+wasi-snapshot-preview1` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasi) |
| `wasip2` | `1.0.3+wasi-0.2.9` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasi-rs) |
| `wasip3` | `0.4.0+wasi-0.3.0-rc-2026-01-06` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasi-rs) |
| `wasm-bindgen` | `0.2.122` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen) |
| `wasm-bindgen-futures` | `0.4.72` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures) |
| `wasm-bindgen-macro` | `0.2.122` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro) |
| `wasm-bindgen-macro-support` | `0.2.122` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support) |
| `wasm-bindgen-shared` | `0.2.122` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared) |
| `wasm-encoder` | `0.244.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasm-encoder) |
| `wasm-metadata` | `0.244.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasm-metadata) |
| `wasmparser` | `0.244.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasmparser) |
| `wayland-backend` | `0.3.15` | `MIT` | [source](https://github.com/smithay/wayland-rs) |
| `wayland-client` | `0.31.14` | `MIT` | [source](https://github.com/smithay/wayland-rs) |
| `wayland-protocols` | `0.32.12` | `MIT` | [source](https://github.com/smithay/wayland-rs) |
| `wayland-scanner` | `0.31.11` | `MIT` | [source](https://github.com/smithay/wayland-rs) |
| `wayland-sys` | `0.31.11` | `MIT` | [source](https://github.com/smithay/wayland-rs) |
| `web-sys` | `0.3.99` | `MIT OR Apache-2.0` | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys) |
| `web-time` | `1.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/daxpedda/web-time) |
| `web_atoms` | `0.2.4` | `MIT OR Apache-2.0` | [source](https://github.com/servo/html5ever) |
| `webkit2gtk` | `2.0.2` | `MIT` | [source](https://github.com/tauri-apps/webkit2gtk-rs) |
| `webkit2gtk-sys` | `2.0.2` | `MIT` | [source](https://github.com/tauri-apps/webkit2gtk-rs) |
| `webview2-com` | `0.38.2` | `MIT` | [source](https://github.com/wravery/webview2-rs) |
| `webview2-com-macros` | `0.8.1` | `MIT` | [source](https://github.com/wravery/webview2-rs) |
| `webview2-com-sys` | `0.38.2` | `MIT` | [source](https://github.com/wravery/webview2-rs) |
| `wgpu` | `23.0.1` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/wgpu) |
| `wgpu-core` | `23.0.1` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/wgpu) |
| `wgpu-hal` | `23.0.1` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/wgpu) |
| `wgpu-types` | `23.0.0` | `MIT OR Apache-2.0` | [source](https://github.com/gfx-rs/wgpu) |
| `winapi` | `0.3.9` | `MIT/Apache-2.0` | [source](https://github.com/retep998/winapi-rs) |
| `winapi-i686-pc-windows-gnu` | `0.4.0` | `MIT/Apache-2.0` | [source](https://github.com/retep998/winapi-rs) |
| `winapi-util` | `0.1.11` | `Unlicense OR MIT` | [source](https://github.com/BurntSushi/winapi-util) |
| `winapi-x86_64-pc-windows-gnu` | `0.4.0` | `MIT/Apache-2.0` | [source](https://github.com/retep998/winapi-rs) |
| `windows` | `0.58.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows` | `0.61.3` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-collections` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-core` | `0.58.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-core` | `0.61.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-future` | `0.2.1` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-implement` | `0.58.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-implement` | `0.60.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-interface` | `0.58.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-interface` | `0.59.3` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-link` | `0.1.3` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-link` | `0.2.1` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-numerics` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-result` | `0.2.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-result` | `0.3.4` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-strings` | `0.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-strings` | `0.4.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-sys` | `0.45.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-sys` | `0.52.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-sys` | `0.59.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-sys` | `0.61.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-targets` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-targets` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-threading` | `0.1.0` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows-version` | `0.1.7` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_gnullvm` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_msvc` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_msvc` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnu` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnu` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_i686_msvc` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_i686_msvc` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnu` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnu` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnullvm` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_msvc` | `0.42.2` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_msvc` | `0.52.6` | `MIT OR Apache-2.0` | [source](https://github.com/microsoft/windows-rs) |
| `winit` | `0.30.13` | `Apache-2.0` | [source](https://github.com/rust-windowing/winit) |
| `winnow` | `0.5.40` | `MIT` | [source](https://github.com/winnow-rs/winnow) |
| `winnow` | `1.0.3` | `MIT` | [source](https://github.com/winnow-rs/winnow) |
| `winreg` | `0.10.1` | `MIT` | [source](https://github.com/gentoo90/winreg-rs) |
| `wit-bindgen` | `0.51.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wit-bindgen) |
| `wit-bindgen` | `0.57.1` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wit-bindgen) |
| `wit-bindgen-core` | `0.51.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wit-bindgen) |
| `wit-bindgen-rust` | `0.51.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wit-bindgen) |
| `wit-bindgen-rust-macro` | `0.51.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wit-bindgen) |
| `wit-component` | `0.244.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wit-component) |
| `wit-parser` | `0.244.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [source](https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wit-parser) |
| `writeable` | `0.6.3` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `wry` | `0.55.1` | `Apache-2.0 OR MIT` | [source](https://github.com/tauri-apps/wry) |
| `x11` | `2.21.0` | `MIT` | [source](https://github.com/AltF02/x11-rs.git) |
| `x11-dl` | `2.21.0` | `MIT` | [source](https://github.com/AltF02/x11-rs.git) |
| `x11rb` | `0.13.2` | `MIT OR Apache-2.0` | [source](https://github.com/psychon/x11rb) |
| `x11rb-protocol` | `0.13.2` | `MIT OR Apache-2.0` | [source](https://github.com/psychon/x11rb) |
| `xkbcommon-dl` | `0.4.2` | `MIT` | [source](https://github.com/rust-windowing/xkbcommon-dl) |
| `xkeysym` | `0.2.1` | `MIT OR Apache-2.0 OR Zlib` | [source](https://github.com/notgull/xkeysym) |
| `xml-rs` | `0.8.28` | `MIT` | [source](https://github.com/kornelski/xml-rs) |
| `yazi` | `0.1.6` | `MIT OR Apache-2.0` | [source](https://github.com/dfrg/yazi) |
| `yoke` | `0.8.3` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `yoke-derive` | `0.8.2` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `zbus` | `5.16.0` | `MIT` | [source](https://github.com/z-galaxy/zbus/) |
| `zbus_macros` | `5.16.0` | `MIT` | [source](https://github.com/z-galaxy/zbus/) |
| `zbus_names` | `4.3.2` | `MIT` | [source](https://github.com/z-galaxy/zbus/) |
| `zeno` | `0.2.3` | `MIT OR Apache-2.0` | [source](https://github.com/dfrg/zeno) |
| `zerocopy` | `0.8.50` | `BSD-2-Clause OR Apache-2.0 OR MIT` | [source](https://github.com/google/zerocopy) |
| `zerocopy-derive` | `0.8.50` | `BSD-2-Clause OR Apache-2.0 OR MIT` | [source](https://github.com/google/zerocopy) |
| `zerofrom` | `0.1.8` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `zerofrom-derive` | `0.1.7` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `zerotrie` | `0.2.4` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `zerovec` | `0.11.6` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `zerovec-derive` | `0.11.3` | `Unicode-3.0` | [source](https://github.com/unicode-org/icu4x) |
| `zmij` | `1.0.21` | `MIT` | [source](https://github.com/dtolnay/zmij) |
| `zvariant` | `5.12.0` | `MIT` | [source](https://github.com/z-galaxy/zbus/) |
| `zvariant_derive` | `5.12.0` | `MIT` | [source](https://github.com/z-galaxy/zbus/) |
| `zvariant_utils` | `3.4.0` | `MIT` | [source](https://github.com/z-galaxy/zbus/) |

## Locked dashboard dependencies

| Package | Version | Declared licence | Upstream |
|---|---:|---|---|
| `@asamuzakjp/css-color` | `3.2.0` | `MIT` | [source](https://www.npmjs.com/package/@asamuzakjp/css-color) |
| `@babel/code-frame` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/code-frame) |
| `@babel/compat-data` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/compat-data) |
| `@babel/core` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/core) |
| `@babel/generator` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/generator) |
| `@babel/helper-compilation-targets` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-compilation-targets) |
| `@babel/helper-globals` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-globals) |
| `@babel/helper-module-imports` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-module-imports) |
| `@babel/helper-module-transforms` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-module-transforms) |
| `@babel/helper-plugin-utils` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-plugin-utils) |
| `@babel/helper-string-parser` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-string-parser) |
| `@babel/helper-validator-identifier` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-validator-identifier) |
| `@babel/helper-validator-option` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helper-validator-option) |
| `@babel/helpers` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/helpers) |
| `@babel/parser` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/parser) |
| `@babel/plugin-transform-react-jsx-self` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/plugin-transform-react-jsx-self) |
| `@babel/plugin-transform-react-jsx-source` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/plugin-transform-react-jsx-source) |
| `@babel/template` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/template) |
| `@babel/traverse` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/traverse) |
| `@babel/types` | `7.29.7` | `MIT` | [source](https://www.npmjs.com/package/@babel/types) |
| `@csstools/color-helpers` | `5.1.0` | `MIT-0` | [source](https://www.npmjs.com/package/@csstools/color-helpers) |
| `@csstools/css-calc` | `2.1.4` | `MIT` | [source](https://www.npmjs.com/package/@csstools/css-calc) |
| `@csstools/css-color-parser` | `3.1.0` | `MIT` | [source](https://www.npmjs.com/package/@csstools/css-color-parser) |
| `@csstools/css-parser-algorithms` | `3.0.5` | `MIT` | [source](https://www.npmjs.com/package/@csstools/css-parser-algorithms) |
| `@csstools/css-tokenizer` | `3.0.4` | `MIT` | [source](https://www.npmjs.com/package/@csstools/css-tokenizer) |
| `@esbuild/aix-ppc64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/aix-ppc64) |
| `@esbuild/android-arm` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/android-arm) |
| `@esbuild/android-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/android-arm64) |
| `@esbuild/android-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/android-x64) |
| `@esbuild/darwin-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/darwin-arm64) |
| `@esbuild/darwin-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/darwin-x64) |
| `@esbuild/freebsd-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/freebsd-arm64) |
| `@esbuild/freebsd-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/freebsd-x64) |
| `@esbuild/linux-arm` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-arm) |
| `@esbuild/linux-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-arm64) |
| `@esbuild/linux-ia32` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-ia32) |
| `@esbuild/linux-loong64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-loong64) |
| `@esbuild/linux-mips64el` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-mips64el) |
| `@esbuild/linux-ppc64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-ppc64) |
| `@esbuild/linux-riscv64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-riscv64) |
| `@esbuild/linux-s390x` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-s390x) |
| `@esbuild/linux-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/linux-x64) |
| `@esbuild/netbsd-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/netbsd-arm64) |
| `@esbuild/netbsd-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/netbsd-x64) |
| `@esbuild/openbsd-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/openbsd-arm64) |
| `@esbuild/openbsd-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/openbsd-x64) |
| `@esbuild/openharmony-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/openharmony-arm64) |
| `@esbuild/sunos-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/sunos-x64) |
| `@esbuild/win32-arm64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/win32-arm64) |
| `@esbuild/win32-ia32` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/win32-ia32) |
| `@esbuild/win32-x64` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/@esbuild/win32-x64) |
| `@jridgewell/gen-mapping` | `0.3.13` | `MIT` | [source](https://www.npmjs.com/package/@jridgewell/gen-mapping) |
| `@jridgewell/remapping` | `2.3.5` | `MIT` | [source](https://www.npmjs.com/package/@jridgewell/remapping) |
| `@jridgewell/resolve-uri` | `3.1.2` | `MIT` | [source](https://www.npmjs.com/package/@jridgewell/resolve-uri) |
| `@jridgewell/sourcemap-codec` | `1.5.5` | `MIT` | [source](https://www.npmjs.com/package/@jridgewell/sourcemap-codec) |
| `@jridgewell/trace-mapping` | `0.3.31` | `MIT` | [source](https://www.npmjs.com/package/@jridgewell/trace-mapping) |
| `@rolldown/pluginutils` | `1.0.0-beta.27` | `MIT` | [source](https://www.npmjs.com/package/@rolldown/pluginutils) |
| `@rollup/rollup-android-arm-eabi` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-android-arm-eabi) |
| `@rollup/rollup-android-arm64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-android-arm64) |
| `@rollup/rollup-darwin-arm64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-darwin-arm64) |
| `@rollup/rollup-darwin-x64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-darwin-x64) |
| `@rollup/rollup-freebsd-arm64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-freebsd-arm64) |
| `@rollup/rollup-freebsd-x64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-freebsd-x64) |
| `@rollup/rollup-linux-arm-gnueabihf` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-arm-gnueabihf) |
| `@rollup/rollup-linux-arm-musleabihf` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-arm-musleabihf) |
| `@rollup/rollup-linux-arm64-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-arm64-gnu) |
| `@rollup/rollup-linux-arm64-musl` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-arm64-musl) |
| `@rollup/rollup-linux-loong64-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-loong64-gnu) |
| `@rollup/rollup-linux-loong64-musl` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-loong64-musl) |
| `@rollup/rollup-linux-ppc64-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-ppc64-gnu) |
| `@rollup/rollup-linux-ppc64-musl` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-ppc64-musl) |
| `@rollup/rollup-linux-riscv64-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-riscv64-gnu) |
| `@rollup/rollup-linux-riscv64-musl` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-riscv64-musl) |
| `@rollup/rollup-linux-s390x-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-s390x-gnu) |
| `@rollup/rollup-linux-x64-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-x64-gnu) |
| `@rollup/rollup-linux-x64-musl` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-linux-x64-musl) |
| `@rollup/rollup-openbsd-x64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-openbsd-x64) |
| `@rollup/rollup-openharmony-arm64` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-openharmony-arm64) |
| `@rollup/rollup-win32-arm64-msvc` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-win32-arm64-msvc) |
| `@rollup/rollup-win32-ia32-msvc` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-win32-ia32-msvc) |
| `@rollup/rollup-win32-x64-gnu` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-win32-x64-gnu) |
| `@rollup/rollup-win32-x64-msvc` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/@rollup/rollup-win32-x64-msvc) |
| `@types/babel__core` | `7.20.5` | `MIT` | [source](https://www.npmjs.com/package/@types/babel__core) |
| `@types/babel__generator` | `7.27.0` | `MIT` | [source](https://www.npmjs.com/package/@types/babel__generator) |
| `@types/babel__template` | `7.4.4` | `MIT` | [source](https://www.npmjs.com/package/@types/babel__template) |
| `@types/babel__traverse` | `7.28.0` | `MIT` | [source](https://www.npmjs.com/package/@types/babel__traverse) |
| `@types/chai` | `5.2.3` | `MIT` | [source](https://www.npmjs.com/package/@types/chai) |
| `@types/deep-eql` | `4.0.2` | `MIT` | [source](https://www.npmjs.com/package/@types/deep-eql) |
| `@types/estree` | `1.0.9` | `MIT` | [source](https://www.npmjs.com/package/@types/estree) |
| `@types/prop-types` | `15.7.15` | `MIT` | [source](https://www.npmjs.com/package/@types/prop-types) |
| `@types/react` | `18.3.31` | `MIT` | [source](https://www.npmjs.com/package/@types/react) |
| `@types/react-dom` | `18.3.7` | `MIT` | [source](https://www.npmjs.com/package/@types/react-dom) |
| `@types/react-test-renderer` | `18.3.1` | `MIT` | [source](https://www.npmjs.com/package/@types/react-test-renderer) |
| `@vitejs/plugin-react` | `4.7.0` | `MIT` | [source](https://www.npmjs.com/package/@vitejs/plugin-react) |
| `@vitest/expect` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/expect) |
| `@vitest/mocker` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/mocker) |
| `@vitest/pretty-format` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/pretty-format) |
| `@vitest/pretty-format` | `3.2.7` | `MIT` | [source](https://www.npmjs.com/package/@vitest/pretty-format) |
| `@vitest/runner` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/runner) |
| `@vitest/snapshot` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/snapshot) |
| `@vitest/spy` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/spy) |
| `@vitest/utils` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/@vitest/utils) |
| `agent-base` | `7.1.4` | `MIT` | [source](https://www.npmjs.com/package/agent-base) |
| `assertion-error` | `2.0.1` | `MIT` | [source](https://www.npmjs.com/package/assertion-error) |
| `baseline-browser-mapping` | `2.10.37` | `Apache-2.0` | [source](https://www.npmjs.com/package/baseline-browser-mapping) |
| `browserslist` | `4.28.2` | `MIT` | [source](https://www.npmjs.com/package/browserslist) |
| `cac` | `6.7.14` | `MIT` | [source](https://www.npmjs.com/package/cac) |
| `caniuse-lite` | `1.0.30001799` | `CC-BY-4.0` | [source](https://www.npmjs.com/package/caniuse-lite) |
| `chai` | `5.3.3` | `MIT` | [source](https://www.npmjs.com/package/chai) |
| `check-error` | `2.1.3` | `MIT` | [source](https://www.npmjs.com/package/check-error) |
| `convert-source-map` | `2.0.0` | `MIT` | [source](https://www.npmjs.com/package/convert-source-map) |
| `cssstyle` | `4.6.0` | `MIT` | [source](https://www.npmjs.com/package/cssstyle) |
| `csstype` | `3.2.3` | `MIT` | [source](https://www.npmjs.com/package/csstype) |
| `data-urls` | `5.0.0` | `MIT` | [source](https://www.npmjs.com/package/data-urls) |
| `debug` | `4.4.3` | `MIT` | [source](https://www.npmjs.com/package/debug) |
| `decimal.js` | `10.6.0` | `MIT` | [source](https://www.npmjs.com/package/decimal.js) |
| `deep-eql` | `5.0.2` | `MIT` | [source](https://www.npmjs.com/package/deep-eql) |
| `electron-to-chromium` | `1.5.375` | `ISC` | [source](https://www.npmjs.com/package/electron-to-chromium) |
| `entities` | `6.0.1` | `BSD-2-Clause` | [source](https://www.npmjs.com/package/entities) |
| `es-module-lexer` | `1.7.0` | `MIT` | [source](https://www.npmjs.com/package/es-module-lexer) |
| `esbuild` | `0.25.12` | `MIT` | [source](https://www.npmjs.com/package/esbuild) |
| `escalade` | `3.2.0` | `MIT` | [source](https://www.npmjs.com/package/escalade) |
| `estree-walker` | `3.0.3` | `MIT` | [source](https://www.npmjs.com/package/estree-walker) |
| `expect-type` | `1.4.0` | `Apache-2.0` | [source](https://www.npmjs.com/package/expect-type) |
| `fdir` | `6.5.0` | `MIT` | [source](https://www.npmjs.com/package/fdir) |
| `fsevents` | `2.3.3` | `MIT` | [source](https://www.npmjs.com/package/fsevents) |
| `gensync` | `1.0.0-beta.2` | `MIT` | [source](https://www.npmjs.com/package/gensync) |
| `html-encoding-sniffer` | `4.0.0` | `MIT` | [source](https://www.npmjs.com/package/html-encoding-sniffer) |
| `http-proxy-agent` | `7.0.2` | `MIT` | [source](https://www.npmjs.com/package/http-proxy-agent) |
| `https-proxy-agent` | `7.0.6` | `MIT` | [source](https://www.npmjs.com/package/https-proxy-agent) |
| `iconv-lite` | `0.6.3` | `MIT` | [source](https://www.npmjs.com/package/iconv-lite) |
| `is-potential-custom-element-name` | `1.0.1` | `MIT` | [source](https://www.npmjs.com/package/is-potential-custom-element-name) |
| `js-tokens` | `4.0.0` | `MIT` | [source](https://www.npmjs.com/package/js-tokens) |
| `js-tokens` | `9.0.1` | `MIT` | [source](https://www.npmjs.com/package/js-tokens) |
| `jsdom` | `26.1.0` | `MIT` | [source](https://www.npmjs.com/package/jsdom) |
| `jsesc` | `3.1.0` | `MIT` | [source](https://www.npmjs.com/package/jsesc) |
| `json5` | `2.2.3` | `MIT` | [source](https://www.npmjs.com/package/json5) |
| `loose-envify` | `1.4.0` | `MIT` | [source](https://www.npmjs.com/package/loose-envify) |
| `loupe` | `3.2.1` | `MIT` | [source](https://www.npmjs.com/package/loupe) |
| `lru-cache` | `10.4.3` | `ISC` | [source](https://www.npmjs.com/package/lru-cache) |
| `lru-cache` | `5.1.1` | `ISC` | [source](https://www.npmjs.com/package/lru-cache) |
| `magic-string` | `0.30.21` | `MIT` | [source](https://www.npmjs.com/package/magic-string) |
| `ms` | `2.1.3` | `MIT` | [source](https://www.npmjs.com/package/ms) |
| `nanoid` | `3.3.18` | `MIT` | [source](https://www.npmjs.com/package/nanoid) |
| `node-releases` | `2.0.47` | `MIT` | [source](https://www.npmjs.com/package/node-releases) |
| `nwsapi` | `2.2.24` | `MIT` | [source](https://www.npmjs.com/package/nwsapi) |
| `object-assign` | `4.1.1` | `MIT` | [source](https://www.npmjs.com/package/object-assign) |
| `parse5` | `7.3.0` | `MIT` | [source](https://www.npmjs.com/package/parse5) |
| `pathe` | `2.0.3` | `MIT` | [source](https://www.npmjs.com/package/pathe) |
| `pathval` | `2.0.1` | `MIT` | [source](https://www.npmjs.com/package/pathval) |
| `picocolors` | `1.1.1` | `ISC` | [source](https://www.npmjs.com/package/picocolors) |
| `picomatch` | `4.0.5` | `MIT` | [source](https://www.npmjs.com/package/picomatch) |
| `postcss` | `8.5.26` | `MIT` | [source](https://www.npmjs.com/package/postcss) |
| `punycode` | `2.3.1` | `MIT` | [source](https://www.npmjs.com/package/punycode) |
| `react` | `18.3.1` | `MIT` | [source](https://www.npmjs.com/package/react) |
| `react-dom` | `18.3.1` | `MIT` | [source](https://www.npmjs.com/package/react-dom) |
| `react-is` | `18.3.1` | `MIT` | [source](https://www.npmjs.com/package/react-is) |
| `react-refresh` | `0.17.0` | `MIT` | [source](https://www.npmjs.com/package/react-refresh) |
| `react-shallow-renderer` | `16.15.0` | `MIT` | [source](https://www.npmjs.com/package/react-shallow-renderer) |
| `react-test-renderer` | `18.3.1` | `MIT` | [source](https://www.npmjs.com/package/react-test-renderer) |
| `rollup` | `4.62.0` | `MIT` | [source](https://www.npmjs.com/package/rollup) |
| `rrweb-cssom` | `0.8.0` | `MIT` | [source](https://www.npmjs.com/package/rrweb-cssom) |
| `safer-buffer` | `2.1.2` | `MIT` | [source](https://www.npmjs.com/package/safer-buffer) |
| `saxes` | `6.0.0` | `ISC` | [source](https://www.npmjs.com/package/saxes) |
| `scheduler` | `0.23.2` | `MIT` | [source](https://www.npmjs.com/package/scheduler) |
| `semver` | `6.3.1` | `ISC` | [source](https://www.npmjs.com/package/semver) |
| `siginfo` | `2.0.0` | `ISC` | [source](https://www.npmjs.com/package/siginfo) |
| `source-map-js` | `1.2.1` | `BSD-3-Clause` | [source](https://www.npmjs.com/package/source-map-js) |
| `stackback` | `0.0.2` | `MIT` | [source](https://www.npmjs.com/package/stackback) |
| `std-env` | `3.10.0` | `MIT` | [source](https://www.npmjs.com/package/std-env) |
| `strip-literal` | `3.1.0` | `MIT` | [source](https://www.npmjs.com/package/strip-literal) |
| `symbol-tree` | `3.2.4` | `MIT` | [source](https://www.npmjs.com/package/symbol-tree) |
| `tinybench` | `2.9.0` | `MIT` | [source](https://www.npmjs.com/package/tinybench) |
| `tinyexec` | `0.3.2` | `MIT` | [source](https://www.npmjs.com/package/tinyexec) |
| `tinyglobby` | `0.2.17` | `MIT` | [source](https://www.npmjs.com/package/tinyglobby) |
| `tinypool` | `1.1.1` | `MIT` | [source](https://www.npmjs.com/package/tinypool) |
| `tinyrainbow` | `2.0.0` | `MIT` | [source](https://www.npmjs.com/package/tinyrainbow) |
| `tinyspy` | `4.0.4` | `MIT` | [source](https://www.npmjs.com/package/tinyspy) |
| `tldts` | `6.1.86` | `MIT` | [source](https://www.npmjs.com/package/tldts) |
| `tldts-core` | `6.1.86` | `MIT` | [source](https://www.npmjs.com/package/tldts-core) |
| `tough-cookie` | `5.1.2` | `BSD-3-Clause` | [source](https://www.npmjs.com/package/tough-cookie) |
| `tr46` | `5.1.1` | `MIT` | [source](https://www.npmjs.com/package/tr46) |
| `typescript` | `5.9.3` | `Apache-2.0` | [source](https://www.npmjs.com/package/typescript) |
| `update-browserslist-db` | `1.2.3` | `MIT` | [source](https://www.npmjs.com/package/update-browserslist-db) |
| `vite` | `6.4.3` | `MIT` | [source](https://www.npmjs.com/package/vite) |
| `vite-node` | `3.2.4` | `MIT` | [source](https://www.npmjs.com/package/vite-node) |
| `vitest` | `3.2.6` | `MIT` | [source](https://www.npmjs.com/package/vitest) |
| `w3c-xmlserializer` | `5.0.0` | `MIT` | [source](https://www.npmjs.com/package/w3c-xmlserializer) |
| `webidl-conversions` | `7.0.0` | `BSD-2-Clause` | [source](https://www.npmjs.com/package/webidl-conversions) |
| `whatwg-encoding` | `3.1.1` | `MIT` | [source](https://www.npmjs.com/package/whatwg-encoding) |
| `whatwg-mimetype` | `4.0.0` | `MIT` | [source](https://www.npmjs.com/package/whatwg-mimetype) |
| `whatwg-url` | `14.2.0` | `MIT` | [source](https://www.npmjs.com/package/whatwg-url) |
| `why-is-node-running` | `2.3.0` | `MIT` | [source](https://www.npmjs.com/package/why-is-node-running) |
| `ws` | `8.21.1` | `MIT` | [source](https://www.npmjs.com/package/ws) |
| `xml-name-validator` | `5.0.0` | `Apache-2.0` | [source](https://www.npmjs.com/package/xml-name-validator) |
| `xmlchars` | `2.2.0` | `MIT` | [source](https://www.npmjs.com/package/xmlchars) |
| `yallist` | `3.1.1` | `ISC` | [source](https://www.npmjs.com/package/yallist) |

## Updating this file

Run `python3 scripts/generate-third-party-notices.py` after either lockfile changes, then
review every changed licence expression and upstream source before accepting the result.
The generator failing on missing licence metadata is intentional.
