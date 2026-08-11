//! Proves the structured (rich-cell) grid snapshot preserves visual attributes,
//! not just characters. We print a single 'X' with an SGR bold + red foreground
//! (`\x1b[1;31mX\x1b[0m`), snapshot, and assert the cell for that 'X' reports
//! `bold = true` and a red-ish foreground. This is the property that makes
//! restored history render in color instead of plain white.

use std::io::BufReader;
use std::time::Duration;

mod common;
use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};

/// Find the first cell in the snapshot whose `text` equals `target`. Returns the
/// cell JSON value.
fn find_cell(grid_line: &str, target: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(grid_line.trim()).expect("grid event is JSON");
    let rows = v["grid"]["rows_cells"]
        .as_array()
        .expect("rows_cells array");
    for row in rows {
        for cell in row.as_array().expect("row is array") {
            if cell["text"].as_str() == Some(target) {
                return cell.clone();
            }
        }
    }
    panic!("no cell with text={target:?} in snapshot: {grid_line}");
}

#[test]
fn snapshot_preserves_bold_red_attributes() {
    let sock = socket_path("rich-snap");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let id = "rich-sess";

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Print a bold, red 'X' then reset, and hold the PTY open so we can snapshot.
    // The escape is double-backslashed so it survives JSON string encoding to the
    // daemon and is then emitted as a real ESC by `printf` in the shell.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","printf '\\033[1;31mX\\033[0m\\n'; sleep 30"],"cols":80,"rows":24}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(400));

    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));

    // Versioned snapshot.
    let v: serde_json::Value = serde_json::from_str(snap.trim()).unwrap();
    assert_eq!(
        v["grid"]["version"].as_u64(),
        Some(2),
        "snapshot version should be 2 (SnapshotV2 adds terminal input modes): {snap}"
    );

    // V2 carries the three terminal input modes. A plain shell at rest has all
    // three off; assert they are present (not missing) and default to false so a
    // renderer that requires them is never silently handed a V1-shaped snapshot.
    for mode in ["app_cursor", "bracketed_paste", "focus_reporting"] {
        assert_eq!(
            v["grid"][mode].as_bool(),
            Some(false),
            "V2 snapshot must carry {mode}=false for a shell at rest: {snap}"
        );
    }

    let cell = find_cell(&snap, "X");

    assert_eq!(
        cell["text"].as_str(),
        Some("X"),
        "cell text should be the single grapheme \"X\": {cell}"
    );

    assert_eq!(
        cell["bold"].as_bool(),
        Some(true),
        "X cell should be bold: {cell}"
    );

    // A plain bold-red 'X' carries none of the other attributes; they must
    // default to their off/none values on the wire.
    assert_eq!(
        cell["strikeout"].as_bool(),
        Some(false),
        "X cell should not be struck out: {cell}"
    );
    assert_eq!(
        cell["dim"].as_bool(),
        Some(false),
        "X cell should not be dim: {cell}"
    );
    assert_eq!(
        cell["hidden"].as_bool(),
        Some(false),
        "X cell should not be hidden: {cell}"
    );
    assert_eq!(
        cell["underline"].as_str(),
        Some("none"),
        "X cell should have no underline: {cell}"
    );

    // Foreground should be red. SGR `31` produces the semantic name "red" on the
    // wire (Maestro's own palette vocabulary). Accept the named-red
    // representation, a palette index 1, or an RGB that is red-dominant, so the
    // assertion stays honest if the daemon ever resolves named colors to RGB.
    let fg = &cell["fg"];
    let is_red = match fg["kind"].as_str() {
        Some("named") => fg["name"].as_str() == Some("red"),
        Some("indexed") => fg["index"].as_u64() == Some(1),
        Some("rgb") => {
            let r = fg["r"].as_u64().unwrap_or(0);
            let g = fg["g"].as_u64().unwrap_or(0);
            let b = fg["b"].as_u64().unwrap_or(0);
            r > 0 && r > g && r > b
        }
        _ => false,
    };
    assert!(is_red, "X foreground should be red-ish, got {fg}");

    // The width of a normal latin glyph is 1.
    assert_eq!(
        cell["width"].as_u64(),
        Some(1),
        "X width should be 1: {cell}"
    );
}

/// Proves SnapshotV2 carries the three terminal INPUT modes and that they
/// survive the serialize -> deserialize wire round-trip as `true` when set. We
/// drive the PTY through real escape sequences: `\033[?1h` (DECCKM application
/// cursor), `\033[?2004h` (bracketed paste), `\033[?1004h` (focus reporting).
/// The renderer relies on these to encode arrows/paste/focus correctly, so a
/// flag silently stuck at false would mis-encode input.
#[test]
fn snapshot_v2_round_trips_terminal_input_modes() {
    let sock = socket_path("v2-modes");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let id = "modes-sess";

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Enable all three modes, then hold the PTY open so the snapshot observes them.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","printf '\\033[?1h\\033[?2004h\\033[?1004h'; sleep 30"],"cols":80,"rows":24}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(400));

    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));

    // Parse (deserialize) the wire line the daemon serialized: this IS the round
    // trip the renderer performs. Every flag must come back true.
    let v: serde_json::Value = serde_json::from_str(snap.trim()).unwrap();
    assert_eq!(
        v["grid"]["version"].as_u64(),
        Some(2),
        "modes snapshot must be V2: {snap}"
    );
    assert_eq!(
        v["grid"]["app_cursor"].as_bool(),
        Some(true),
        "DECCKM (\\033[?1h) must set app_cursor: {snap}"
    );
    assert_eq!(
        v["grid"]["bracketed_paste"].as_bool(),
        Some(true),
        "\\033[?2004h must set bracketed_paste: {snap}"
    );
    assert_eq!(
        v["grid"]["focus_reporting"].as_bool(),
        Some(true),
        "\\033[?1004h must set focus_reporting: {snap}"
    );
}

/// Proves the grapheme fix: a base letter plus a combining mark must land in the
/// SAME cell's `text` as two chars, not get split or dropped. We print 'e'
/// followed by the UTF-8 for U+0301 (COMBINING ACUTE ACCENT, bytes 0xCC 0x81 =
/// octal \314\201). alacritty stores combining marks on `cell.zerowidth()`, and
/// `snapshot()` appends them after the base char, so the cell's `text` should be
/// exactly "e\u{301}" (two chars).
#[test]
fn snapshot_captures_combining_mark_in_one_cell() {
    let sock = socket_path("rich-combine");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let id = "combine-sess";

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // printf emits the raw bytes for 'e' + U+0301 (combining acute accent).
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","printf 'e\\314\\201\\n'; sleep 30"],"cols":80,"rows":24}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(400));

    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));

    // The combined grapheme is "e\u{301}" — find the cell whose text is exactly
    // that, proving the combining mark was captured on the same cell as 'e' and
    // not split into a separate cell or dropped.
    let cell = find_cell(&snap, "e\u{301}");
    let text = cell["text"].as_str().expect("text is a string");
    assert_eq!(
        text.chars().count(),
        2,
        "base + combining mark should be two chars in one cell's text: {cell}"
    );
    assert_eq!(
        text, "e\u{301}",
        "text should be base 'e' then U+0301: {cell}"
    );
}
