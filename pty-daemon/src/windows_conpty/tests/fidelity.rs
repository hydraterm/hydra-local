//! Compare terminal semantics, not ConPTY's repaint byte stream, against the same parser.
use super::*;
use alacritty_terminal::{
    event::{Event as TerminalEvent, EventListener},
    grid::Dimensions,
    index::{Column, Line},
    term::{Config, Term},
    vte::ansi::Processor,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_INPUT_HANDLE,
};

const READY: &str = "HYDRA_FIDELITY_READY";
const INPUT: &str = "input-输入-🦞-e\u{301}";
const END: &str = "HYDRA_FIDELITY_END";

fn payload() -> String {
    format!("BEGIN:{}:{END}", "A🦀界e\u{301}".repeat(8192))
}

pub(super) fn write_unicode_fixture() -> ! {
    unsafe {
        let input = GetStdHandle(STD_INPUT_HANDLE);
        let output = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        assert_ne!(GetConsoleMode(input, &mut mode), 0);
        assert_ne!(SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT), 0);
        assert_ne!(GetConsoleMode(output, &mut mode), 0);
        assert_ne!(
            SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING),
            0
        );
    }
    print!("\x1b[0m\x1b[2J\x1b[H{READY}");
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    assert_eq!(input.trim_end_matches(['\r', '\n']), INPUT);
    std::io::stdout().write_all(payload().as_bytes()).unwrap();
    std::io::stdout().flush().unwrap();
    std::process::exit(0);
}

#[derive(Clone)]
struct Listener;
impl EventListener for Listener {
    fn send_event(&self, _: TerminalEvent) {}
}
struct Size;
impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        10030
    }
    fn screen_lines(&self) -> usize {
        30
    }
    fn columns(&self) -> usize {
        100
    }
}

fn projection(bytes: &[u8]) -> Term<Listener> {
    let mut term = Term::new(
        Config {
            scrolling_history: 10000,
            ..Config::default()
        },
        &Size,
        Listener,
    );
    let mut parser: Processor = Processor::new();
    parser.advance(&mut term, READY.as_bytes());
    parser.advance(&mut term, bytes);
    term
}

fn assert_same_cells(actual: &[u8], expected: &[u8]) {
    let actual = projection(actual);
    let expected = projection(expected);
    let actual_history = actual.grid().history_size();
    let history = expected.grid().history_size();
    assert!(history > 30 && history < 10000);
    assert_eq!(
        actual_history, history,
        "ConPTY changed retained history length"
    );
    for row in -(history as i32)..30 {
        for col in 0..100 {
            assert_eq!(
                actual.grid()[Line(row)][Column(col)],
                expected.grid()[Line(row)][Column(col)],
                "Unicode cell/combining/wrap mismatch at row {row}, col {col}"
            );
        }
    }
    assert_eq!(actual.grid().cursor.point, expected.grid().cursor.point);
}

#[test]
fn sustained_unicode_input_output_preserves_every_cell_and_history_row() {
    const CASE: &str = "windows_conpty::tests::fidelity::sustained_unicode_input_output_preserves_every_cell_and_history_row";
    if run_exact_owned_child(CASE) {
        return;
    }
    let pair = openpty(PtySize {
        rows: 30,
        cols: 100,
        pixel_width: 0,
        pixel_height: 0,
    })
    .unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let (output, pump) = drain_output(&pair);
    let mut child = pair
        .slave
        .spawn_command(selected_child("unicode-fidelity"))
        .unwrap();
    let mut baseline = Vec::new();
    read_until(&output, &mut baseline, READY);
    let marker = baseline
        .windows(READY.len())
        .position(|part| part == READY.as_bytes())
        .unwrap();
    let mut actual = baseline[marker + READY.len()..].to_vec();
    // Finish ConPTY's initial clear-screen paint before beginning the observed fixture.
    let deadline = Instant::now() + OBSERVATION;
    loop {
        assert!(Instant::now() < deadline, "baseline did not settle");
        match output.recv_timeout(Duration::from_millis(50)) {
            Ok(bytes) => actual.extend(bytes),
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(error) => panic!("baseline disconnected: {error}"),
        }
    }
    let mut expected = actual.clone();
    expected.extend_from_slice(b"\r\n"); // Cooked input advances with echo disabled.
    let expected_payload = payload();
    assert!(expected_payload.len() > 64 * 1024);
    expected.extend_from_slice(expected_payload.as_bytes());
    writer.write_all(format!("{INPUT}\r").as_bytes()).unwrap();
    read_until(&output, &mut actual, END);
    assert!(child.wait().unwrap().success());
    wait_job_empty(&pair);
    pump.join().unwrap();
    for remaining in output.try_iter() {
        actual.extend(remaining);
    }
    assert_same_cells(&actual, &expected);
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[test]
fn fidelity_oracle_rejects_missing_combining_marks_and_lost_history() {
    let expected = payload();
    assert_same_cells(expected.as_bytes(), expected.as_bytes());
    let lost_marks = expected.replace('\u{301}', "");
    assert!(std::panic::catch_unwind(|| assert_same_cells(
        lost_marks.as_bytes(),
        expected.as_bytes()
    ))
    .is_err());
    let lost_rows = &expected.as_bytes()[512..];
    assert!(
        std::panic::catch_unwind(|| assert_same_cells(lost_rows, expected.as_bytes())).is_err()
    );
}
