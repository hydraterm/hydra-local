//! Read-only current-grid observation using the same schema/layout validation as native painting.
//! No PTY attachment, input, history request, lifecycle operation, or raw terminal parser.

use maestro_shell::provider_attention::{
    classify_codex_grid, classify_opencode_grid, ObservedProvider, ProviderAttentionObservation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderGridObservation {
    pub revision: u64,
    pub state: ProviderAttentionObservation,
}

pub fn observe_opencode_grid(
    frame: &[u8],
    expected_session: &str,
    expected_generation: &str,
) -> Option<ProviderGridObservation> {
    observe_provider_grid(
        frame,
        expected_session,
        expected_generation,
        ObservedProvider::OpenCode,
    )
}

pub fn observe_provider_grid(
    frame: &[u8],
    expected_session: &str,
    expected_generation: &str,
    provider: ObservedProvider,
) -> Option<ProviderGridObservation> {
    if frame.len() > 2 * 1024 * 1024 || expected_generation.is_empty() {
        return None;
    }
    let line = std::str::from_utf8(frame).ok()?;
    let (crate::wire::DaemonEvent::Grid { id, grid }, _) =
        crate::wire::decode_event_with_route(line).ok()?
    else {
        return None;
    };
    if id != expected_session || grid.generation.0 != expected_generation || !grid.alt_screen {
        return None;
    }
    crate::sync::SyncState::new(expected_session)
        .on_grid(&id, &grid)
        .ok()?;
    if grid.rows > 256 || grid.cols > 512 || grid.rows.saturating_mul(grid.cols) > 32768 {
        return None;
    }
    let rows = grid
        .rows_cells
        .iter()
        .map(|row| {
            row.iter()
                .filter(|cell| cell.width != 0)
                .map(|cell| if cell.hidden { " " } else { cell.text.as_str() })
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    Some(ProviderGridObservation {
        revision: grid.revision.0,
        state: match provider {
            ObservedProvider::OpenCode => {
                classify_opencode_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>())
            }
            ObservedProvider::Codex => {
                classify_codex_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>())
            }
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic wire envelopes around real recorded, normalized provider rows. These test the
    // production schema/identity boundary, not a claim that this generated grid was captured.
    fn frame() -> serde_json::Value {
        frame_for(include_str!(
            "../../maestro-shell/tests/fixtures/opencode/1.18.23/permission.json"
        ))
    }

    fn frame_for(fixture: &str) -> serde_json::Value {
        let rows: Vec<String> = serde_json::from_str(fixture).unwrap();
        let cols = rows.iter().map(|row| row.chars().count()).max().unwrap();
        let cells = rows
            .iter()
            .map(|row| {
                row.chars()
                    .chain(std::iter::repeat(' '))
                    .take(cols)
                    .map(|ch| {
                        serde_json::json!({
                            "text": ch.to_string(), "width": 1,
                            "fg": {"kind":"named","name":"foreground"},
                            "bg": {"kind":"named","name":"background"}
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        serde_json::json!({"ev":"grid", "id":"session", "grid":{
            "version":2,"generation":"generation","revision":7,"base_revision":7,
            "cols":cols,"rows":rows.len(),"rows_cells":cells,
            "cursor_line":0,"cursor_col":0,"cursor_visible":true,"cursor_shape":"block",
            "alt_screen":true,"app_cursor":false,"bracketed_paste":true,"focus_reporting":false
        }})
    }

    fn observe(frame: &serde_json::Value) -> Option<ProviderGridObservation> {
        observe_opencode_grid(&serde_json::to_vec(frame).unwrap(), "session", "generation")
    }

    #[test]
    fn exact_current_grid_is_observed_without_exposing_terminal_text() {
        assert_eq!(
            observe(&frame()),
            Some(ProviderGridObservation {
                revision: 7,
                state: ProviderAttentionObservation::Waiting
            })
        );
    }

    #[test]
    fn codex_dispatch_requires_exact_provider_and_preserves_grid_fences() {
        let codex = frame_for(include_str!(
            "../../maestro-shell/tests/fixtures/codex/0.159.2/permission.json"
        ));
        let observe_codex = |frame: &serde_json::Value| {
            observe_provider_grid(
                &serde_json::to_vec(frame).unwrap(),
                "session",
                "generation",
                ObservedProvider::Codex,
            )
        };
        assert_eq!(
            observe_codex(&codex).unwrap().state,
            ProviderAttentionObservation::Waiting
        );
        assert_eq!(
            observe(&codex).unwrap().state,
            ProviderAttentionObservation::Unknown
        );
        assert_eq!(
            observe_codex(&frame()).unwrap().state,
            ProviderAttentionObservation::Unknown
        );
        for (field, value) in [
            ("generation", serde_json::json!("stale")),
            ("version", serde_json::json!(999)),
            ("rows", serde_json::json!(1)),
            ("alt_screen", serde_json::json!(false)),
        ] {
            let mut wrong = codex.clone();
            wrong["grid"][field] = value;
            assert!(observe_codex(&wrong).is_none());
        }
        let mut hidden = codex;
        for row in hidden["grid"]["rows_cells"].as_array_mut().unwrap() {
            for cell in row.as_array_mut().unwrap() {
                cell["hidden"] = serde_json::json!(true);
            }
        }
        assert_eq!(
            observe_codex(&hidden).unwrap().state,
            ProviderAttentionObservation::Unknown
        );
    }

    #[test]
    fn wrong_session_generation_schema_or_layout_cannot_observe() {
        for (field, value) in [
            ("generation", serde_json::json!("replacement")),
            ("version", serde_json::json!(999)),
            ("rows", serde_json::json!(1)),
            ("alt_screen", serde_json::json!(false)),
        ] {
            let mut frame = frame();
            frame["grid"][field] = value;
            assert!(observe(&frame).is_none(), "{field}");
        }
        let mut wrong = frame();
        wrong["id"] = serde_json::json!("other");
        assert!(observe(&wrong).is_none());
        assert!(observe_opencode_grid(b"{}", "session", "generation").is_none());
        assert!(
            observe_opencode_grid(&vec![b' '; 2 * 1024 * 1024 + 1], "session", "generation")
                .is_none()
        );
    }

    #[test]
    fn hidden_control_text_is_not_a_visible_prompt() {
        let mut frame = frame();
        for row in frame["grid"]["rows_cells"].as_array_mut().unwrap() {
            for cell in row.as_array_mut().unwrap() {
                cell["hidden"] = serde_json::json!(true);
            }
        }
        assert_eq!(
            observe(&frame).unwrap().state,
            ProviderAttentionObservation::Unknown
        );
    }
}
