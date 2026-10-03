//! Read-only, revision-bound selection acquisition. Pages never become viewport pixels.
use crate::client::CellPos;
use crate::terminal_selection::ScrolledSelection;
use crate::wire::{
    Cell, GridSnapshot, Revision, SessionGeneration, MAX_SCROLLBACK_ROWS_PER_REQUEST,
};
use maestro_protocol::row_copy::RowCopy;
use std::sync::Arc;

// Mirror the retained history bounds in pty-daemon/src/grid.rs, not the per-response wire cap.
// A selected live tail is already bounded by the accepted endpoint/source Grid frame.
const HISTORY_ROWS: i64 = 5000;
const HISTORY_CELLS: usize = 2_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PageRequest {
    pub ticket: u64,
    pub page: u32,
    pub generation: SessionGeneration,
    pub revision: Revision,
    pub cols: usize,
    pub offset: u32,
    pub count: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Cancelled,
    Stale,
    InvalidPage,
    Bounds,
    QueueRefused,
}

#[derive(Clone, Debug)]
pub(crate) struct PageResult {
    pub request: PageRequest,
    pub history_len: u32,
    pub result: Result<Arc<GridSnapshot>, Failure>,
}

pub(crate) enum PageStatus {
    Waiting,
    Ready(PageResult),
    Missing,
}

pub(crate) struct Acquisition {
    ticket: u64,
    page: u32,
    source: ScrolledSelection,
    endpoint: Arc<GridSnapshot>,
    endpoint_offset: u32,
    anchor: (i64, usize),
    focus: (i64, usize),
    start: i64,
    next: i64,
    end: i64,
    rows: Vec<Vec<Cell>>,
    row_copy: Vec<RowCopy>,
    history_len: Option<u32>,
}

impl Acquisition {
    pub fn new(
        ticket: u64,
        source: ScrolledSelection,
        anchor: CellPos,
        endpoint: Arc<GridSnapshot>,
        endpoint_offset: u32,
        focus: CellPos,
    ) -> Result<Self, Failure> {
        if source.grid.generation != endpoint.generation
            || source.grid.revision != endpoint.revision
            || source.grid.cols != endpoint.cols
            || source.grid.cols == 0
        {
            return Err(Failure::Stale);
        }
        let anchor = source.local(anchor).ok_or(Failure::Bounds)?;
        let focus = source.local(focus).ok_or(Failure::Bounds)?;
        source
            .grid
            .rows_cells
            .get(anchor.row)
            .and_then(|row| row.get(anchor.col))
            .ok_or(Failure::Bounds)?;
        endpoint
            .rows_cells
            .get(focus.row)
            .and_then(|row| row.get(focus.col))
            .ok_or(Failure::Bounds)?;
        let anchor = (
            anchor.row as i64 - i64::from(source.served_offset),
            anchor.col,
        );
        let focus = (focus.row as i64 - i64::from(endpoint_offset), focus.col);
        // The wire cannot address a positive live-row start. Include that bounded prefix and keep
        // the real selection endpoints separately; it is never copied merely because it was read.
        let start = anchor.0.min(focus.0).min(0);
        let end = anchor.0.max(focus.0);
        if -start > HISTORY_ROWS
            || usize::try_from(-start)
                .ok()
                .and_then(|rows| rows.checked_mul(source.grid.cols))
                .is_none_or(|cells| cells > HISTORY_CELLS)
        {
            return Err(Failure::Bounds);
        }
        Ok(Self {
            ticket,
            page: 0,
            source,
            endpoint,
            endpoint_offset,
            anchor,
            focus,
            start,
            next: start,
            end,
            rows: Vec::new(),
            row_copy: Vec::new(),
            history_len: None,
        })
    }

    pub fn request(&self) -> Option<PageRequest> {
        if self.next > self.end {
            return None;
        }
        let offset = u32::try_from(-self.next.min(0)).ok()?;
        let count = (self.end + i64::from(offset) + 1)
            .min(i64::from(MAX_SCROLLBACK_ROWS_PER_REQUEST)) as u16;
        Some(PageRequest {
            ticket: self.ticket,
            page: self.page,
            generation: self.source.grid.generation.clone(),
            revision: self.source.grid.revision,
            cols: self.source.grid.cols,
            offset,
            count,
        })
    }

    pub fn accept(&mut self, reply: PageResult) -> Result<(), Failure> {
        if self.request().as_ref() != Some(&reply.request) {
            return Err(Failure::Stale);
        }
        if self
            .history_len
            .is_some_and(|depth| depth != reply.history_len)
        {
            return Err(Failure::Stale);
        }
        self.history_len = Some(reply.history_len);
        let grid = reply.result?;
        if grid.generation != reply.request.generation || grid.revision != reply.request.revision {
            return Err(Failure::Stale);
        }
        if grid.cols != reply.request.cols
            || grid.rows == 0
            || grid.rows > usize::from(reply.request.count)
        {
            return Err(Failure::InvalidPage);
        }
        // An offset-zero reply may be cell-budget-limited before the positive row already reached
        // by the preceding page. It proves no additional rows; do not repeat it or publish a prefix.
        if reply.request.offset != 0 || self.next < grid.rows as i64 {
            self.append(&grid, -i64::from(reply.request.offset))?;
        }
        self.page = self.page.checked_add(1).ok_or(Failure::Bounds)?;
        // offset_from_top cannot address ANY positive live-row start. After the offset-zero page
        // (or the wire row ceiling), complete only from the frozen exact endpoint/source pixels.
        while self.next <= self.end
            && (self.next >= i64::from(MAX_SCROLLBACK_ROWS_PER_REQUEST)
                || (reply.request.offset == 0 && self.next > 0))
        {
            let source = self.source.grid.clone();
            let endpoint = self.endpoint.clone();
            if self
                .append(&source, -i64::from(self.source.served_offset))
                .is_err()
            {
                self.append(&endpoint, -i64::from(self.endpoint_offset))?;
            }
        }
        Ok(())
    }

    fn append(&mut self, grid: &GridSnapshot, start: i64) -> Result<(), Failure> {
        let metadata = grid.row_copy.as_ref().ok_or(Failure::InvalidPage)?;
        if grid.rows_cells.len() != grid.rows
            || grid
                .rows_cells
                .iter()
                .any(|row| row.len() != self.source.grid.cols)
            || !crate::wire::row_copy_cells_valid(&grid.rows_cells, Some(metadata))
        {
            return Err(Failure::InvalidPage);
        }
        let first = usize::try_from(self.next - start).map_err(|_| Failure::InvalidPage)?;
        let available = grid
            .rows
            .checked_sub(first)
            .filter(|n| *n > 0)
            .ok_or(Failure::InvalidPage)?;
        let count = available.min((self.end - self.next + 1) as usize);
        if let Some(previous) = self.row_copy.last() {
            if metadata[first].starts_line != Some(!previous.soft_wrap) {
                return Err(Failure::InvalidPage);
            }
        }
        self.rows
            .extend_from_slice(&grid.rows_cells[first..first + count]);
        self.row_copy
            .extend_from_slice(&metadata[first..first + count]);
        self.next += count as i64;
        Ok(())
    }

    pub fn finish(self) -> Option<(ScrolledSelection, CellPos, CellPos)> {
        if self.next <= self.end {
            return None;
        }
        let mut grid = (*self.source.grid).clone();
        grid.rows = self.rows.len();
        grid.rows_cells = self.rows;
        grid.row_copy = Some(self.row_copy);
        grid.cursor_visible = false;
        let position = |(row, col): (i64, usize)| CellPos {
            row: self.source.origin.row + (row - self.start) as usize,
            col: self.source.origin.col + col,
        };
        let anchor = position(self.anchor);
        let focus = position(self.focus);
        let source = ScrolledSelection {
            grid: Arc::new(grid),
            served_offset: (-self.start) as u32,
            ..self.source
        };
        Some((source, anchor, focus))
    }
}
