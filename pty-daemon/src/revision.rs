//! Generation + revision: the correctness backbone that lets a renderer trust
//! its screen. Four separate failure modes — attach applying a snapshot and a
//! live chunk out of order, a late attacher missing an exit, the daemon grid and
//! renderer grid silently drifting, and a lagged stream losing bytes — all
//! reduce to one question the renderer must be able to answer: "is what I'm
//! holding still a contiguous, in-order view of the daemon's grid?" Generation +
//! revision make that answerable.
//!
//! - `SessionGeneration` is a random UUID minted when a grid is created. A
//!   respawn (new process, fresh grid) mints a NEW generation. The renderer
//!   treats a generation change as "throw everything away and re-snapshot" — it
//!   cannot incrementally bridge two generations.
//! - `Revision` is a per-generation counter starting at 0, incremented after
//!   every committed grid mutation (parsed output, resize). A snapshot is taken
//!   at a revision; incremental damage carries `base_revision -> revision`. The
//!   renderer applies damage only if its current revision equals the damage's
//!   `base_revision`; any gap means it lost a mutation and must re-snapshot.
//!
//! Overflow policy: a u64 revision cannot realistically wrap (at a billion
//! mutations/sec it takes ~585 years), but we still refuse to wrap silently —
//! `Revision::next` returns `None` at the ceiling, and the grid responds by
//! minting a new generation rather than aliasing revision 0 of the old one.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifies one grid lifetime. Minted on grid creation and on respawn. A
/// renderer that sees a generation different from the one it last synced to must
/// discard its screen and restore from a fresh snapshot — generations are not
/// incrementally bridgeable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct SessionGeneration(Uuid);

impl SessionGeneration {
    /// Mint a fresh, random generation.
    pub fn new() -> Self {
        SessionGeneration(Uuid::new_v4())
    }
}

impl std::fmt::Display for SessionGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A per-generation mutation counter. Starts at 0; each committed grid mutation
/// advances it by one. Monotonic within a generation, so a renderer can detect a
/// gap (it expected `base_revision` but holds something earlier/later).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Revision(pub u64);

impl Revision {
    /// The starting revision of a fresh generation.
    pub const ZERO: Revision = Revision(0);

    /// The next revision, or `None` at the u64 ceiling. `None` is the signal to
    /// roll a new generation rather than wrap back to an ambiguous 0.
    pub fn next(self) -> Option<Revision> {
        self.0.checked_add(1).map(Revision)
    }
}
