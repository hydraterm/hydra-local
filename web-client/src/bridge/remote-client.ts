// S5 — RemoteClientController: the framework-light state machine the connection-shell UI binds to. It
// orchestrates the whole flow — sign in → list desktops → connect (signaling+auth) → list sessions →
// attach → terminal — and exposes a single observable `view` + actions. A React (or plain) shell just
// renders `view` and calls the actions; the core stays framework-free (and unit-testable without a DOM).
//
// No terminal bytes touch the cloud: the cloud is used only for devices/token/signaling.

import {
  AuthAccountDeletedError,
  AuthAccountDeletionCancelledError,
  AuthClientTrustRequiredError,
  AuthSecondFactorRequiredError,
  type AuthSecondFactorStrategy,
  type AuthProvider,
} from './auth-contract.js'
import { clearAllAccountState } from './account-reset.js'
import type { DeviceIdentity } from './device-identity.js'
import {
  RemoteSession,
  SCROLLBACK_RESPONSE_TIMEOUT_MS,
  type RemoteSessionMetadata,
} from './remote-session.js'
import type {
  ConnectionAttemptPhase,
  ConnectionMode,
  ControlState,
  Diagnostics,
  RemoteTransport,
} from './remote-transport.js'
import { defaultDiagnostics } from './remote-transport.js'
import { MultiAttachManager } from './multi-attach-manager.js'
import { MultiPaneTerminalSession } from './multi-pane-terminal.js'
import type { TerminalPaneRenderer } from './channel-terminal-bank.js'
import { loadDeviceLabels, saveDeviceLabels } from './device-label-store.js'
import { loadLastOpenedSession, saveLastOpenedSession } from './last-opened-store.js'
import { clearHints, loadHints, saveHints } from './reconnect-hints.js'
import { connTrace, mintTraceId, short, buildStamp } from './conn-trace.js'
import { parseRemoteLayout, serializeRemoteLayout, type RemoteLayoutPort } from './remote-layout-contract.js'
import { loadFavoriteSessions, saveFavoriteSessions, toggleFavorite } from './session-favorites-store.js'
import { loadKnownSessions, saveKnownSessions } from './session-cache-store.js'
import { loadSessionOrder, saveSessionOrder } from './session-order-store.js'
import { loadHiddenSessions, saveHiddenSessions } from './session-visibility-store.js'
import { loadSessionLabels, saveSessionLabels } from './session-label-store.js'
import { loadLayoutPresetState, saveLayoutPresetState } from './layout-preset-store.js'
import { moveSession as moveSessionInOrder } from '../model/session-order.js'
import { hideSession as hideSessionInView, unhideSession as unhideSessionInView } from '../model/session-visibility.js'
import { sessionLabel } from '../model/session-row.js'
import { agentFromLabel, HISTORY_AGENT_OPTIONS, isRunnableAgentKind } from '../model/agent-provider-core.js'
import { workspaceTreeFromRemoteView } from '../model/workspace-tree.js'
import type {
  AgentSessionMeta,
  AgentSessionPreviewLine,
  DesktopPlatform,
  DirectoryEntry,
  FullDiskAccessStatus,
  NewWindowOptions,
  ProjectEditOptions,
  RemoteAgentKind,
  RemoteLaunchFlags,
} from '../protocol/control-messages.js'
import {
  createPreset, renamePreset, deletePreset, setDefaultPreset, restorePreset,
  type LayoutPresetState,
} from '../model/layout-preset.js'
import {
  CREATE_INTERRUPTED_MESSAGE,
  MACOS_FULL_DISK_ACCESS_REQUIRED_CODE,
  MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE,
  createSessionMessage,
} from '../model/create-session-messages.js'
import { validateTokenScope } from '../model/token-scope.js'
import { safeMessage } from './safe-message.js'
import {
  singlePane, splitActive, closePane as closePaneInLayout, focusPane as focusPaneInLayout,
  setPaneSession as setPaneSessionInLayout, activeLeaf, findLeaf, leaves, swapPaneSessions,
  rebalanceLayout, setSplitRatio, paneNeighbor, swallowCanonical,
  reconcileExistence, stashPane as stashPaneInWorkspace, revivePane as reviveInWorkspace, paneCount,
  reviveWindow as reviveWindowInWorkspace, renamePaneId,
  readingOrderPanes, addStashed, removePaneEverywhere,
  type PaneLayout, type SplitDir, type EdgeDir, type WorkspacePanes, type StashedPane,
} from '../model/pane-layout.js'
import { GridRenderer } from '../terminal/grid-renderer.js'
import {
  DEFAULT_SESSION_GRID,
  MAX_COLS,
  MAX_ROWS,
  MIN_COLS,
  MIN_ROWS,
} from '../terminal/viewport.js'
import type { GridSnapshot } from '../protocol/web-protocol.js'
import { highlightSpans, type HighlightSpan } from '../terminal/search-highlight.js'
import type { TerminalSearchMatch, TerminalSearchStatus } from '../terminal/search.js'
import type { PixelPoint, SelectionGeometry, SelectionRange } from '../terminal/selection.js'
import type { KeyEvent } from '../terminal/input-encoder.js'
import { encodeMouse } from '../terminal/input-encoder.js'
import {
  beginConnectionAttempt,
  recordInitialHistoryCompletion,
  resetTransportMetrics,
  type ConnectionAttemptMetricRecorder,
  type ConnectionAttemptOutcome,
  type ConnectionAttemptTrigger,
  type InitialHistoryResult,
} from './render-metrics.js'
import {
  ProgressDeadline,
  REMOTE_CONNECT_ABSOLUTE_MS,
  REMOTE_CONNECT_INACTIVITY_MS,
  type ConnectDeadlineScope,
} from './connect-deadline.js'

export interface DesktopDevice {
  deviceId: string
  label: string
  revoked: boolean
  /** Enrolled desktop ed25519 public key (raw 32-byte base64). Used to verify signed WebRTC answer proofs. */
  publicKey?: string
  /** When the device was enrolled (cloud `createdAtMs`). Optional — only shown if the backend provides it;
   * never faked. Used for an honest "Added <date>" on the card. */
  createdAtMs?: number
  /** Server time of the device's last SIGNED heartbeat (cloud `lastSeenMs`). Optional — undefined until the
   * device has ever heartbeat. Honest presence only ("Recently seen" / "Last seen <when>"); never "Online". */
  lastSeenMs?: number
}

export type Phase =
  | 'signed_out'
  | 'authenticating' // a sign-in/sign-up/verify request is in flight (drives the button spinner)
  | 'restoring' // checking the session cookie on load (refresh-resume)
  | 'devices' // signed in, choosing a desktop
  | 'connecting' // signaling + auth in progress
  | 'sessions' // authenticated, choosing a session
  | 'terminal' // attached
  | 'revoked'
  | 'plan_required'
  | 'offline'
  | 'error'

export interface RemoteWorkspacePaneMetadata {
  id: string
  sessionId: string
  name?: string
  stashed?: boolean
  live?: boolean
  /** The pane's session working directory, so the split picker can default to the source window's folder. */
  cwd?: string
}

export interface RemoteWorkspaceWindowMetadata {
  id: string
  name?: string
  focused?: boolean
  stashed?: boolean
  panes: RemoteWorkspacePaneMetadata[]
}

export interface RemoteWorkspaceProjectMetadata {
  id: string
  name: string
  root: string
  icon?: string
  accentColor?: string
  selected?: boolean
  launchDefaults?: {
    agent?: RemoteAgentKind
    /** Desktop vocabulary is 'none'|'resume'|'continue'; 'new' may still arrive from records written by
     * legacy remote builds (the form migrates it to 'none' on read). */
    resumeMode?: 'new' | 'none' | 'resume' | 'continue'
    model?: string
    dangerouslySkipPermissions?: boolean
    customCommand?: string
  }
  directories?: Array<{ name?: string; path: string }>
  /** The built-in "Terminal" project: plain-bash terminals, simplified dialogs (name-only), never deletable. */
  system?: boolean
  /** User hid this project from the sidebar. */
  hidden?: boolean
  windows: RemoteWorkspaceWindowMetadata[]
}

export interface RemoteWorkspaceMetadata {
  projects: RemoteWorkspaceProjectMetadata[]
}

const PRODUCT_RECOVERY_PROJECT_ID = 'system-product-recovery'

export interface RemoteSyncBrowserPaneDebug {
  projectId: string
  windowId: string
  paneId: string
  sessionIdPresent: boolean
  sessionLive: boolean
  placed: boolean
  desktopStashed: boolean
  pendingLanding: boolean
  clickable: boolean
  reason: string
}

export interface RemoteSyncBrowserDebug {
  phase: Phase
  traceId: string
  selectedDevice: string | null
  activeWindowId: string | null
  attachedSession: string | null
  sessionCount: number
  projectCount: number
  windowCount: number
  paneCount: number
  namedPanes: number
  redactedPanes: number
  layoutHydrated: boolean
  lastAppliedWorkspaceEpoch: number
  pendingLandingWindows: string[]
  knownCounts: { projects: number; windows: number; panes: number }
  paneLayoutsByWindow: Record<string, { placedSessions: string[]; stashed: Array<{ paneId: string; sessionId: string | null }>; windowStashed: boolean }>
  panes: RemoteSyncBrowserPaneDebug[]
  tree: Array<{
    id: string
    name: string
    isSelected: boolean
    statusDot: string
    windows: Array<{
      id: string
      name: string
      isFocused: boolean
      isStashed: boolean
      isStarting: boolean
      statusDot: string
      panes: Array<{
        id: string
        name: string
        sessionId: string
        isLive: boolean
        isStashed: boolean
        isStarting: boolean
        statusDot: string
      }>
    }>
  }>
}

export interface RemoteSyncDebugSnapshot {
  browser: RemoteSyncBrowserDebug
  agent?: unknown
  error?: string
}

export interface RemoteAgentSessionMeta extends AgentSessionMeta {
  /** Browser-local source cwd for this row: copied from the list_agent_sessions request that surfaced it.
   * Not part of the wire payload; used so preview/delete/resume operate on the same desktop folder even if the
   * active pane changes before the user clicks. */
  readonly listCwd?: string
}

export interface RemoteAgentSessionPreviewState {
  loading?: boolean
  error?: string
  lines?: readonly AgentSessionPreviewLine[]
}

export interface RemoteDirectoryBrowserState {
  loading: boolean
  requestId?: string
  path: string
  parent?: string
  entries: readonly DirectoryEntry[]
  error?: string
}

// R1: create-session copy moved to model/create-session-messages.ts (shared with the readiness daemon-not-
// ready predicate so they can't drift on a magic string). Re-exported for back-compat.
export { createSessionMessage }

/** Reconnect backoff base/cap (ms). Exponential `base * 2^attempt`, capped, plus jitter. Exported for tests. */
export const RECONNECT_BASE_MS = 800
export const RECONNECT_CAP_MS = 15_000
export const RECONNECT_MAX_ATTEMPTS = 6
/** Maximum inactivity between unique setup stages (preflight, relay/signaling, ICE, DataChannel, auth). A healthy
 * attempt may use several such windows, but repeated poll snapshots cannot extend one. Session-list loading has
 * its own post-auth watchdog below. */
export const CONNECT_WATCHDOG_MS = REMOTE_CONNECT_INACTIVITY_MS
/** A progressing connection may span several network/ICE steps, but can never remain in setup indefinitely. */
export const CONNECT_ABSOLUTE_WATCHDOG_MS = REMOTE_CONNECT_ABSOLUTE_MS
/** After auth, we ask the agent for the session list; the phase stays 'connecting' ("Loading its projects…") until
 * it arrives. Guard THAT step too — without it, a dropped/slow session_list hangs on "Loading…" forever (transport
 * auth cleared the connect watchdog). On timeout we re-request once, then fall back to offline+retry. */
export const SESSION_LIST_WATCHDOG_MS = 15_000
/** How long an attach may wait for terminal materialization (attach_ok + first terminal data) before we
 * surface a retryable error. A healthy attach should receive an initial grid/prompt quickly; without this,
 * one stuck attach can leave a blank terminal/pane with no user feedback. */
export const ATTACH_WATCHDOG_MS = 12_000
/** A missing first-history reply must never hold the pane hydration queue indefinitely. Valid chunk progress
 * refreshes the inactivity bound; a separate absolute cap prevents a peer from dribbling forever. */
export const INITIAL_HISTORY_WARM_INACTIVITY_MS = 8_000
export const INITIAL_HISTORY_WARM_ABSOLUTE_MS = 30_000
const CORRELATED_ATTACH_ERROR_CODES = new Set([
  'session_scope',
  'forbidden',
  'already_attached',
  'too_many_attaches',
  'attach_failed',
])
const LEGACY_UNAMBIGUOUS_ATTACH_ERROR_CODES = new Set([
  'session_scope',
  'already_attached',
  'too_many_attaches',
  'attach_failed',
])
/** Pane-row click should give fast feedback. If the attach/switch has not produced an attached channel quickly,
 * re-request the authoritative workspace/session snapshot; this gives the same healing effect users got from a
 * manual refresh without tearing down the terminal connection. */
export const PANE_SWITCH_REFRESH_MS = 2_000
/** After a browser-created desktop pane lands, give the local renderer one beat to spread/repaint, then re-attach
 * that one session for a fresh full Grid. This is the scoped equivalent of the manual refresh that fixed the
 * first-frame "not spread" symptom, without tearing down the page or connection. */
export const POST_CREATE_FRESH_ATTACH_MS = 450
/** How long an AUTHORITATIVELY-created session (split_pane_ok / project_edit_ok seed / session_created /
 * new_window_ok / revive_pane_ok named it) survives session-list snapshots that don't know it yet. The
 * desktop's DB commit + the agent's session-cache refresh land well inside this; a session the lists still
 * don't know after the grace really did die. */
export const CREATED_SESSION_GRACE_MS = 30_000
/** How long a desktop-authoritative mutation (create/split/new-window/project-edit/rename/…) may sit with
 * `creatingSession=true` waiting for its ok/error reply. Every such intent sets the flag and ONLY the reply
 * callback clears it — so one lost reply used to wedge ALL creation UI forever. The watchdog clears the flag
 * and surfaces an honest "the desktop did not reply" message instead. */
export const CREATING_WATCHDOG_MS = 12_000
/** Cadence for re-polling /v1/devices while the device list is shown (enroll/revoke appear live). */
export const DEVICE_REFRESH_INTERVAL_MS = 8_000
/** One-shot winsize settle re-push delay — must sit PAST the agent's ~2s winsize-owner-sessions tick so the
 * desktop has adopted this browser's per-pane ownership before the size is reasserted (see
 * scheduleWinsizeSettleRepush). */
export const WINSIZE_SETTLE_REPUSH_MS = 2_600

/** Fixed, content-blind copy for an unconfirmed logout. Never include provider/network response text here. */
const PENDING_LOGOUT_WARNING = 'Signed out locally, but Hydra could not confirm server sign-out. Check your connection and try again before signing in.'
const AUTH_COORDINATION_WARNING = 'Secure account switching requires a browser with Web Locks support. Update your browser and try again.'

function pendingLogoutWarning(error: unknown): string {
  return error instanceof Error && error.name === 'AuthCoordinationError'
    ? AUTH_COORDINATION_WARNING
    : PENDING_LOGOUT_WARNING
}

/** Content-blind equality for the device list so the poll only re-renders on a REAL change (add/remove/revoke/rename
 * /presence). Compares the fields the card shows; avoids churning the UI every 8s when nothing changed. */
export function devicesEqual(a: readonly DesktopDevice[], b: readonly DesktopDevice[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    const x = a[i]
    const y = b[i]
    if (
      x.deviceId !== y.deviceId ||
      x.label !== y.label ||
      x.revoked !== y.revoked ||
      x.createdAtMs !== y.createdAtMs ||
      x.lastSeenMs !== y.lastSeenMs ||
      x.publicKey !== y.publicKey
    ) {
      return false
    }
  }
  return true
}

/**
 * The delay (ms) before reconnect attempt `attempt` (0-based). Bounded exponential backoff with FULL jitter:
 * the exponential term is `min(cap, base * 2^attempt)`, then the actual delay is a random point in
 * `[term/2, term]` — so retries are capped (never unbounded) AND spread out (no thundering herd when many
 * clients drop at once). `rand` is injected (Math.random in prod) for deterministic tests. Always ≥ 0.
 */
export function reconnectDelayMs(attempt: number, rand: () => number = Math.random): number {
  const exp = Math.min(RECONNECT_CAP_MS, RECONNECT_BASE_MS * 2 ** Math.max(0, attempt))
  // full-jitter: half the term is fixed, the other half is randomized → range [exp/2, exp].
  return Math.round(exp / 2 + rand() * (exp / 2))
}

/** A content-blind reason string from the explicit legacy/fake constructor-token seam. Production does not mint a
 * constructor token; it enrolls the browser first and lets the transport mint only the signaling-session-bound
 * token. We retain these reasons solely so older injected transports remain deterministic in tests. */
export type TokenMintFailureReason =
  | 'device_revoked'
  | 'device_not_found'
  | 'account_mismatch'
  | 'unauthorized'
  | 'forbidden'
  | 'mint_failed'

/** Typed, allowlisted legacy/fake constructor-token failure. */
export class TokenMintError extends Error {
  constructor(readonly reason: TokenMintFailureReason) {
    super(reason)
    this.name = 'TokenMintError'
  }
}

function tokenMintReason(e: unknown): string {
  if (e instanceof TokenMintError) return e.reason
  const msg = e instanceof Error ? e.message : String(e ?? '')
  for (const code of ['device_revoked', 'device_not_found', 'account_mismatch', 'unauthorized', 'forbidden']) {
    if (msg.toLowerCase().includes(code)) return code
  }
  return 'mint_failed'
}

function tokenMetricOutcome(e: unknown): ConnectionAttemptOutcome {
  const reason = tokenMintReason(e)
  if (reason === 'device_revoked') return 'revoked'
  if (reason === 'account_mismatch' || reason === 'unauthorized' || reason === 'forbidden') return 'auth_refused'
  // A legacy constructor-token control-plane failure is not evidence that ICE/DataChannel networking failed.
  return 'control_plane_failure'
}

function controlStateMetricOutcome(state: ControlState): ConnectionAttemptOutcome | null {
  switch (state) {
    case 'authenticated': return 'connected'
    case 'authorization_required': return 'authorization_required'
    case 'entitlement_required': return 'control_plane_failure'
    case 'access_required': return 'control_plane_failure'
    case 'auth_refused': return 'auth_refused'
    case 'revoked': return 'revoked'
    case 'offline':
    case 'error':
    case 'closed':
      return 'network_failure'
    default:
      return null
  }
}

/** Bind a transport to one controller connection generation. Closing/replacing a session does not necessarily
 * prevent an already-queued browser/WebRTC callback from firing, so every inbound and outbound transport action
 * is gated by current ownership. `close()` deliberately always reaches the underlying transport so retirement
 * still tears down the peer after ownership has moved on. */
function connectionOwnedTransport(transport: RemoteTransport, ownsConnection: () => boolean): RemoteTransport {
  const owned: RemoteTransport = {
    sendText: (json) => ownsConnection() ? transport.sendText(json) : false,
    sendBinary: (bytes) => ownsConnection() ? transport.sendBinary(bytes) : false,
    sendBinaryBatch: (frames) => ownsConnection() ? transport.sendBinaryBatch(frames) : false,
    sendBulkBinaryBatch: (frames) => ownsConnection() ? transport.sendBulkBinaryBatch(frames) : false,
    onText: (handler) => transport.onText((json) => { if (ownsConnection()) handler(json) }),
    onBinary: (handler) => transport.onBinary((bytes) => { if (ownsConnection()) handler(bytes) }),
    onState: (handler) => transport.onState((state) => { if (ownsConnection()) handler(state) }),
    fail: () => ownsConnection() ? transport.fail() : transport.close(),
    close: () => transport.close(),
  }
  // Preserve optional-method absence. RemoteSession treats an absent currentToken as the legacy/fake path; adding
  // a method that merely returned null would silently change which constructor token it presents in tests/legacy.
  if (transport.currentToken) {
    owned.currentToken = () => ownsConnection() ? transport.currentToken!() : null
  }
  if (transport.currentAuthorization) {
    owned.currentAuthorization = () => ownsConnection() ? transport.currentAuthorization!() : null
  }
  if (transport.refreshAuthorization) {
    owned.refreshAuthorization = async (current, signal) => {
      if (!ownsConnection()) return null
      const successor = await transport.refreshAuthorization!(current, signal)
      return ownsConnection() ? successor : null
    }
  }
  if (transport.onDiagnostics) {
    owned.onDiagnostics = (handler) => transport.onDiagnostics!((diagnostics) => {
      if (ownsConnection()) handler(diagnostics)
    })
  }
  return owned
}

function sessionCwdsFromMetadata(
  sessions: readonly string[],
  metadata: readonly RemoteSessionMetadata[],
): Record<string, string> {
  const live = new Set(sessions)
  const out: Record<string, string> = {}
  for (const m of metadata) {
    if (live.has(m.id) && m.cwd?.trim()) out[m.id] = m.cwd
  }
  return out
}

function cwdBasename(cwd: string | undefined): string | null {
  const trimmed = cwd?.trim()
  if (!trimmed) return null
  const withoutTrailing = trimmed.replace(/[\\/]+$/, '')
  if (!withoutTrailing) return '/'
  const parts = withoutTrailing.split(/[\\/]+/)
  return parts[parts.length - 1] || null
}

/** Build a canonical {@link WorkspacePanes} from a mirror layout + stash, applying the empty-grid convention (a single
 * empty placeholder pane → `layout: null`). Used so the per-window map entry always equals what `workspacePanes()`
 * would produce for the active window's mirror. Pure. */
function workspacePanesFrom(layout: PaneLayout, stashed: readonly StashedPane[]): WorkspacePanes {
  const placedIsEmpty = layout.root.kind === 'leaf' && layout.root.sessionId === null
  return { layout: placedIsEmpty ? null : layout, stashed: [...stashed] }
}

/** An empty per-window WorkspacePanes (no placed grid, no stash). */
function emptyWorkspace(): WorkspacePanes {
  return { layout: null, stashed: [] }
}

/** Carry a window's user-stashed flag (R2) across a rebuild of its WorkspacePanes: the flag survives only
 * while nothing is placed — placing a pane un-hides the window (a visible grid can't be "stashed"). */
function preserveWindowStashed(entry: WorkspacePanes, prev: WorkspacePanes | undefined): WorkspacePanes {
  return prev?.windowStashed && !entry.layout ? { ...entry, windowStashed: true } : entry
}

/** The pane name the DESKTOP set for a session (from workspace metadata), if any — this is how a rename made on
 * LOCAL flows to the remote display. Returns the first metadata pane whose sessionId matches. */
function desktopPaneNameForSession(view: RemoteClientView, id: string): string | undefined {
  for (const project of view.workspaceMetadata?.projects ?? []) {
    for (const window of project.windows) {
      for (const pane of window.panes) {
        if (pane.sessionId === id && pane.name?.trim()) return pane.name.trim()
      }
    }
  }
  return undefined
}

function displaySessionLabel(view: RemoteClientView, id: string): string {
  // Priority: an explicit browser rename wins (the user set it HERE); else the DESKTOP's pane name (local→remote name
  // flow); else cwd basename; else "Terminal N". This makes a name set on local appear on remote and vice-versa.
  const custom = view.sessionLabels[id]
  if (custom) return custom
  const desktopName = desktopPaneNameForSession(view, id)
  if (desktopName) return desktopName
  const cwdLabel = cwdBasename(view.sessionCwds[id])
  if (cwdLabel) return cwdLabel
  const index = view.sessions.indexOf(id)
  return index >= 0 ? `Terminal ${index + 1}` : id
}

function desktopActionMessage(prefix: string, code: string, message: string): string {
  if (code === MACOS_FULL_DISK_ACCESS_REQUIRED_CODE) return MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
  const cleaned = safeMessage(message || code)
  return cleaned ? `${prefix}: ${cleaned}` : prefix
}

function trustedDesktopError(code: string, message: string): string {
  return code === MACOS_FULL_DISK_ACCESS_REQUIRED_CODE
    ? MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
    : safeMessage(message || code)
}

export interface DesktopAccessView {
  readonly platform: DesktopPlatform | 'unknown'
  readonly fullDiskAccess: FullDiskAccessStatus
}

const UNKNOWN_DESKTOP_ACCESS: DesktopAccessView = {
  platform: 'unknown',
  fullDiskAccess: 'unknown',
}

export interface RemoteClientView {
  phase: Phase
  /** Sessionless optional-MFA continuation. Contains only public factor labels, never a code or provider
   * secret, and is cleared on completion, cancellation, logout, or account change. */
  authSecondFactor?: {
    strategies: readonly AuthSecondFactorStrategy[]
    selectedStrategy?: AuthSecondFactorStrategy
  } | null
  /** One-shot, non-secret notice after Clerk consumed a recovery code. Clerk exposes no remaining-code count,
   * so Hydra conservatively recommends replacing the set instead of inventing one. */
  recoveryCodeUsed: boolean
  accountId: string | null
  devices: DesktopDevice[]
  sessions: string[]
  selectedDevice: string | null
  attachedSession: string | null
  /** Non-null only while an explicit open/reconnect/manual-attach is still acquiring a paintable terminal.
   * This is deliberately separate from `phase === 'sessions'`: sessions is also the stable workspace reached
   * after an intentional detach or a failed attach, where loading chrome would be dishonest and actionable
   * recovery/empty-state controls must remain visible. */
  terminalAcquisition: 'connecting' | 'loading' | null
  /** Browser-local hint for the last session the user opened on this account+desktop. Distinct from Active
   * and from reconnect resume; survives detach/reload but never auto-attaches by itself. */
  lastOpenedSessionId: string | null
  /** Transient: set true for ONE sessions-list update when the "Recent session" marker was dropped because that
   * session ended on the desktop (vs. was never set). Lets the sessions UI explain the disappearance instead of
   * the reopen affordance silently vanishing. Content-blind (a boolean). Cleared on the next list/attach. */
  recentSessionEnded: boolean
  /** Slice E "New session": true while a create_session is in flight (button disabled); `createSessionError`
   * holds a friendly message when the last create failed (cleared on the next attempt / a fresh list). */
  creatingSession: boolean
  createSessionError: string | null
  /** Step 18: bounded user-visible feedback for desktop-control intents such as split/stash/rename/focus/
   * project edits. Kept separate from createSessionError so a failed rename/window action is not mislabeled
   * as a new-session failure. Content-blind: protocol code + scrubbed message only. */
  desktopActionMessage: string | null
  /** Session id → readable label. Browser-local persistence only: labels survive reload for the same
   * account+desktop+session ids, but do not imply daemon/cloud session persistence. */
  sessionLabels: Record<string, string>
  /** Session id → daemon-reported cwd. Used only for display labels; never stores terminal content. */
  sessionCwds: Record<string, string>
  /** Optional desktop-provided project/window/pane metadata. Content-blind: ids, labels, colors, focus/stash
   * only; never terminal bytes. Null means the browser must use its cwd/session fallback tree. */
  workspaceMetadata: RemoteWorkspaceMetadata | null
  /** Wall-clock (ms) of the last authoritative desktop session/workspace metadata list. Content-blind freshness
   * marker only; lets diagnostics show whether the mirrored dashboard was refreshed recently. */
  lastSessionListAtMs?: number
  /** Prior local agent-history sessions reported by the desktop for the current project context. Content-blind:
   * id, agent, modified time, and message count only. Message text belongs to a separate preview op. */
  agentSessions: RemoteAgentSessionMeta[]
  /** True once at least one authoritative agent-session list result has landed. Distinguishes "asked the desktop
   * and it has no prior sessions" (→ honest empty state) from "haven't asked yet" (→ show nothing). */
  agentSessionsListed: boolean
  /** The REMOVED (⊘-hidden) sessions for the folder currently being browsed — powers the Removed sessions section. */
  hiddenAgentSessions: RemoteAgentSessionMeta[]
  hiddenAgentSessionsListed: boolean
  /** Prior-session preview text by `${agent}:${sessionId}`. This is the explicit SessionPicker content-preview
   * exception; it is only populated after the user asks to preview a row. */
  agentSessionPreviews: Record<string, RemoteAgentSessionPreviewState>
  /** Bounded error from a SessionPicker manage op (rename/hide/delete); null when none. */
  agentSessionManageError: string | null
  /** Remote folder browser for ProjectForm. Content-blind: directory names/paths only. */
  directoryBrowser: RemoteDirectoryBrowserState | null
  /** Browser-local favorite/pinned session ids, scoped by account+desktop. Content-blind: ids only. */
  favoriteSessions: string[]
  /** Browser-local manual session order, scoped by account+desktop. Content-blind: ids only. */
  sessionOrder: string[]
  /** Browser-local hidden/archived sessions, scoped by account+desktop. Content-blind: ids only. */
  hiddenSessions: string[]
  /** Session ids that have produced output since they were last focused (a non-active pane painted). Cleared
   * when that session becomes the active pane. Content-blind: ids only — never any terminal text. Drives a
   * subtle "unread" dot on the session row / pane header. */
  unreadSessions: string[]
  /** Browser-local last-known session ids by desktop, from the last authoritative daemon session list. This
   * lets the dashboard show "saved sessions" after refresh/back before reconnecting. Content-blind hint only:
   * ids are never treated as live authority until the desktop reports them again. */
  knownSessionsByDevice: Record<string, string[]>
  /** Browser-local desktop label overrides, scoped by account. UI-only until a backend label PATCH is
   * explicitly approved; stores only device ids + labels. */
  deviceLabels: Record<string, string>
  /** F2: the in-progress text in the "New session" name field. Seeds the input's initial value; cleared on a
   * successful create, preserved on a failed one so retry keeps what the user typed. */
  newSessionLabel: string
  /** Roadmap §4: browser multi-pane layout (split tree + active pane). Pure layout state — leaves map to
   * sessions in a later slice. PER-WINDOW model: this is the MIRROR of the ACTIVE window's placed grid (the source of
   * truth is `paneLayoutsByWindow[activeWindowId]`). Every read-site reads this mirror; every mutation goes through
   * applyWorkspace, which updates both the mirror and the map. When `activeWindowId` is null (pre-metadata) this is the
   * single flat grid, identical to the old behavior. */
  paneLayout: PaneLayout
  /** PER-WINDOW: which desktop window's grid the mirror (`paneLayout`/`browserStashed`) currently reflects. Null before
   * any window metadata arrives (single-grid fallback). Set by setActiveWindow + repaired on reconcile. Optional so
   * existing view fixtures (which set only paneLayout) compile untouched. */
  activeWindowId?: string | null
  /** PER-WINDOW source of truth: one WorkspacePanes (placed layout + browser stash) per desktop window id. The mirror
   * (`paneLayout`/`browserStashed`) reflects `[activeWindowId]`. Optional/absent = single-grid (mirror is the truth). */
  paneLayoutsByWindow?: Record<string, WorkspacePanes>
  /** pane existence contract: panes that EXIST on local (from workspaceMetadata) but the browser
   * hasn't PLACED in its grid yet. The browser runs its OWN layout — `paneLayout` is the placed grid, this is
   * the browser-local stash. Filled by reconcileExistence on each workspaceMetadata update (first connect → all
   * local panes land here; grid starts on the single default pane). Revive moves one into the grid; stashing a
   * placed pane moves it back here — all BROWSER-LOCAL (no wire to the desktop). Content-blind: ids/names only. */
  browserStashed: StashedPane[]
  /** docs/architecture/terminal.md: who sizes the shared PTY — 'local' (desktop, default: browser scales) or 'remote'
   * (this browser sizes the PTY to its active pane; Claude/TUIs redraw for it; the desktop reflows + does NOT
   * counter-resize). One owner at a time → no ping-pong. Set via the Local/Remote topbar toggle. */
  winsizeOwner: 'local' | 'remote'
  /** Roadmap §8: browser-local named pane-layout presets, scoped to the signed-in account. Content-blind. */
  layoutPresetState: LayoutPresetState
  /** S3c — which path carried the connection (UI badge): direct / relay / failed / unknown. */
  connectionMode: ConnectionMode
  /** S3c-browser-smoke — observable connection diagnostics for the dev panel. */
  diagnostics: Diagnostics
  /** Authenticated agent-reported Git identity for QA cohort visibility. Null before auth and for legacy/invalid
   * peers. This is a bounded build label, not cryptographic attestation. */
  agentBuildGit: string | null
  /** Authenticated desktop filesystem-access readiness. Legacy agents remain unknown. */
  desktopAccess: DesktopAccessView
  /** The auth state for the panel (mirrors the control flow). */
  authState: 'idle' | 'authenticated' | 'refused' | 'revoked'
  /** Dev: the browser's device id (the token's subject → the correct revoke target). Shown in the panel. */
  browserDeviceId: string | null
  error: string | null
  /** G4: wall-clock time of the next scheduled reconnect attempt (undefined = none scheduled). Set when a
   * retry is scheduled, cleared on success / manual reconnect / give-up / disconnect. Lets the readiness
   * model show an honest "next try in Ns" countdown derived from real backoff timing. */
  nextRetryAtMs?: number
  /** G5: true while an actual reconnect attempt (doReconnect → connectTo) is in flight, so the offline
   * screen can show "Reconnecting…" and disable the manual button to avoid a double-call. Distinct from
   * nextRetryAtMs (a retry is merely SCHEDULED, not yet running). Cleared when the attempt settles. */
  reconnectingNow?: boolean
  /** Wall-clock (ms) of the last SUCCESSFUL authenticate (control state → authenticated). Lets the UI show a
   * content-blind "Connected <relative time> ago" line for reconnect supportability. Survives across reconnects
   * (re-stamped on each fresh auth). Undefined before the first connect. */
  lastConnectedAtMs?: number
  /** "Add desktop" enrollment: the short-lived link code being shown (null = none). Every issuance requires
   * fresh user verification by the exact current account passkey. */
  enroll: {
    issuing: boolean
    code: string | null
    expiresAtMs: number | null
    error: string | null
    stage?: 'confirming_passkey'
  }
  /** Revoke a desktop: `confirmingDeviceId` = a row awaiting confirm; `pendingDeviceId` = revoke in flight;
   * `error` = a recoverable per-action failure (device stays visible). Revoke cuts live + future access. */
  revoke: { confirmingDeviceId: string | null; pendingDeviceId: string | null; error: string | null }
  /** Self-service account deletion UI. `notice` survives the successful reset long enough to explain the
   * signed-out result; pending means only managed-auth cleanup remains, never product data access. */
  accountDeletion: {
    confirming: boolean
    deleting: boolean
    error: string | null
    notice: string | null
    identityDeletionPending: boolean
  }
  /** ACCESS PASSKEY (#11): registering the account passkey (WebAuthn) that authorizes new browsers.
   * `registering` = ceremony in flight; `registered` = a passkey exists; `error` = a recoverable failure. */
  passkey: {
    registering: boolean
    registered: boolean
    error: string | null
    /** Whether the cloud anchor has been authoritatively loaded. `unavailable` must not be treated as absent:
     * offering registration then could create an orphan credential while an unseen anchor still exists. */
    status?: 'loading' | 'present' | 'absent' | 'unavailable'
    replacing?: boolean
    credentialId?: string
    createdAtMs?: number
    generation?: number
    /** Positive outcome copy is separate from `error`, so successful recovery is never styled as a failure. */
    notice?: string
    /** The create() ceremony finished and the immediate signed possession confirmation is now active. */
    stage?: 'confirming_possession'
  }
}

/** Browser page-lifecycle signals that can wake a reconnect loop after a long offline/sleep period. The
 * production source is window/document; the small interface keeps controller tests deterministic and gives the
 * controller explicit listener ownership. */
export interface RemoteReconnectLifecycle {
  onOnline(listener: () => void): () => void
  onVisibilityChange(listener: () => void): () => void
  isVisible(): boolean
  isOnline(): boolean
}

function browserReconnectLifecycle(): RemoteReconnectLifecycle | null {
  if (
    typeof window === 'undefined' || typeof document === 'undefined' ||
    typeof window.addEventListener !== 'function' || typeof window.removeEventListener !== 'function' ||
    typeof document.addEventListener !== 'function' || typeof document.removeEventListener !== 'function'
  ) return null
  return {
    onOnline(listener) {
      window.addEventListener('online', listener)
      return () => window.removeEventListener('online', listener)
    },
    onVisibilityChange(listener) {
      document.addEventListener('visibilitychange', listener)
      return () => document.removeEventListener('visibilitychange', listener)
    },
    isVisible: () => document.visibilityState !== 'hidden',
    // Some embedded browsers omit navigator.onLine. Only an explicit `false` suppresses a visibility wake;
    // the `online` event itself remains authoritative and does not consult this hint.
    isOnline: () => typeof navigator === 'undefined' || navigator.onLine !== false,
  }
}

interface RemoteClientCommonDeps {
  auth: AuthProvider
  identity: DeviceIdentity
  /** Explicit runtime rollout gate. Omitted/false keeps the destructive control unavailable. */
  accountDeletionEnabled?: boolean
  /** Explicit hosted rollout gate. Omitted/false keeps unreleased Linux-server instructions absent. */
  linuxServerEnrollmentEnabled?: boolean
  /** Lists the account's desktop devices (S1 GET /v1/devices, filtered to desktops). */
  listDesktops: (credential: string) => Promise<DesktopDevice[]>
  /** Issues a short-lived, single-use desktop enrollment code only after fresh UV by the exact current passkey.
   * The account session selects the account but is never sufficient enrollment authority. */
  issueLinkCode: (
    credential: string,
    expected: { credentialId: string; generation: number },
    context: { accountId: string; signal: AbortSignal; onStage: (stage: 'confirming_passkey') => void },
  ) => Promise<{ code: string; expiresAtMs: number } | null>
  /** Revokes a desktop device (authenticated POST /v1/devices/revoke { deviceId }). Cuts the device's
   * live + future terminal access (the cloud refuses token mint + signaling for a revoked device).
   * Resolves true on success (200 revoked), false on a non-2xx (e.g. 404 not yours / not found). */
  revokeDevice: (credential: string, deviceId: string) => Promise<boolean>
  /** Builds the transport for a target desktop (real = WebrtcBridge; fake in tests). connect() begins it.
   * `onMode` reports the S3c connection mode (direct/relay/failed) for the UI badge. */
  makeTransport: (
    targetDeviceId: string,
    onMode: (mode: ConnectionMode) => void,
    targetDevicePublicKeyB64?: string | null,
    connectDeadline?: ConnectDeadlineScope,
  ) => { transport: RemoteTransport; connect: () => Promise<void> }
  /** Terminal renderer mode: 'grid' (structured canvas, default) or 'xterm' (raw-PTY prototype). */
  rendererMode?: 'grid' | 'xterm'
  /** When the landing is served from the marketing apex, the APP origin to send Sign in/Sign up CTAs to
   * (e.g. https://app.hydraterms.com). Absent/null → run auth in-page (we ARE the app). */
  appRedirectOrigin?: string | null
  /** Durable remote-layout persistence (remote-layout API contract): the per-window pane arrangement is stored
   * server-side keyed by (account, device) so it restores cross-browser. Optional — absent in tests / plain browser
   * mode → persist/restore become no-ops (in-memory per-window layout still works, just not durable). */
  remoteLayout?: RemoteLayoutPort
  /** Called on logout / account switch so the entry layer can drop ANY account-scoped caches it holds
   * OUTSIDE the view — notably the cloud browser-device-id cache (per (account, publicKey), so it must not
   * bleed across accounts). Optional; absent in tests. */
  onAccountReset?: () => void
  /** Server-issued and server-verified initial WebAuthn registration. The context signal prevents an account
   * switch while a native authenticator sheet is open from completing against stale authority. */
  registerAccountPasskey?: (
    credential: string,
    context: {
      accountId: string
      signal: AbortSignal
      onStage: (stage: 'confirming_possession') => void
    },
  ) => Promise<{ credentialId: string; createdAtMs: number; generation: number; revokedDesktopCount: number }>
  /** Current account passkey metadata, or false when none exists. */
  hasAccountPasskey?: (credential: string) => Promise<boolean | { credentialId: string; createdAtMs?: number; generation?: number }>
  /** Current-passkey-authorized replacement. The cloud verifies both the current anchor assertion and new
   * WebAuthn credential, then atomically swaps the anchor and revokes desktops. */
  replaceAccountPasskey?: (
    credential: string,
    expected: { credentialId: string; generation: number },
    context: {
      accountId: string
      signal: AbortSignal
      onStage: (stage: 'confirming_possession') => void
    },
  ) => Promise<{ credentialId: string; createdAtMs: number; generation: number; revokedDesktopCount: number }>
  /** Page lifecycle source for reconnect wakeups. `undefined` selects window/document in a browser; explicit
   * `null` disables it (SSR/tests). */
  reconnectLifecycle?: RemoteReconnectLifecycle | null
}

/** Production and legacy authentication preparation are deliberately disjoint.
 *
 * Production performs only browser enrollment/account-ownership preparation here. Its WebRTC transport must expose
 * `currentToken()` and mint one fresh token after the signaling session exists. The constructor-token arm exists only
 * for explicit legacy/fake transports that do not implement `currentToken()`; it must never become a production
 * fallback. */
export type RemoteClientDeps = RemoteClientCommonDeps & (
  | {
      prepareConnection: (
        credential: string,
        targetDeviceId: string,
        signal?: AbortSignal,
      ) => Promise<void>
      legacyMintToken?: never
    }
  | {
      prepareConnection?: never
      legacyMintToken: (
        credential: string,
        targetDeviceId: string,
        signal?: AbortSignal,
      ) => Promise<string>
    }
)

type ConnectOptions = {
  /** Product primary action: "Open terminal" should produce a usable terminal. If the desktop reports no
   * sessions, create one on demand and auto-attach it. Plain connect/reconnect paths leave the explicit
   * "New session" choice intact. */
  createSessionIfEmpty?: { cols: number; rows: number }
  /** Internal origin for the opt-in, content-blind page-lifetime connection accumulator. */
  trigger?: ConnectionAttemptTrigger
}

export type RemoteCreationGeometrySource =
  | 'remote-terminal-slot'
  | 'remote-shell-slot'
  | 'remote-measured-cache'
  | 'legacy-fallback'

type PendingRemoteCreationGeometry = {
  cols: number
  rows: number
  /** Attempt-scoped provenance. This records where the INITIAL geometry came from; it never grants permanent
   * winsize ownership (the normal local/remote owner handoff remains authoritative after creation). */
  source: RemoteCreationGeometrySource
}

function validRemoteCreationGrid(value: { cols: number; rows: number }): boolean {
  return Number.isInteger(value.cols)
    && Number.isInteger(value.rows)
    && value.cols >= MIN_COLS
    && value.rows >= MIN_ROWS
    && value.cols <= MAX_COLS
    && value.rows <= MAX_ROWS
}

function normalizedRemoteCreationGeometry(
  value: { cols: number; rows: number },
  source: RemoteCreationGeometrySource,
): PendingRemoteCreationGeometry {
  return validRemoteCreationGrid(value)
    ? { ...value, source }
    : { ...DEFAULT_SESSION_GRID, source: 'legacy-fallback' }
}

export type RemoteCreationKind =
  | 'create-session'
  | 'split-pane'
  | 'new-pane'
  | 'revive-pane'
  | 'start-pane-session'
  | 'new-window'
  | 'project-create'

export type RemoteCreationMeasurementRequest = {
  readonly kind: RemoteCreationKind
  readonly targetPaneId: string | null
}

type RemoteDesktopMutationKind =
  | RemoteCreationKind
  | 'stash-pane'
  | 'remove-pane'
  | 'rename-pane'
  | 'rename-window'
  | 'focus-window'
  | 'close-window'
  | 'project-update'
  | 'project-delete'

type PendingRemoteCreationAttempt = {
  readonly requestId: string
  readonly kind: RemoteCreationKind
  readonly geometry: PendingRemoteCreationGeometry
  targetPaneId?: string | null
  /** Occupant of `targetPaneId` at intent time. A late creation reply may use that pane only while it still
   * holds this exact occupant (or already holds the newly-created session). This prevents an async reply from
   * overwriting a session the user deliberately placed there while the desktop mutation was in flight. */
  readonly expectedTargetSessionId?: string | null
  splitPaneId?: string | null
  desktopRevivePaneId?: string | null
  virtualStartPaneId?: string | null
}

type RemoteCreationPlacement = Omit<
  PendingRemoteCreationAttempt,
  'requestId' | 'kind' | 'geometry' | 'expectedTargetSessionId'
>

type PendingRemoteMutation = {
  readonly requestId: string
  readonly kind: RemoteDesktopMutationKind
}

/**
 * The canonical INITIAL account-scoped view — every field at its signed-out default. Used both to
 * initialize the controller and to FULLY reset in-memory state on logout / account switch, so account B can
 * never inherit account A's stale view (device/session labels, agent session lists + transcript previews,
 * directory-browser paths, pane layouts + stashed panes, active window, attached session, enrollment/revoke
 * UI, browserDeviceId, diagnostics). Device PREFERENCES (renderer mode, font size) live outside the view
 * (in storage, preserved by clearAllAccountState) and are intentionally NOT reset here.
 */
export function freshAccountView(): RemoteClientView {
  return {
    phase: 'signed_out',
    authSecondFactor: null,
    recoveryCodeUsed: false,
    accountId: null,
    devices: [],
    sessions: [],
    creatingSession: false,
    createSessionError: null,
    desktopActionMessage: null,
    sessionLabels: {},
    sessionCwds: {},
    workspaceMetadata: null,
    lastSessionListAtMs: undefined,
    agentSessions: [],
    agentSessionsListed: false,
    hiddenAgentSessions: [],
    hiddenAgentSessionsListed: false,
    agentSessionPreviews: {},
    agentSessionManageError: null,
    directoryBrowser: null,
    favoriteSessions: [],
    sessionOrder: [],
    hiddenSessions: [],
    unreadSessions: [],
    knownSessionsByDevice: {},
    deviceLabels: {},
    newSessionLabel: '',
    paneLayout: singlePane(),
    browserStashed: [],
    activeWindowId: null,
    paneLayoutsByWindow: {},
    winsizeOwner: 'local', // default: desktop owns the PTY size; browser scales. Flip via the topbar toggle.
    layoutPresetState: { presets: [] },
    selectedDevice: null,
    attachedSession: null,
    terminalAcquisition: null,
    lastOpenedSessionId: null,
    recentSessionEnded: false,
    connectionMode: 'unknown',
    diagnostics: defaultDiagnostics(),
    agentBuildGit: null,
    desktopAccess: UNKNOWN_DESKTOP_ACCESS,
    authState: 'idle',
    browserDeviceId: null,
    error: null,
    enroll: { issuing: false, code: null, expiresAtMs: null, error: null },
    revoke: { confirmingDeviceId: null, pendingDeviceId: null, error: null },
    accountDeletion: { confirming: false, deleting: false, error: null, notice: null, identityDeletionPending: false },
    passkey: { registering: false, registered: false, error: null, status: 'loading' },
  }
}

export class RemoteClientController {
  private view: RemoteClientView = freshAccountView()
  private listeners = new Set<(v: RemoteClientView) => void>()
  private session: RemoteSession | null = null
  /** Highest live-sync push epoch APPLIED. Guards ordering: a workspace_update with epoch <= this is ignored (a late
   * re-push can't clobber a newer state). Reset per connection when the session_list baseline re-establishes. */
  private lastAppliedWorkspaceEpoch = 0
  private multiAttach = new MultiAttachManager()
  private multiPaneTerminal = new MultiPaneTerminalSession()
  private multiPaneOutputEnabled = false
  /** Sessions with a baseline-recovery re-attach in flight — dedupes so a burst of un-appliable damage frames
   * sends ONE attach; an entry clears when its attach_ok lands (see onAttached). */
  private baselineReattachPending = new Set<string>()
  /** The viewport last passed to attach(); baseline-recovery re-attaches reuse it (same screen, same size). */
  private lastAttachSize = { cols: 80, rows: 24 }
  /** True once the APP layer has actually measured this browser's viewport (resize()/resizePane() ran). Until
   * then `lastAttachSize` is just the 80×24 default and must NOT override an explicit caller size — a sidebar
   * click's fallback grid is still better than an unmeasured default. */
  private viewportMeasured = false
  private measureRemoteCreationGeometry:
    ((request: RemoteCreationMeasurementRequest) => {
      cols: number
      rows: number
      source: 'remote-terminal-slot' | 'remote-shell-slot'
    } | null)
    | null = null
  private winsizeRefreshTimer: ReturnType<typeof setTimeout> | null = null
  private winsizeRefreshAfterAttach = new Set<string>()
  private winsizeRefreshAfterMaterialize = new Set<string>()
  private winsizeRefreshFallbackTimers = new Map<string, ReturnType<typeof setTimeout>>()
  /** Exact app-measured viewport for each attached pane. A single global `lastAttachSize` is still the legacy
   * fallback for new/recovery attaches, but it must never drive a delayed multi-pane settle: the active pane can
   * change while the ownership handoff is propagating. */
  private measuredWinsizes = new Map<string, { cols: number; rows: number }>()
  /** One independent one-shot ownership-settle timer per session. */
  private winsizeSettleTimers = new Map<string, ReturnType<typeof setTimeout>>()

  /** Sessions this browser learned exist from an AUTHORITATIVE creation reply (split_pane_ok /
   * session_created / project_edit_ok seed / new_window_ok / revive_pane_ok), keyed to when we learned it.
   * A session_list / workspace_update SNAPSHOT computed before the desktop committed the creation (or while
   * the agent's session cache lagged the reservation) must not ERASE them: onSessions would replace
   * view.sessions, the existence reconcile's metadata-lag safety (which requires sessions.includes) would
   * drop the just-placed pane, and every later attach path (sessions.includes guards) would go dead until a
   * page refresh — the live "remote split creates the pane but it never appears/streams" trace. Entries
   * expire after CREATED_SESSION_GRACE_MS, or as soon as a list/push finally names the session. */
  private recentlyCreatedSessions = new Map<string, number>()
  /** One-shot automatic recovery marker: sessions whose attach got attach_ok but produced NO terminal data
   * before the attach watchdog fired, and were re-attached automatically. Cleared when data materializes. */
  private attachAutoRetried = new Set<string>()
  /** Sessions that have produced a first valid Grid/raw frame on this transport. */
  private hydratedSessions = new Set<string>()
  private materializedRows = new Map<string, number>()
  /** Sessions whose one bounded active-pane history warm has replied or timed out. Background panes are never
   * warmed; when one becomes active it enters this same foreground gate. */
  private historyWarmSettled = new Set<string>()
  private activeHistoryWarm: {
    sessionId: string
    offset: number
    inactivityTimer: ReturnType<typeof setTimeout>
    absoluteTimer: ReturnType<typeof setTimeout>
  } | null = null
  /** Reserved state for bounded cleanup of an already-started legacy background attach. The shipping policy does
   * not start speculative sibling attaches; siblings are acquired only when focused. */
  private backgroundAttachInFlight: string | null = null
  /** A background pane gets one bounded hydration attempt per connection. If it acknowledges attach but never
   * materializes a Grid, skip it for the rest of the automatic queue so optional history and later siblings
   * cannot be starved by an attach/detach loop. Explicitly focusing the pane may still retry it. */
  private backgroundHydrationSkipped = new Set<string>()
  private paneHydrationTimer: ReturnType<typeof setTimeout> | null = null
  /** Foreground scrollback/prefetch request bounds. Valid chunks refresh only that request's inactivity bound;
   * a separate absolute bound prevents an endless dribble from holding the active-history gate forever. */
  private priorityScrollback = new Map<string, {
    sessionId: string
    owner: object
    inactivityTimer: ReturnType<typeof setTimeout>
    absoluteTimer: ReturnType<typeof setTimeout>
  }>()
  /** One structured-history response may be in flight per visible pane. Trackpad bursts only replace
   * `latestOffset`; a completed stale page becomes cache-fill and then the newest uncached target is sent. */
  private paneScrollbackInFlight = new Map<string, {
    requestedOffset: number
    latestOffset: number
    count: number
    sessionTraceOwned: boolean
    timeoutTimer: ReturnType<typeof setTimeout>
  }>()
  /** Focus moved to an attach still in flight. Reassert viewed ownership after attach_ok as well as in ordered
   * wire order immediately after attach_session. */
  private pendingOwnershipReassert = new Set<string>()
  private lastViewedSessionId: string | null = null

  /** Record a session named by an authoritative creation reply (see recentlyCreatedSessions). */
  private noteCreatedSession(sessionId: string): void {
    this.recentlyCreatedSessions.set(sessionId, Date.now())
    // The correlated success is already desktop-authoritative. Surface the durable session immediately instead
    // of depending on the follow-up inventory reply: that reply can be delayed/lost, and a disappeared or rebound
    // placement target intentionally does not attach the session anywhere. A later post-commit push/list remains
    // authoritative and may remove it if the desktop deleted it immediately after creation.
    if (!this.view.sessions.includes(sessionId)) {
      this.update({ sessions: [...this.view.sessions, sessionId] })
    }
  }

  /** A workspace_update PUSH is generated agent-side AFTER the DB commit that triggered it, and rides the
   * ordered channel BEHIND the creation's ok-reply — so its session list is post-commit truth, not a racing
   * snapshot. Entries it names are now known; entries it omits were authoritatively deleted (e.g. the project
   * was killed right after creating). Either way the guard entry is settled — drop it, so a later stale
   * REPLY can't resurrect a deleted session (R14). */
  private settleRecentlyCreatedFromPush(): void {
    this.recentlyCreatedSessions.clear()
  }

  /** Union an incoming session-list REPLY snapshot with the not-yet-expired recently-created sessions, so a
   * stale snapshot (requested before the desktop committed the creation, or served from the agent's lagging
   * session cache) can't erase a session the desktop's own ok-reply just named. Prunes entries the list now
   * knows (normal handoff) and entries past the grace window (the creation really did die). */
  private mergeRecentlyCreated(sessions: string[]): string[] {
    if (this.recentlyCreatedSessions.size === 0) return sessions
    const now = Date.now()
    const merged = [...sessions]
    for (const [sid, ts] of [...this.recentlyCreatedSessions]) {
      if (sessions.includes(sid) || now - ts > CREATED_SESSION_GRACE_MS) {
        this.recentlyCreatedSessions.delete(sid)
        continue
      }
      merged.push(sid)
    }
    return merged
  }

  /** Release a session's WIRE attach (the agent-side channel) while KEEPING its pane bank state + renderer,
   * then attach fresh. The agent REFUSES attach_session for a session it still holds a channel for
   * (`already_attached`, remote_bridge.rs) — so every automatic recovery re-attach MUST detach first. The
   * old bare re-send was permanently refused: the daemon never resent a grid, baselineReattachPending never
   * cleared, and the pane stayed blank until a page refresh. */
  private reattachSessionFresh(sessionId: string): void {
    const channel = this.multiAttach.channelForSession(sessionId)
    if (channel !== null) {
      // The old channel is a proof boundary: no request correlated to it may survive into the new channel. This is
      // especially important on TURN, where the first winsize reattach can beat the initial history reply.
      this.retirePaneScrollbackFlow(sessionId, true)
      this.session?.detachSession(sessionId)
      this.multiAttach.detachSession(sessionId)
      this.multiPaneTerminal.releaseChannel(channel) // keep bank state/renderer; the new attach re-binds it
    } else if (this.reclaimPendingAttach(sessionId)) {
      // A request is already awaiting attach_ok. There is no proven channel to detach and a second attach is
      // guaranteed to race it, so keep waiting on the original ownership transfer.
      return
    }
    this.armAttachWatchdog(sessionId)
    this.scheduleWinsizeSettleRepush(sessionId)
    this.sendAttachRequest(sessionId, this.lastAttachSize.cols, this.lastAttachSize.rows)
  }

  /** Retire a departed scalar channel without immediately streaming its replacement Grid. Foreground acquisition
   * must stay ahead of background work on TURN; if the pane is still placed it will be reacquired on focus (and a
   * future proven-idle prefetch tier may do so later). */
  private releaseSessionForOnDemandReattach(sessionId: string): void {
    const channel = this.multiAttach.channelForSession(sessionId)
    if (channel === null) return
    this.retirePaneScrollbackFlow(sessionId, true)
    this.session?.detachSession(sessionId)
    this.multiAttach.detachSession(sessionId)
    this.multiPaneTerminal.releaseChannel(channel)
    this.clearAttachLifecycle(sessionId)
  }

  private abandonPendingAttachOnDeparture(sessionId: string): void {
    if (!this.pendingWireAttaches.has(sessionId)) return
    this.abandonedPendingAttaches.add(sessionId)
    this.clearAttachWatchdog(sessionId)
    this.clearPaneSwitchWatchdog(sessionId)
    this.pendingOwnershipReassert.delete(sessionId)
    if (this.backgroundAttachInFlight === sessionId) this.backgroundAttachInFlight = null
  }

  private retirePaneScrollbackFlow(sessionId: string, prepareForFreshGrid: boolean): void {
    const flow = this.paneScrollbackInFlight.get(sessionId)
    if (flow) {
      clearTimeout(flow.timeoutTimer)
      this.paneScrollbackInFlight.delete(sessionId)
      if (flow.sessionTraceOwned) {
        this.session?.settleExternallyRoutedScrollback(sessionId, flow.requestedOffset)
      }
    }
    for (const [key, pending] of [...this.priorityScrollback]) {
      if (!key.startsWith(`${sessionId}\u0000`)) continue
      clearTimeout(pending.inactivityTimer)
      clearTimeout(pending.absoluteTimer)
      this.priorityScrollback.delete(key)
    }
    if (this.activeHistoryWarm?.sessionId === sessionId) {
      clearTimeout(this.activeHistoryWarm.inactivityTimer)
      clearTimeout(this.activeHistoryWarm.absoluteTimer)
      this.activeHistoryWarm = null
    }
    if (prepareForFreshGrid) {
      // A fresh channel/geometry has no materialized baseline yet. Clear the hydration proof before any queued
      // zero-delay hydration task can run; only the replacement Grid may make this session warm-eligible again.
      this.hydratedSessions.delete(sessionId)
      this.materializedRows.delete(sessionId)
      this.historyWarmSettled.delete(sessionId)
      this.multiPaneTerminal.resetScrollbackForReattach(sessionId)
    }
  }

  private cancelWinsizeRefresh(): void {
    if (this.winsizeRefreshTimer) clearTimeout(this.winsizeRefreshTimer)
    this.winsizeRefreshTimer = null
  }

  private refreshActiveSessionAfterWinsizeClaim(): void {
    this.cancelWinsizeRefresh()
    const sessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    if (!sessionId) return
    this.refreshSessionAfterWinsizeClaim(sessionId)
  }

  private refreshSessionAfterWinsizeClaim(sessionId: string): void {
    this.cancelWinsizeRefresh()
    if (activeLeaf(this.view.paneLayout).sessionId !== sessionId) return
    if (this.attachWatchdogs.has(sessionId) && this.multiAttach.channelForSession(sessionId) === null) {
      this.winsizeRefreshAfterAttach.add(sessionId)
      return
    }
    const connectionGen = this.connectionGeneration
    this.winsizeRefreshTimer = setTimeout(() => {
      this.winsizeRefreshTimer = null
      if (this.connectionGeneration !== connectionGen) return
      if (this.intentionalDetachGeneration === connectionGen) return
      if (this.view.winsizeOwner !== 'remote') return
      if (activeLeaf(this.view.paneLayout).sessionId !== sessionId) return
      if (!leaves(this.view.paneLayout.root).some((leaf) => leaf.sessionId === sessionId)) return
      if (this.multiAttach.channelForSession(sessionId) === null) return
      this.reattachSessionFresh(sessionId)
    }, 180)
    this.winsizeRefreshTimer.unref?.()
  }

  private refreshSessionAfterFirstWinsizeFrame(sessionId: string): void {
    this.winsizeRefreshAfterMaterialize.add(sessionId)
    const existing = this.winsizeRefreshFallbackTimers.get(sessionId)
    if (existing) clearTimeout(existing)
    const timer = setTimeout(() => {
      this.winsizeRefreshFallbackTimers.delete(sessionId)
      if (!this.winsizeRefreshAfterMaterialize.delete(sessionId)) return
      this.refreshSessionAfterWinsizeClaim(sessionId)
    }, 900)
    timer.unref?.()
    this.winsizeRefreshFallbackTimers.set(sessionId, timer)
  }

  private pushRemoteSizeAfterPaint(): void {
    setTimeout(() => {
      if (this.view.winsizeOwner !== 'remote') return
      this.pushActivePaneResize()
    }, 0)
    setTimeout(() => {
      if (this.view.winsizeOwner !== 'remote') return
      this.pushActivePaneResize()
    }, 120)
  }

  /** WINSIZE SETTLE: the agent propagates per-pane remote ownership to the desktop through the
   * `winsize-owner-sessions` file, written by a ~2s background tick (hydra-agent remote_peer). Every size this
   * browser pushes in the first ~2s after attach can be clobbered by the desktop's local refit. Reassert each
   * session's OWN already-measured size once after that window. Timer and measurement are both session-keyed so
   * focus changes (or a later measurement of a differently-sized sibling) cannot cross-apply geometry. */
  private scheduleWinsizeSettleRepush(sessionId: string): void {
    this.cancelWinsizeSettleRepush(sessionId)
    const timer = setTimeout(() => {
      this.winsizeSettleTimers.delete(sessionId)
      if (this.view.winsizeOwner !== 'remote') return // desktop reclaimed (or user chose Local) — don't fight it
      const measured = this.measuredWinsizes.get(sessionId)
      if (!measured) return // never reassert an unmeasured 80×24 fallback over a real desktop size
      if (!leaves(this.view.paneLayout.root).some((leaf) => leaf.sessionId === sessionId)) return
      if (this.multiAttach.channelForSession(sessionId) === null) return
      this.applyResizePane(sessionId, measured.cols, measured.rows)
    }, WINSIZE_SETTLE_REPUSH_MS)
    timer.unref?.()
    this.winsizeSettleTimers.set(sessionId, timer)
  }

  private cancelWinsizeSettleRepush(sessionId: string, forgetMeasurement = false): void {
    const timer = this.winsizeSettleTimers.get(sessionId)
    if (timer) clearTimeout(timer)
    this.winsizeSettleTimers.delete(sessionId)
    if (forgetMeasurement) this.measuredWinsizes.delete(sessionId)
  }

  private cancelAllWinsizeSettleRepushes(forgetMeasurements = false): void {
    for (const timer of this.winsizeSettleTimers.values()) clearTimeout(timer)
    this.winsizeSettleTimers.clear()
    if (forgetMeasurements) this.measuredWinsizes.clear()
  }

  private schedulePlacedWinsizeSettleRepushes(): void {
    for (const leaf of leaves(this.view.paneLayout.root)) {
      if (leaf.sessionId) this.scheduleWinsizeSettleRepush(leaf.sessionId)
    }
  }

  /** Terminal data materialized for a session — clear the attach watchdog AND its one-shot auto-retry marker
   * (a later stall gets a fresh automatic recovery). */
  private noteAttachMaterialized(sessionId: string, rows?: number): void {
    const firstMaterialization = !this.hydratedSessions.has(sessionId)
    this.hydratedSessions.add(sessionId)
    this.backgroundHydrationSkipped.delete(sessionId)
    if (rows && rows > 0) this.materializedRows.set(sessionId, rows)
    this.clearPaneSwitchWatchdog(sessionId)
    this.clearAttachWatchdog(sessionId)
    this.attachAutoRetried.delete(sessionId)
    if (this.backgroundAttachInFlight === sessionId) this.backgroundAttachInFlight = null
    if (this.winsizeRefreshAfterMaterialize.delete(sessionId)) {
      const fallback = this.winsizeRefreshFallbackTimers.get(sessionId)
      if (fallback) clearTimeout(fallback)
      this.winsizeRefreshFallbackTimers.delete(sessionId)
      this.refreshSessionAfterWinsizeClaim(sessionId)
    }
    if (firstMaterialization || sessionId === activeLeaf(this.view.paneLayout).sessionId) {
      this.schedulePaneHydration()
    }
  }

  private scrollbackKey(sessionId: string, offset: number): string {
    return `${sessionId}\u0000${offset}`
  }

  private notePriorityScrollbackRequest(sessionId: string, offset: number): void {
    if (sessionId !== activeLeaf(this.view.paneLayout).sessionId) return
    const key = this.scrollbackKey(sessionId, offset)
    const existing = this.priorityScrollback.get(key)
    if (existing) {
      clearTimeout(existing.inactivityTimer)
      clearTimeout(existing.absoluteTimer)
    }
    const owner = {}
    const expire = () => {
      const current = this.priorityScrollback.get(key)
      if (!current || current.owner !== owner) return
      clearTimeout(current.inactivityTimer)
      clearTimeout(current.absoluteTimer)
      this.priorityScrollback.delete(key)
      this.schedulePaneHydration()
    }
    const inactivityTimer = setTimeout(expire, INITIAL_HISTORY_WARM_INACTIVITY_MS)
    const absoluteTimer = setTimeout(expire, INITIAL_HISTORY_WARM_ABSOLUTE_MS)
    inactivityTimer.unref?.()
    absoluteTimer.unref?.()
    this.priorityScrollback.set(key, { sessionId, owner, inactivityTimer, absoluteTimer })
  }

  private noteScrollbackWireRequest(
    sessionId: string,
    offset: number,
    count: number,
    sessionTraceOwned: boolean,
  ): void {
    this.notePriorityScrollbackRequest(sessionId, offset)
    const existing = this.paneScrollbackInFlight.get(sessionId)
    if (existing) {
      // sendPaneScrollbackRequest pre-registers its owner so a synchronous rejected send can clean it up. The
      // post-send RemoteSession callback confirms that same request; any different offset here proves two requests
      // escaped the one-per-pane gate and the connection must be retired rather than guessed at.
      if (existing.requestedOffset !== offset) {
        this.session?.failConnection()
        return
      }
      existing.count = count
      existing.sessionTraceOwned ||= sessionTraceOwned
      return
    }
    this.trackPaneScrollbackRequest(sessionId, offset, count, sessionTraceOwned)
  }

  private noteScrollbackReply(sessionId: string, offset: number, accepted = true): void {
    const flow = this.paneScrollbackInFlight.get(sessionId)
    // Every legitimate scalar or bank request registers this controller owner after a successful send. A stray
    // same-session reply with no owner must not finish the current warm/priority gate or mutate hydration state.
    if (!flow) return
    const requestedOffset = flow?.requestedOffset ?? offset
    if (flow) {
      clearTimeout(flow.timeoutTimer)
      this.paneScrollbackInFlight.delete(sessionId)
      // Safe whether RemoteSession consumed the reply itself or ChannelTerminalBank intercepted it. This stable
      // ownership handoff closes the false→true pane-mount race without guessing which route will own the reply.
      if (flow.sessionTraceOwned) {
        this.session?.settleExternallyRoutedScrollback(sessionId, requestedOffset)
      }
    }
    const key = this.scrollbackKey(sessionId, requestedOffset)
    const pending = this.priorityScrollback.get(key)
    if (pending) {
      clearTimeout(pending.inactivityTimer)
      clearTimeout(pending.absoluteTimer)
    }
    this.priorityScrollback.delete(key)
    if (!accepted) {
      // A generation-raced page is unusable. Returning this pane to its already-held live grid is a bounded local
      // recovery: never freeze at a history offset with no complete page, and never spin retries against a moving
      // generation. A later deliberate wheel gesture may request against the fresh Grid.
      this.multiPaneTerminal.jumpToLive(sessionId)
      if (this.activeHistoryWarm?.sessionId === sessionId) {
        this.finishActiveHistoryWarm(sessionId, 'not_available')
      }
      this.schedulePaneHydration()
      return
    }
    if (this.activeHistoryWarm?.sessionId === sessionId) {
      this.finishActiveHistoryWarm(sessionId, 'reply')
    }
    if (
      flow
      && this.multiPaneOutputEnabled
      && this.multiPaneTerminal.hasSession(sessionId)
    ) {
      // Only the bank owns a latest per-pane target while the pane route is currently active. A request can be
      // issued in the bank route and complete after the UI flips back to the single-session surface; in that case
      // RemoteSession consumed the reply and the bank's old offset must not resurrect the completed request.
      const latestOffset = this.multiPaneTerminal.scrollbackRequestOffset(sessionId)
      if (latestOffset !== null) {
        const bounds = this.multiPaneTerminal.gridBounds(sessionId)
        const count = this.session?.scrollbackRequestCount(bounds?.rows ?? 24, bounds?.cols ?? 80)
          ?? flow.count
        this.sendPaneScrollbackRequest(sessionId, latestOffset, count)
      }
    }
    this.schedulePaneHydration()
  }

  private sendPaneScrollbackRequest(sessionId: string, offset: number, count: number): void {
    const current = this.paneScrollbackInFlight.get(sessionId)
    if (current) {
      current.latestOffset = offset
      current.count = count
      return
    }
    const session = this.session
    if (!session?.isAuthenticated) return
    const flow = this.trackPaneScrollbackRequest(sessionId, offset, count, false)
    if (!session.requestScrollbackOn(sessionId, offset, count)) {
      clearTimeout(flow.timeoutTimer)
      if (this.paneScrollbackInFlight.get(sessionId) === flow) {
        this.paneScrollbackInFlight.delete(sessionId)
      }
    }
  }

  private trackPaneScrollbackRequest(
    sessionId: string,
    offset: number,
    count: number,
    sessionTraceOwned = false,
  ): {
    requestedOffset: number
    latestOffset: number
    count: number
    sessionTraceOwned: boolean
    timeoutTimer: ReturnType<typeof setTimeout>
  } {
    let flow!: {
      requestedOffset: number
      latestOffset: number
      count: number
      sessionTraceOwned: boolean
      timeoutTimer: ReturnType<typeof setTimeout>
    }
    const timeoutTimer = setTimeout(() => {
      if (this.paneScrollbackInFlight.get(sessionId) !== flow) return
      this.paneScrollbackInFlight.delete(sessionId)
      this.session?.failConnection()
    }, SCROLLBACK_RESPONSE_TIMEOUT_MS)
    timeoutTimer.unref?.()
    flow = {
      requestedOffset: offset,
      latestOffset: offset,
      count,
      sessionTraceOwned,
      timeoutTimer,
    }
    this.paneScrollbackInFlight.set(sessionId, flow)
    return flow
  }

  private startActiveHistoryWarm(sessionId: string): void {
    if (this.historyWarmSettled.has(sessionId) || this.activeHistoryWarm) return
    if (sessionId !== activeLeaf(this.view.paneLayout).sessionId) return
    if (!this.hydratedSessions.has(sessionId)) return
    if (this.rendererMode === 'xterm') {
      this.historyWarmSettled.add(sessionId)
      recordInitialHistoryCompletion(sessionId, true, 'not_applicable')
      this.schedulePaneHydration()
      return
    }
    const bounds = this.multiPaneTerminal.gridBounds(sessionId)
    const rows = this.materializedRows.get(sessionId)
      ?? bounds?.rows
      ?? this.measuredWinsizes.get(sessionId)?.rows
      ?? this.lastAttachSize.rows
    const cols = bounds?.cols
      ?? this.measuredWinsizes.get(sessionId)?.cols
      ?? this.lastAttachSize.cols
    const existing = this.paneScrollbackInFlight.get(sessionId)
    let offset: number
    if (existing) {
      // A physical scroll can win the event-loop turn immediately after the first Grid. Its owned visible page is
      // already a valid first-history warm; do not add a second large request behind it.
      offset = existing.requestedOffset
    } else {
      const requested = this.session?.requestInitialScrollbackWarm(sessionId, rows, cols)
      if (requested === null || requested === undefined) {
        this.historyWarmSettled.add(sessionId)
        recordInitialHistoryCompletion(sessionId, true, 'not_available')
        this.schedulePaneHydration()
        return
      }
      offset = requested
      // requestInitialScrollbackWarm's post-send callback registered the stable controller owner synchronously.
      if (!this.paneScrollbackInFlight.has(sessionId)) {
        this.session?.failConnection()
        return
      }
    }
    const inactivityTimer = setTimeout(
      () => this.finishActiveHistoryWarm(sessionId, 'inactivity_timeout'),
      INITIAL_HISTORY_WARM_INACTIVITY_MS,
    )
    const absoluteTimer = setTimeout(
      () => this.finishActiveHistoryWarm(sessionId, 'absolute_timeout'),
      INITIAL_HISTORY_WARM_ABSOLUTE_MS,
    )
    inactivityTimer.unref?.()
    absoluteTimer.unref?.()
    this.activeHistoryWarm = { sessionId, offset, inactivityTimer, absoluteTimer }
  }

  private finishActiveHistoryWarm(sessionId: string, result: InitialHistoryResult): void {
    const warm = this.activeHistoryWarm
    if (!warm || warm.sessionId !== sessionId) return
    clearTimeout(warm.inactivityTimer)
    clearTimeout(warm.absoluteTimer)
    this.activeHistoryWarm = null
    this.historyWarmSettled.add(sessionId)
    recordInitialHistoryCompletion(
      sessionId,
      sessionId === activeLeaf(this.view.paneLayout).sessionId,
      result,
    )
    this.schedulePaneHydration()
  }

  private cancelPaneHydrationState(): void {
    if (this.paneHydrationTimer) clearTimeout(this.paneHydrationTimer)
    this.paneHydrationTimer = null
    if (this.activeHistoryWarm) {
      clearTimeout(this.activeHistoryWarm.inactivityTimer)
      clearTimeout(this.activeHistoryWarm.absoluteTimer)
    }
    this.activeHistoryWarm = null
    for (const pending of this.priorityScrollback.values()) {
      clearTimeout(pending.inactivityTimer)
      clearTimeout(pending.absoluteTimer)
    }
    this.priorityScrollback.clear()
    for (const flow of this.paneScrollbackInFlight.values()) clearTimeout(flow.timeoutTimer)
    this.paneScrollbackInFlight.clear()
    this.hydratedSessions.clear()
    this.materializedRows.clear()
    this.historyWarmSettled.clear()
    this.backgroundAttachInFlight = null
    this.backgroundHydrationSkipped.clear()
    this.pendingOwnershipReassert.clear()
    this.lastViewedSessionId = null
  }

  private schedulePaneHydration(): void {
    if (this.paneHydrationTimer) return
    const connectionGen = this.connectionGeneration
    const timer = setTimeout(() => {
      if (this.paneHydrationTimer !== timer) return
      this.paneHydrationTimer = null
      if (this.connectionGeneration !== connectionGen) return
      this.advancePaneHydration()
    }, 0)
    timer.unref?.()
    this.paneHydrationTimer = timer
  }

  /** Once the authoritative session list has settled, either begin the terminal's active-first queue or, when
   * there is honestly no live active pane, release the deferred provider inventory immediately. */
  private scheduleStartupHydrationOrHistory(): void {
    // Create-on-empty has already put create_session on the wire. Do not queue optional history behind it: the
    // creation reply's foreground attach must remain the next control operation.
    if (this.view.creatingSession) return
    const active = activeLeaf(this.view.paneLayout).sessionId
    if (!active || !this.view.sessions.includes(active)) {
      this.flushDeferredAgentSessionRefresh()
      return
    }
    this.schedulePaneHydration()
  }

  private advancePaneHydration(): void {
    if (this.intentionalDetachGeneration === this.connectionGeneration || !this.session?.isAuthenticated) return
    const active = activeLeaf(this.view.paneLayout).sessionId
    if (!active || !this.view.sessions.includes(active)) {
      // No terminal can occupy the foreground lane (an honestly empty desktop / all sessions hidden). History is
      // the useful product surface in this case, so do not wait for a Grid that cannot arrive.
      this.flushDeferredAgentSessionRefresh()
      return
    }
    if (this.multiAttach.channelForSession(active) === null && !this.pendingWireAttaches.has(active)) {
      this.ensureForegroundAttach(active)
      return
    }
    if (!this.hydratedSessions.has(active)) return
    if (!this.historyWarmSettled.has(active)) {
      this.startActiveHistoryWarm(active)
      return
    }
    // Ignore bounded foreground requests from a pane that ceased to be active; their replies can still fill
    // that pane's cache but must not stall the newly focused pane's queue.
    for (const [key, pending] of [...this.priorityScrollback]) {
      if (key.startsWith(`${active}\u0000`)) continue
      clearTimeout(pending.inactivityTimer)
      clearTimeout(pending.absoluteTimer)
      this.priorityScrollback.delete(key)
    }
    if (this.priorityScrollback.size > 0 || this.backgroundAttachInFlight) return
    // Safe rollout default: sibling panes are acquired on focus and then remain cache-hot. Do not speculate from
    // an inferred "idle" period—active output can resume between any two event-loop turns, especially on TURN,
    // and a background full Grid would then head-of-line block the visible pane. A future idle-prefetch tier must
    // bring an explicit quiet proof plus immediate preemption before it may replace this on-demand policy.
    this.flushDeferredAgentSessionRefresh()
  }

  private ensureForegroundAttach(sessionId: string): void {
    if (!this.view.sessions.includes(sessionId)) return
    const size = this.measuredWinsizes.get(sessionId) ?? this.lastAttachSize
    const channel = this.multiAttach.channelForSession(sessionId)
    this.pendingOwnershipReassert.add(sessionId)
    if (channel !== null) {
      this.session?.setActiveAttach(sessionId, channel)
      this.session?.resizeSession(sessionId, size.cols, size.rows, true)
      this.pendingOwnershipReassert.delete(sessionId)
      return
    }
    if (!this.pendingWireAttaches.has(sessionId) && !this.attachWatchdogs.has(sessionId)) {
      this.armAttachWatchdog(sessionId)
      this.scheduleWinsizeSettleRepush(sessionId)
      this.sendAttachRequest(sessionId, size.cols, size.rows)
    } else {
      this.reclaimPendingAttach(sessionId)
    }
    // Ordered behind attach_session (or an already-sent in-flight attach). Reassert once more at attach_ok.
    this.session?.resizeSession(sessionId, size.cols, size.rows, true)
  }

  /** A validated chunk arrived for an attached session, but no complete daemon line has materialized yet.
   * Measure inactivity rather than total transfer time, and never resurrect a watchdog after Grid/raw output. */
  private noteAttachProgress(sessionId: string): void {
    const warm = this.activeHistoryWarm
    if (warm?.sessionId === sessionId) {
      clearTimeout(warm.inactivityTimer)
      warm.inactivityTimer = setTimeout(
        () => this.finishActiveHistoryWarm(sessionId, 'inactivity_timeout'),
        INITIAL_HISTORY_WARM_INACTIVITY_MS,
      )
      warm.inactivityTimer.unref?.()
    }
    // A user-requested active-pane history page has the same priority as the initial warm. Progress from that
    // exact session refreshes inactivity, but the fixed absolute timer remains untouched; chunks from background
    // channels cannot prolong this foreground gate.
    for (const [key, pending] of this.priorityScrollback) {
      if (pending.sessionId !== sessionId) continue
      clearTimeout(pending.inactivityTimer)
      const owner = pending.owner
      const timer = setTimeout(() => {
        const current = this.priorityScrollback.get(key)
        if (!current || current.owner !== owner) return
        clearTimeout(current.absoluteTimer)
        this.priorityScrollback.delete(key)
        this.schedulePaneHydration()
      }, INITIAL_HISTORY_WARM_INACTIVITY_MS)
      timer.unref?.()
      pending.inactivityTimer = timer
    }
    if (!this.attachWatchdogs.has(sessionId)) return
    this.armAttachWatchdog(sessionId)
  }

  /** Retire channel-scoped state when the terminal transport is no longer authorized/live. Pane layout and
   * resume hints deliberately survive for reconnect, but old bindings, banks, chunks, and attach timers cannot. */
  private retireTerminalTransportState(): void {
    const sessions = new Set([
      ...this.multiAttach.bindings().map((binding) => binding.sessionId),
      ...this.attachWatchdogs.keys(),
      ...this.pendingWireAttaches,
    ])
    for (const sessionId of sessions) this.clearAttachLifecycle(sessionId)
    for (const timer of this.winsizeRefreshFallbackTimers.values()) clearTimeout(timer)
    this.winsizeRefreshFallbackTimers.clear()
    this.winsizeRefreshAfterAttach.clear()
    this.winsizeRefreshAfterMaterialize.clear()
    this.baselineReattachPending.clear()
    this.attachAutoRetried.clear()
    this.pendingWireAttaches.clear()
    this.abandonedPendingAttaches.clear()
    this.cancelPaneHydrationState()
    this.deferredAgentSessionRefresh = false
    this.deferredAgentSessionFolderRefreshes.clear()
    this.multiAttach.clear()
    this.multiPaneOutputEnabled = false
    this.multiPaneTerminal = new MultiPaneTerminalSession()
    resetTransportMetrics()
    this.update({
      diagnostics: defaultDiagnostics(),
      agentBuildGit: null,
      desktopAccess: UNKNOWN_DESKTOP_ACCESS,
      desktopActionMessage: this.view.desktopActionMessage === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
        ? null
        : this.view.desktopActionMessage,
    })
  }

  /** Force a fresh daemon attach for a session whose pane bank lost (or never had) its baseline grid — the only
   * way to make the daemon resend a full grid. Deduped per session until the attach_ok arrives. */
  private reattachForBaseline(sessionId: string): void {
    if (this.baselineReattachPending.has(sessionId)) return
    this.baselineReattachPending.add(sessionId)
    this.reattachSessionFresh(sessionId)
  }
  private layoutPresetIdSeq = 0

  // Reconnect/resume state. The PTY survives on the Mac (daemon owns it); on a drop we re-run connectTo
  // with bounded backoff and re-attach the SAME session id (a no-op respawn on the daemon → no duplicate).
  private resumeSessionId: string | null = null // the session to auto-reattach after reconnect
  private traceId: string = mintTraceId() // correlation id for the CURRENT connect/sync cycle; re-minted per connect
  private readonly pendingRemoteCreations = new Map<string, PendingRemoteCreationAttempt>()
  private readonly creationRequestCounts = new Map<string, number>()
  /** The one desktop-authoritative operation that owns `creatingSession` and its watchdog. Every reply must
   * consume this exact request id + kind before it may clear the busy state; a late reply from a timed-out
   * operation can therefore never disarm a newer creation. */
  private pendingRemoteMutation: PendingRemoteMutation | null = null
  private pendingAgentPreviewRequests = new Map<string, string>()
  private pendingAgentSessionListCwds = new Map<string, string | undefined>()
  private pendingAgentSessionListAgents = new Map<string, RemoteAgentKind | undefined>()
  /** The broad provider-history inventory is optional startup work. Keep it off the ordered control channel until
   * the focused terminal (and any already-placed siblings) have materialized, otherwise a slow local provider scan
   * can head-of-line block the first attach. Explicit folder/history actions remain immediate after this gate. */
  private deferredAgentSessionRefresh = false
  /** Project/editor forms can mount during the session-list render and request the same optional inventory for
   * several folders before the terminal attach timer runs. Coalesce those scopes behind the same startup gate;
   * once the gate opens, later user-initiated folder requests remain immediate. */
  private deferredAgentSessionFolderRefreshes = new Set<string>()
  private pendingAgentSessionManageCwds = new Map<string, string | undefined>()
  private pendingAgentSessionManageAgents = new Map<string, RemoteAgentKind>()
  private pendingHiddenListRequests = new Set<string>()
  private createSessionIfEmpty: ({ targetDeviceId: string } & NonNullable<ConnectOptions['createSessionIfEmpty']>) | null = null
  private reconnectAttempt = 0
  /** Monotonic owner for connection attempts and their transport callbacks. A newer explicit connect, reconnect,
   * intentional leave, or sign-out makes every late event from the prior peer inert. */
  private connectionGeneration = 0
  /** Per-controller attach correlation. Several panes may legitimately rebind concurrently; sharing the old
   * literal `attach` id let one attach_ok erase another request's gzip negotiation proof. */
  private attachRequestSeq = 0
  /** Content-blind observer for the current connection generation. It owns no account/device/session identifier
   * and is a no-op unless the page explicitly enabled `?metrics=1`. */
  private activeConnectionMetric: {
    generation: number
    recorder: ConnectionAttemptMetricRecorder
  } | null = null
  /** The connection generation in which the user deliberately left the terminal surface via detach(). Pane
   * bindings intentionally survive that navigation, but inventory/workspace refreshes in the SAME connection
   * must not interpret those bindings as reconnect work and silently attach again. A fresh connection has a new
   * generation (so genuine reconnect resume still works); an explicit attach clears the marker immediately. */
  private intentionalDetachGeneration: number | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private deviceRefreshTimer: ReturnType<typeof setInterval> | null = null // polls /v1/devices while on the device list
  /** Monotonic generation for account-passkey status reads. A registration/removal mutation invalidates every
   * read that began before (or during) it, so a late GET cannot overwrite the mutation's authoritative result. */
  private passkeyStatusGeneration = 0
  private directoryBrowserTimer: ReturnType<typeof setTimeout> | null = null
  private directoryBrowserRetryTimer: ReturnType<typeof setTimeout> | null = null
  /** One owner-scoped progress deadline spans browser preparation, relay/signaling, the session-bound token, ICE,
   * passkey, and transport authentication. The shared AbortSignal also cancels every owned cloud request. */
  private connectDeadline: { generation: number; deadline: ProgressDeadline } | null = null
  private sessionListWatchdog: ReturnType<typeof setTimeout> | null = null // guards the post-auth session_list wait
  private sessionListRetried = false // one re-request before giving up to offline+retry
  // Restore the remote's OWN saved per-window layout ONCE per connect (before the first existence-reconcile), so a
  // reconnect/sign-in keeps each window's arrangement instead of dropping every pane to stashed. Reset on each
  // connectTo. Browser-only state. (Part C wires the cloud GET that seeds paneLayoutsByWindow using this guard.)
  private restoredLayoutThisConnect = false
  // Slice 1 (pane lifecycle contract, S2-R1): persistence is FORBIDDEN until the cloud-restore
  // continuation has hydrated `paneLayoutsByWindow`. On a refresh, resumePanes→attach→persistLastLayout used to run
  // BEFORE the async fetch landed — activeWindowId null + empty map → it PUT "{}" over the durable row, wiping the
  // saved arrangement (the "sometimes placed, sometimes stashed" nondeterminism). Set in finishLayoutRestore (both
  // fetch arms); reset per connect. Invariant 4: never persist before hydration; persist after every partition
  // mutation, including reconcile and window switch.
  private layoutHydrated = false
  /** R8/R13 (first-handoff dedup, persisted ledger): the known-id LEDGER — projects/windows/panes the remote
   * already tracks. Seeded per connect from the restored cloud row's v3 `known` ledger (v1/v2 rows: known
   * windows derived from the window keys once), extended by every post-hydration reconcile, PRUNED to
   * currently-existing entities on every reconcile (R14 — deleted means gone, no tombstones), and persisted
   * back in the v3 row. First-handoff is PROJECT-scoped: the R7 landing applies only to projects absent from
   * `knownProjectIds`. Content-blind (ids only). */
  private knownProjectIds = new Set<string>()
  private knownWindowIds = new Set<string>()
  private knownPaneIds = new Set<string>()
  /** R7 landing-PENDING (lifecycle state `landing-pending`, pane lifecycle contract): windows designated for the
   * first-sight live landing whose first pane was NOT placeable yet when first seen. REALITY vs the atomic-push
   * fixture: a desktop-side create arrives as SEVERAL pushes (one per store commit), and the agent redacts a
   * pane's session_id to "" until the session is live — so the first sight of a new project often carries
   * nothing placeable. Burning the one-shot on that push (adding the window to knownWindowIds and moving on)
   * made the whole project land grey. A pending window stays landing-ELIGIBLE across pushes until the landing
   * places a live pane, a deliberate desktop stash decides the presentation, or the user acts on the window.
   * Pending windows are EXCLUDED from the persisted row (nothing user-built in them), so a refresh mid-creation
   * re-derives them as unknown → still landing-eligible (R8 reads the row; an unrecorded window may land). */
  private pendingLandingWindows = new Set<string>()
  /** R7 (creation liveness): sessions THIS BROWSER created (project_create auto-attach / new_window) whose
   * home window isn't in metadata yet. When the next session_list/workspace_update names the session's home
   * window, the completion places the seeded pane LIVE there, makes that window active, attaches at the
   * captured size, and persists — a self-created entity is "born known" (first-seen-as-placed) and must never
   * pass through the R4 stash landing rule. Keyed by session id → the create's viewport size. */
  private pendingSelfCreated = new Map<string, { cols: number; rows: number }>()
  private postCreateFreshAttachTimers = new Map<string, ReturnType<typeof setTimeout>>()
  private syncDebugWaiters = new Map<string, (agent: unknown) => void>()

  /** The project that owns the browser's ACTIVE window, tracked across reconciles/switches — so an eviction
   * (the active WINDOW deleted) can prefer the SAME project's next window before the Terminal fallback. */
  private activeProjectIdHint: string | null = null
  /** Browser-local navigation memory: the last window the user actually opened in each project. Project clicks
   * return to this window while it remains visible; a deleted/stashed memory falls back deterministically. */
  private focusedWindowByProject = new Map<string, string>()
  /** Watchdogs for session attaches that have not yet produced terminal data. Keyed by session id. */
  private attachWatchdogs = new Map<string, ReturnType<typeof setTimeout>>()
  /** Attach requests sent on the current transport that have not produced attach_ok yet. Unlike the materialize
   * watchdog, this survives an intentional UI leave: without an acknowledgement there is no confirmed channel
   * that can be detached safely. */
  private pendingWireAttaches = new Set<string>()
  /** Pending wire attaches abandoned by clear/leave. A same-session explicit attach may reclaim one without
   * sending a duplicate; otherwise its eventual attach_ok is quarantined and drained exactly once. */
  private abandonedPendingAttaches = new Set<string>()
  /** Short watchdog for sidebar pane clicks: click → optimistic active/green row; if the channel doesn't attach
   * quickly, refresh the workspace/session model so stale grey/green badges self-heal. */
  private paneSwitchWatchdog: {
    sessionId: string
    connectionGen: number
    timer: ReturnType<typeof setTimeout>
  } | null = null
  /** ONE watchdog for the `creatingSession` busy flag: armed whenever it flips true, disarmed whenever any
   * ok/error reply clears it (both transitions observed centrally in update()). Fires onCreatingWatchdog. */
  private creatingWatchdog: ReturnType<typeof setTimeout> | null = null
  private stopReconnect = false // set on revoke/auth_refused/signOut — never retry then
  private static readonly RECONNECT_MAX = RECONNECT_MAX_ATTEMPTS
  // Backoff base/cap live as module-level consts (RECONNECT_BASE_MS / RECONNECT_CAP_MS) used by the pure
  // reconnectDelayMs() helper. Injected randomness for jitter (deterministic in tests); defaults to Math.random.
  private rand: () => number = Math.random
  private pendingSignOutUnsubscribe: (() => void) | null = null
  private accountDeletedUnsubscribe: (() => void) | null = null
  private authContextChangedUnsubscribe: (() => void) | null = null
  private reconnectLifecycleUnsubscribes: Array<() => void> = []
  private lifecycleReconnectInFlight = false
  private disposed = false

  constructor(private readonly deps: RemoteClientDeps) {
    this.pendingSignOutUnsubscribe = this.deps.auth.onPendingSignOut?.((state) => {
      if (state === 'pending') this.onExternalPendingSignOut()
      else this.onExternalSignOutCleared()
    }) ?? null
    this.accountDeletedUnsubscribe = this.deps.auth.onAccountDeleted?.(() => {
      this.onExternalAccountDeleted()
    }) ?? null
    this.authContextChangedUnsubscribe = this.deps.auth.onAuthContextChanged?.(() => {
      this.onExternalAuthContextChanged()
    }) ?? null
    const reconnectLifecycle = this.deps.reconnectLifecycle === undefined
      ? browserReconnectLifecycle()
      : this.deps.reconnectLifecycle
    if (reconnectLifecycle) {
      this.reconnectLifecycleUnsubscribes.push(
        reconnectLifecycle.onOnline(() => this.wakeReconnectFromLifecycle('online')),
        reconnectLifecycle.onVisibilityChange(() => {
          if (!reconnectLifecycle.isVisible() || !reconnectLifecycle.isOnline()) return
          this.wakeReconnectFromLifecycle('visible')
        }),
      )
    }
  }

  private finishConnectionMetric(generation: number, outcome: ConnectionAttemptOutcome): void {
    const active = this.activeConnectionMetric
    if (active?.generation !== generation) return
    active.recorder.finish(outcome)
  }

  private finishActiveConnectionMetric(outcome: ConnectionAttemptOutcome): void {
    this.activeConnectionMetric?.recorder.finish(outcome)
  }

  accountDeletionEnabled(): boolean {
    return this.deps.accountDeletionEnabled === true
  }

  linuxServerEnrollmentEnabled(): boolean {
    return this.deps.linuxServerEnrollmentEnabled === true
  }

  // AUTH GENERATION (Codex #3): a monotonic counter that is bumped SYNCHRONOUSLY on logout and on any
  // account change. An async auth-scoped operation (token mint, device-list refresh, connect, enrollment,
  // revoke, layout restore) captures the generation before its first await and re-checks it after each
  // continuation — if it changed, the account context is no longer the one the operation started under, so
  // the operation aborts instead of applying results to a signed-out UI or the WRONG account. Without this,
  // a delayed token response could even build a live terminal session after logout.
  private authGeneration = 0
  /** Exactly one server/Clerk logout may run at a time. Every auth entry point joins this barrier before it
   * may restore or mint a different account cookie. A rejected barrier is cleared so the next explicit click
   * can retry; the provider's persistent marker remains until a confirmed success. */
  private logoutBarrier: Promise<boolean> | null = null
  /** Same-controller fail-closed state for custom providers that cannot persist/expose a marker. */
  private logoutUnconfirmed = false
  /** An explicit Sign out arriving while a lock-only settlement barrier is active must run afterwards. */
  private explicitLogoutRequested = false
  /** Cancels an in-flight native WebAuthn recovery prompt and every subsequent cloud request when auth changes. */
  private passkeyReplacementAbort: AbortController | null = null
  /** Initial registration has the same account-race boundary as replacement. */
  private passkeyRegistrationAbort: AbortController | null = null
  /** Add Desktop has its own native WebAuthn prompt and completion request; auth change cancels both. */
  private desktopEnrollmentAbort: AbortController | null = null
  /** Set only after the exact recovery-factor attempt produced an exchanged Hydra session. It is account-scoped
   * so a later sign-in for a different account cannot inherit the notice. No recovery code or count is stored. */
  private recoveryCodeNoticeAccountId: string | null = null
  /** Capture the current generation at the start of an auth-scoped async op. */
  private captureAuthGen(): number {
    return this.authGeneration
  }
  /** True if the auth context changed (logout / account switch) since `gen` was captured → abort. */
  private authGenChanged(gen: number): boolean {
    return this.authGeneration !== gen
  }
  /** Invalidate every in-flight auth-scoped op. Called synchronously before clearing session state so a
   * late continuation can't act on the old account. */
  private bumpAuthGeneration(): void {
    this.authGeneration++
    this.passkeyRegistrationAbort?.abort()
    this.passkeyRegistrationAbort = null
    this.passkeyReplacementAbort?.abort()
    this.passkeyReplacementAbort = null
    this.desktopEnrollmentAbort?.abort()
    this.desktopEnrollmentAbort = null
  }

  subscribe(fn: (v: RemoteClientView) => void): () => void {
    this.listeners.add(fn)
    fn(this.view)
    return () => this.listeners.delete(fn)
  }

  /** Release page-lifetime provider listeners when an embedding/test replaces the controller. */
  dispose(): void {
    this.disposed = true
    this.desktopEnrollmentAbort?.abort()
    this.desktopEnrollmentAbort = null
    this.pendingSignOutUnsubscribe?.()
    this.pendingSignOutUnsubscribe = null
    this.accountDeletedUnsubscribe?.()
    this.accountDeletedUnsubscribe = null
    this.authContextChangedUnsubscribe?.()
    this.authContextChangedUnsubscribe = null
    for (const unsubscribe of this.reconnectLifecycleUnsubscribes.splice(0)) unsubscribe()
  }
  private update(patch: Partial<RemoteClientView>): void {
    const wasCreating = this.view.creatingSession
    // A terminal acquisition may legitimately span connecting -> sessions while inventory, layout restore,
    // create-on-empty, and attach settle. Every phase outside that pair conclusively ends it. Keeping this
    // invariant here prevents an error/offline/sign-out path from forgetting to clear the passive loading surface.
    const nextPhase = patch.phase ?? this.view.phase
    const acquisitionPatch =
      patch.terminalAcquisition === undefined && nextPhase !== 'connecting' && nextPhase !== 'sessions'
        ? { terminalAcquisition: null }
        : {}
    this.view = { ...this.view, ...patch, ...acquisitionPatch }
    // Central creatingSession watchdog (Item: lost desktop reply must not wedge creation UI forever). Every
    // desktop-authoritative mutation funnels its busy flag through update(), so observing the flips HERE arms
    // the timer for every intent and disarms it on every ok/error reply — no per-callback bookkeeping to drift.
    if (!wasCreating && this.view.creatingSession) this.armCreatingWatchdog()
    else if (wasCreating && !this.view.creatingSession) this.clearCreatingWatchdog()
    for (const fn of this.listeners) fn(this.view)
    if (wasCreating && !this.view.creatingSession && this.pendingSelfCreated.size > 0) {
      // A self-created window/project may have become visible in metadata while a different desktop mutation
      // owned the single request lane. Drain after the current publication completes; otherwise the already-seen
      // metadata push is consumed and that seeded pane can remain unattached until unrelated future traffic.
      const ownerGeneration = this.connectionGeneration
      queueMicrotask(() => {
        if (
          !this.disposed
          && ownerGeneration === this.connectionGeneration
          && !this.view.creatingSession
          && this.session?.isAuthenticated
        ) this.completeSelfCreatedPlacements()
      })
    }
  }
  snapshot(): RemoteClientView {
    return this.view
  }

  /** Content-blind debugger for the local→agent→browser workspace sync path. Safe to call from the console. */
  async debugSyncSnapshot(timeoutMs = 2500): Promise<RemoteSyncDebugSnapshot> {
    const requestId = `sync-debug-${Date.now().toString(36)}`
    const sent = this.session?.debugSyncSnapshot(requestId)
    if (!sent) {
      const result = { browser: this.browserSyncDebugSnapshot(), error: 'not authenticated or no remote session' }
      return result
    }
    const agent = await new Promise<unknown>((resolve) => {
      const timer = setTimeout(() => {
        this.syncDebugWaiters.delete(requestId)
        resolve({ error: 'agent debug_sync_snapshot timed out' })
      }, timeoutMs)
      this.syncDebugWaiters.set(requestId, (value) => {
        clearTimeout(timer)
        resolve(value)
      })
    })
    const result = { browser: this.browserSyncDebugSnapshot(), agent }
    return result
  }

  private browserSyncDebugSnapshot(): RemoteSyncBrowserDebug {
    const metadata = this.view.workspaceMetadata
    const liveSessions = new Set(this.view.sessions)
    const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) map[this.view.activeWindowId] = this.workspacePanes()
    const placedSessionsFor = (windowId: string): Set<string> => {
      const entry = map[windowId]
      if (!entry?.layout) return new Set()
      return new Set(leaves(entry.layout.root).map((l) => l.sessionId).filter((s): s is string => s !== null))
    }
    const paneLayoutsByWindow: RemoteSyncBrowserDebug['paneLayoutsByWindow'] = {}
    for (const [windowId, entry] of Object.entries(map)) {
      paneLayoutsByWindow[windowId] = {
        placedSessions: entry.layout ? leaves(entry.layout.root).map((l) => l.sessionId).filter((s): s is string => s !== null) : [],
        stashed: entry.stashed.map((s) => ({ paneId: s.paneId, sessionId: s.sessionId })),
        windowStashed: Boolean(entry.windowStashed && !entry.layout),
      }
    }

    let windowCount = 0
    let paneCount = 0
    let namedPanes = 0
    let redactedPanes = 0
    const panes: RemoteSyncBrowserPaneDebug[] = []
    for (const project of metadata?.projects ?? []) {
      for (const window of project.windows) {
        windowCount += 1
        const placed = placedSessionsFor(window.id)
        for (const pane of window.panes) {
          paneCount += 1
          const sessionIdPresent = Boolean(pane.sessionId)
          if (sessionIdPresent) namedPanes += 1
          else redactedPanes += 1
          const sessionLive = sessionIdPresent && liveSessions.has(pane.sessionId)
          const isPlaced = sessionIdPresent && placed.has(pane.sessionId)
          const pendingLanding = this.pendingLandingWindows.has(window.id)
          const reason = !sessionIdPresent
            ? 'metadata pane has no session id'
            : !sessionLive
              ? 'session id is not in browser live sessions'
              : isPlaced
                ? 'placed in remote layout'
                : pendingLanding
                  ? 'live but waiting in pending landing'
                  : 'live but stashed in remote layout'
          panes.push({
            projectId: project.id,
            windowId: window.id,
            paneId: pane.id,
            sessionIdPresent,
            sessionLive,
            placed: isPlaced,
            desktopStashed: Boolean(pane.stashed),
            pendingLanding,
            clickable: sessionLive,
            reason,
          })
        }
      }
    }
    const tree = workspaceTreeFromRemoteView(this.view, { pendingLandingWindows: [...this.pendingLandingWindows] })
      .projects
      .map((project) => ({
        id: project.id,
        name: project.name,
        isSelected: project.isSelected,
        statusDot: project.statusDot,
        windows: project.windows.map((window) => ({
          id: window.id,
          name: window.name,
          isFocused: window.isFocused,
          isStashed: window.isStashed,
          isStarting: window.isStarting,
          statusDot: window.statusDot,
          panes: window.panes.map((pane) => ({
            id: pane.id,
            name: pane.name,
            sessionId: pane.sessionId,
            isLive: pane.isLive,
            isStashed: pane.isStashed,
            isStarting: pane.isStarting,
            statusDot: pane.statusDot,
          })),
        })),
      }))
    return {
      phase: this.view.phase,
      traceId: this.traceId,
      selectedDevice: this.view.selectedDevice,
      activeWindowId: this.view.activeWindowId ?? null,
      attachedSession: this.view.attachedSession,
      sessionCount: this.view.sessions.length,
      projectCount: metadata?.projects.length ?? 0,
      windowCount,
      paneCount,
      namedPanes,
      redactedPanes,
      layoutHydrated: this.layoutHydrated,
      lastAppliedWorkspaceEpoch: this.lastAppliedWorkspaceEpoch,
      pendingLandingWindows: [...this.pendingLandingWindows],
      knownCounts: {
        projects: this.knownProjectIds.size,
        windows: this.knownWindowIds.size,
        panes: this.knownPaneIds.size,
      },
      paneLayoutsByWindow,
      panes,
      tree,
    }
  }

  async signIn(): Promise<void> {
    await this.interactiveAuth('sign-in')
  }

  /** Create an account then land in the app. Same flow + failure handling as signIn; only the Clerk page
   * (hosted sign-up vs sign-in) + the error label differ. */
  async signUp(): Promise<void> {
    await this.interactiveAuth('sign-up')
  }

  async signInWithPassword(email: string, password: string): Promise<void> {
    await this.interactiveAuth('sign-in', () => this.deps.auth.signInWithPassword?.(email, password) ?? this.deps.auth.signIn())
  }

  async completeSignInSecondFactor(strategy: AuthSecondFactorStrategy, code: string): Promise<void> {
    const pending = this.view.authSecondFactor
    if (!pending?.strategies.includes(strategy)) {
      this.update({
        phase: 'signed_out',
        authSecondFactor: null,
        error: 'That additional verification method is no longer available. Start sign-in again.',
      })
      return
    }
    this.update({
      authSecondFactor: {
        strategies: [...pending.strategies],
        selectedStrategy: strategy,
      },
    })
    let completedAccountId: string | null = null
    await this.interactiveAuth(
      'sign-in',
      () => this.deps.auth.completeSignInSecondFactor?.(strategy, code) ?? Promise.resolve(null),
      false,
      true,
      (session) => {
        if (strategy !== 'backup_code') return
        completedAccountId = session.accountId
        this.recoveryCodeNoticeAccountId = session.accountId
      },
    )
    if (strategy === 'backup_code' && completedAccountId !== null) {
      if (this.view.accountId === completedAccountId) {
        this.update({ recoveryCodeUsed: true })
      } else if (this.recoveryCodeNoticeAccountId === completedAccountId) {
        const prefix = this.view.error ? `${this.view.error} ` : ''
        this.update({
          authSecondFactor: null,
          recoveryCodeUsed: false,
          error: `${prefix}One recovery code was consumed. Sign in again, then generate a fresh set.`,
        })
      }
    }
  }

  dismissRecoveryCodeNotice(): void {
    this.recoveryCodeNoticeAccountId = null
    if (this.view.recoveryCodeUsed) this.update({ recoveryCodeUsed: false })
  }

  cancelSignInSecondFactor(): void {
    // A Clerk attempt cannot be cancelled once its provider request has started. The UI disables Start over
    // while authenticating, and this guard makes imperative/double-click callers obey the same rule; otherwise
    // a suppressed controller update could still leave a valid Clerk/Hydra cookie after apparent cancellation.
    if (!this.view.authSecondFactor || this.view.phase === 'authenticating') return
    this.bumpAuthGeneration()
    this.update({ phase: 'signed_out', authSecondFactor: null, error: null })
  }

  async signUpWithPassword(name: string, email: string, password: string): Promise<void> {
    await this.interactiveAuth('sign-up', () => this.deps.auth.signUpWithPassword?.(name, email, password) ?? this.deps.auth.signUp())
  }

  async verifySignUpCode(code: string): Promise<void> {
    await this.interactiveAuth('sign-up', () => this.deps.auth.verifySignUpCode?.(code) ?? this.deps.auth.signUp())
  }

  async signInWithOAuth(provider: 'google' | 'github' | 'apple' | 'facebook', mode: 'sign-in' | 'sign-up'): Promise<void> {
    // isRedirect: OAuth navigates the browser away to the provider. We must NOT re-render (that rebuilds
    // the auth terminal and wipes the click spinner the button set); the button's own imperative spinner
    // is the feedback, and the page is unloading anyway.
    await this.interactiveAuth(mode, () => this.deps.auth.signInWithOAuth?.(provider, mode) ?? (mode === 'sign-up' ? this.deps.auth.signUp() : this.deps.auth.signIn()), true)
  }

  private async interactiveAuth(
    mode: 'sign-in' | 'sign-up',
    authenticate?: () => Promise<import('./auth-contract.js').Session | null>,
    isRedirect = false,
    preserveSecondFactor = false,
    onAuthenticated?: (session: import('./auth-contract.js').Session) => void,
  ): Promise<void> {
    const invocationAuthGen = this.captureAuthGen()
    // Wrap the WHOLE flow: auth.signIn/signUp() (Clerk origin/config/runtime failure on the hosted app) AND
    // afterSignedIn()'s listDesktops() can THROW. Without this catch, a click becomes a silent rejected
    // promise — nothing happens on screen. Fail VISIBLE: land back on signed_out with a bounded,
    // content-blind error so the user sees the failure and can retry. safeMessage scrubs any
    // token/cookie/origin detail the thrown error might carry.
    const label = mode === 'sign-up' ? 'Sign-up' : 'Sign-in'
    // A logout response carries the cookie deletion. It must settle before Clerk/session-exchange can write a
    // cookie for account B. Re-read the provider marker on every auth action so a logout started in another tab
    // also blocks this tab. Failure is fail-closed and content-blind; the next explicit click retries.
    if (!isRedirect) this.update({
      phase: 'authenticating',
      error: null,
      ...(preserveSecondFactor ? {} : { authSecondFactor: null }),
    })
    try {
      if (this.deps.auth.coordinatesAuthSession) {
        // CookieAuthProvider captures marker+epoch and performs settle+auth inside ONE queued Web Lock callback.
        // Only join a barrier already started by this controller (explicit/external logout); never add a
        // separate pre-settle lock that would break provider FIFO.
        if (this.logoutBarrier) await this.logoutBarrier
      } else {
        await this.settlePendingSignOutBeforeAuth()
      }
    } catch (error) {
      this.update({ phase: 'signed_out', error: pendingLogoutWarning(error) })
      return
    }
    // Logout may have arrived while this invocation was queued behind an existing barrier. It owns the later
    // intent: do not start a fresh exchange merely because the barrier has now finished.
    if (this.authGenChanged(invocationAuthGen)) return
    // A fresh sign-in/up starts a NEW auth context — invalidate any in-flight ops from a prior account so a
    // late continuation (token/device-list) from account A can't land after account B signs in.
    this.bumpAuthGeneration()
    const authGen = this.captureAuthGen()
    // Show a spinner while a NON-redirect request is in flight (password/email). For an OAuth redirect we
    // skip this re-render so the button's own click spinner survives until the page navigates.
    if (!isRedirect && this.view.phase !== 'authenticating') this.update({
      phase: 'authenticating',
      error: null,
      ...(preserveSecondFactor ? {} : { authSecondFactor: null }),
    })
    try {
      const s = authenticate ? await authenticate() : mode === 'sign-up' ? await this.deps.auth.signUp() : await this.deps.auth.signIn()
      // Logout/account switch won while the provider was awaiting Clerk or the exchange. Never publish its late
      // result. (The logout barrier separately prevents a later account-B exchange from overtaking logout.)
      if (this.authGenChanged(authGen)) return
      if (!s) {
        this.update({ phase: 'signed_out', error: `${label} failed. Please try again.` })
        return
      }
      onAuthenticated?.(s)
      await this.afterSignedIn(s, authGen)
    } catch (e) {
      if (this.authGenChanged(authGen)) return
      if (e instanceof AuthAccountDeletedError) {
        const reset = freshAccountView()
        reset.accountDeletion.notice = e.message
        this.update(reset)
        return
      }
      if (this.showSignInContinuation(e)) return
      // Matched by NAME so this crate stays auth-provider-agnostic (no clerk-client import here).
      // 1) OAuth redirect: the browser is navigating to the provider (Google/GitHub). NOT a failure, and
      //    we must NOT re-render — a re-render rebuilds the auth terminal and wipes the click spinner the
      //    button set imperatively. Leave the current DOM (spinner spinning) as the page unloads.
      if (e instanceof Error && e.name === 'AuthRedirectingError') {
        return
      }
      // 2) Email verification is a NORMAL next step: surface the clean prompt (which the auth terminal
      //    recognizes to show the code field), staying on the sign-out surface.
      if (e instanceof Error && e.name === 'EmailVerificationRequiredError') {
        this.update({ phase: 'signed_out', error: e.message })
        return
      }
      this.update({ phase: 'signed_out', error: `${label} failed: ${safeMessage(e instanceof Error ? e.message : String(e))}` })
    }
  }

  private showSignInContinuation(error: unknown): boolean {
    if (error instanceof AuthSecondFactorRequiredError) {
      this.update({
        phase: 'signed_out',
        authSecondFactor: {
          strategies: [...error.strategies],
          ...(error.rejectedStrategy ? { selectedStrategy: error.rejectedStrategy } : {}),
        },
        error: error.message,
      })
      return true
    }
    if (error instanceof AuthClientTrustRequiredError) {
      this.update({ phase: 'signed_out', authSecondFactor: null, error: error.message })
      return true
    }
    return false
  }

  /** On page load: restore the session from the httpOnly cookie (no prompt) and, if hints match, auto
   * reconnect/reattach — so a refresh resumes seamlessly with NO Sign-in click. */
  async restoreSession(): Promise<void> {
    const invocationAuthGen = this.captureAuthGen()
    this.update({ phase: 'restoring' })
    // A persisted marker means a prior tab/navigation may have interrupted the cookie-clearing response. Service
    // that logout FIRST and deliberately remain signed out for this load. Never call restore/resumeIdentitySession here:
    // either could resurrect account A before the user explicitly chooses to authenticate again.
    const hadPendingAtInvocation = this.deps.auth.hasPendingSignOut?.() === true
    let settledPending = false
    try {
      if (this.deps.auth.coordinatesAuthSession) {
        if (this.logoutBarrier) settledPending = await this.logoutBarrier
      } else {
        settledPending = await this.settlePendingSignOutBeforeAuth()
      }
    } catch (error) {
      this.update({ phase: 'signed_out', error: pendingLogoutWarning(error) })
      return
    }
    if (
      settledPending ||
      (hadPendingAtInvocation && !this.deps.auth.coordinatesAuthSession)
    ) {
      this.update({ phase: 'signed_out', error: null })
      return
    }
    if (this.authGenChanged(invocationAuthGen)) return
    const authGen = this.captureAuthGen()
    try {
      // 1. Revalidate the existing session through the configured identity provider.
      let s = await this.deps.auth.restore()
      if (this.authGenChanged(authGen)) return
      // 2. Complete an already-authenticated provider continuation without another sign-in prompt.
      //    A genuinely signed-out visitor still receives null.
      if (!s) s = await this.deps.auth.resumeIdentitySession()
      if (this.authGenChanged(authGen)) return
      if (!s) {
        this.update({ phase: 'signed_out', error: null })
        return
      }
      await this.afterSignedIn(s, authGen)
    } catch (e) {
      if (this.authGenChanged(authGen)) return
      if (e instanceof AuthAccountDeletedError) {
        const reset = freshAccountView()
        reset.accountDeletion.notice = e.message
        this.update(reset)
        return
      }
      if (e instanceof Error && e.name === 'AuthSupersededError') {
        this.update({ phase: 'signed_out', error: null })
        return
      }
      if (this.showSignInContinuation(e)) return
      // CookieAuthProvider normally settles a captured crash/reload marker inside the same Web Lock as restore.
      // In a real browser without Web Locks, normal auth deliberately fails closed; logout-only settlement is
      // still safe because every auth mutation is blocked. Service that durable marker, remain signed out, and
      // never continue to Clerk for this load so the browser is not permanently wedged on every refresh.
      if (
        hadPendingAtInvocation &&
        this.deps.auth.coordinatesAuthSession &&
        e instanceof Error &&
        e.name === 'AuthCoordinationError'
      ) {
        try {
          await this.settlePendingSignOutBeforeAuth()
          this.update({ phase: 'signed_out', error: null })
        } catch (settleError) {
          this.update({ phase: 'signed_out', error: pendingLogoutWarning(settleError) })
        }
        return
      }
      const message = safeMessage(e instanceof Error ? e.message : String(e))
      this.update({ phase: 'signed_out', error: `Session restore failed: ${message}` })
    }
  }

  private async afterSignedIn(s: { accountId: string; credential: string }, authGen: number): Promise<void> {
    const devices = await this.deps.listDesktops(s.credential)
    // Abort if the user logged out (or switched account) while the device list was loading — otherwise we'd
    // render account A's desktops onto a signed-out or account-B screen.
    if (this.authGenChanged(authGen)) return
    const recoveryCodeUsed = this.recoveryCodeNoticeAccountId === s.accountId
    if (this.recoveryCodeNoticeAccountId !== null && !recoveryCodeUsed) {
      this.recoveryCodeNoticeAccountId = null
    }
    const deviceLabels = loadDeviceLabels(s.accountId)
    this.update({
      phase: 'devices',
      authSecondFactor: null,
      recoveryCodeUsed,
      accountId: s.accountId,
      devices,
      deviceLabels,
      knownSessionsByDevice: this.loadKnownSessionsForDevices(s.accountId, devices),
      layoutPresetState: loadLayoutPresetState(s.accountId),
      passkey: { registering: false, registered: false, error: null, status: 'loading' },
      error: null,
    })
    // Passkey metadata is account state just like the device list. Refresh it after every successful auth path
    // (interactive sign-in/up, cookie restore, and Clerk resume) so the panel never shows its default "not set"
    // state while the cloud still has an anchor. Keep it non-blocking: a transient status failure must not delay
    // desktop listing or automatic reconnect.
    void this.refreshPasskeyStatus(s)
    // RESUME after a refresh: if we have hints and the same desktop is still enrolled, reconnect to it
    // (and the session-list handler will reattach the saved session). Otherwise stay on the device list.
    const h = loadHints()
    if (h && h.accountId === s.accountId) {
      const target = devices.find((d) => d.deviceId === h.desktopDeviceId && !d.revoked)
      if (target) {
        this.resumeSessionId = h.sessionId
        void this.connectTo(h.desktopDeviceId, { trigger: 'restore' })
      } else {
        // The hinted desktop is gone or revoked for THIS account — the hint can never resume, so clear it
        // (hygiene: a later refresh won't re-check a dead desktop). Hints for OTHER accounts are left intact.
        clearHints()
      }
    }
    // Keep the device list LIVE while the user is looking at it: a desktop they just enrolled (or one revoked
    // elsewhere) appears/disappears without a page refresh. One-shot listDesktops at sign-in was why "Add desktop
    // appears here automatically" never happened.
    this.startDeviceRefresh()
  }

  /** Re-fetch /v1/devices and merge into the view (only meaningful on the device list). Silent on failure — a
   * transient poll error must not disrupt the UI; the next tick retries. */
  private async refreshDevices(): Promise<void> {
    const s = this.deps.auth.current()
    if (!s) return
    const authGen = this.captureAuthGen()
    let devices: DesktopDevice[]
    try {
      devices = await this.deps.listDesktops(s.credential)
    } catch {
      return // transient — keep the last good list, retry next tick
    }
    // Abort if the auth context changed during the fetch (logout / account switch).
    if (this.authGenChanged(authGen)) return
    // Only apply while still on the device list (the user may have navigated into a session mid-fetch).
    if (this.view.phase !== 'devices') return
    if (devicesEqual(this.view.devices, devices)) return // no-op guard: don't churn the UI when nothing changed
    this.update({
      devices,
      knownSessionsByDevice: this.loadKnownSessionsForDevices(s.accountId, devices),
    })
  }

  /** Start polling /v1/devices while the device list is shown. Idempotent; stopped by stopDeviceRefresh (on
   * connect/sign-out/disconnect). ~8s cadence — responsive for enroll/revoke without hammering the API. */
  private startDeviceRefresh(): void {
    if (this.deviceRefreshTimer) return
    if (typeof setInterval !== 'function') return
    this.deviceRefreshTimer = setInterval(() => {
      if (this.view.phase !== 'devices') {
        this.stopDeviceRefresh()
        return
      }
      void this.refreshDevices()
    }, DEVICE_REFRESH_INTERVAL_MS)
  }

  private stopDeviceRefresh(): void {
    if (this.deviceRefreshTimer) {
      clearInterval(this.deviceRefreshTimer)
      this.deviceRefreshTimer = null
    }
  }

  signOut(): void {
    // Invalidate every in-flight auth-scoped async op FIRST (synchronously), so a token mint / device list /
    // connect / layout restore that resolves after this can't act on the now-signed-out account.
    this.bumpAuthGeneration()
    this.recoveryCodeNoticeAccountId = null
    this.disconnect()
    // Wipe ALL account-scoped browser storage so nothing leaks to the next account on a shared browser
    // (device labels, session labels/order/favorites/hidden, layouts, presets, per-device token, reconnect
    // hint). Device PREFERENCES (renderer mode, font size) are preserved.
    clearAllAccountState()
    // Drop entry-layer account-scoped caches too (the cloud browser-device-id cache), so account B can't
    // reuse account A's device id on a shared browser.
    this.deps.onAccountReset?.()
    this.logoutUnconfirmed = true
    this.explicitLogoutRequested = true
    // FULL in-memory reset happens before the provider publishes its marker. The initiating provider's
    // notification is source-filtered, but this ordering also makes duplicate browser delivery harmless.
    this.update(freshAccountView())
    // Clear the UI immediately (responsive), then revoke the SERVER session with retry — a fire-and-forget
    // logout that fails would leave a VALID cookie a refresh could restore. If every attempt fails we
    // surface a warning and keep every auth path blocked until a later explicit action confirms logout.
    void this.confirmServerSignOut().catch((error) => {
      // Account B cannot have started through this controller while the barrier was pending, so this warning
      // cannot overwrite a successful account switch. Keep it fixed/content-blind regardless of provider error.
      if (this.view.phase === 'signed_out') this.update({ phase: 'signed_out', error: pendingLogoutWarning(error) })
    })
  }

  async deleteAccount(): Promise<void> {
    if (!this.accountDeletionEnabled() || this.view.accountDeletion.deleting || !this.view.accountId) return
    const expectedAccountId = this.view.accountId
    const remove = this.deps.auth.deleteAccount
    if (!remove) {
      this.update({
        accountDeletion: {
          ...this.view.accountDeletion,
          confirming: true,
          error: 'Account deletion is unavailable. Try again later.',
        },
      })
      return
    }
    const authGen = this.captureAuthGen()
    this.update({
      accountDeletion: {
        confirming: true,
        deleting: true,
        error: null,
        notice: null,
        identityDeletionPending: false,
      },
    })
    let result: Awaited<ReturnType<NonNullable<typeof remove>>>
    try {
      result = await remove.call(this.deps.auth, expectedAccountId)
    } catch (error) {
      if (this.authGenChanged(authGen)) return
      if (error instanceof AuthAccountDeletedError) {
        this.bumpAuthGeneration()
        this.disconnect()
        clearAllAccountState()
        this.deps.onAccountReset?.()
        const reset = freshAccountView()
        reset.accountDeletion.notice = error.message
        this.update(reset)
        return
      }
      if (error instanceof AuthAccountDeletionCancelledError) {
        this.update({
          accountDeletion: {
            confirming: true,
            deleting: false,
            error: null,
            notice: null,
            identityDeletionPending: false,
          },
        })
        return
      }
      const message = error instanceof Error && error.message
        ? safeMessage(error.message)
        : 'Could not confirm account deletion. Check your connection and try again.'
      this.update({
        accountDeletion: {
          confirming: true,
          deleting: false,
          error: message,
          notice: null,
          identityDeletionPending: false,
        },
      })
      return
    }
    if (this.authGenChanged(authGen)) return
    this.bumpAuthGeneration()
    this.disconnect()
    clearAllAccountState()
    this.deps.onAccountReset?.()
    const reset = freshAccountView()
    reset.accountDeletion = {
      confirming: false,
      deleting: false,
      error: null,
      identityDeletionPending: result.identityDeletionPending,
      notice: result.identityDeletionPending
        ? 'Your Hydra account and cloud product data were deleted. Managed sign-in cleanup is still finishing automatically.'
        : 'Your Hydra account was deleted. You are signed out.',
    }
    this.update(reset)
  }

  private onExternalAccountDeleted(): void {
    this.bumpAuthGeneration()
    this.disconnect()
    clearAllAccountState()
    this.deps.onAccountReset?.()
    const reset = freshAccountView()
    reset.accountDeletion = {
      confirming: false,
      deleting: false,
      error: null,
      notice: 'This Hydra account was deleted in another tab. You are signed out.',
      identityDeletionPending: true,
    }
    this.update(reset)
  }

  /** Another document completed a Clerk exchange and may have replaced the browser-wide Hydra cookie.
   * Retire this document's authority synchronously; a later explicit restore must reconcile its own Clerk
   * identity with the server before any account or desktop state can be published again. */
  private onExternalAuthContextChanged(): void {
    this.bumpAuthGeneration()
    this.disconnect()
    clearAllAccountState()
    this.deps.onAccountReset?.()
    this.logoutUnconfirmed = false
    this.explicitLogoutRequested = false
    this.update(freshAccountView())
  }

  beginAccountDeletion(): void {
    if (!this.accountDeletionEnabled() || !this.view.accountId || this.view.accountDeletion.deleting) return
    this.update({
      accountDeletion: {
        ...this.view.accountDeletion,
        confirming: true,
        error: null,
      },
    })
  }

  dismissAccountDeletion(): void {
    if (this.view.accountDeletion.deleting) return
    this.update({
      accountDeletion: {
        ...this.view.accountDeletion,
        confirming: false,
        error: null,
      },
    })
  }

  /** Install the controller's one coalesced barrier. The provider supplies the cross-document lock; this keeps
   * repeated actions in one controller from starting parallel retry loops. */
  private installLogoutBarrier(operation: Promise<boolean>): Promise<boolean> {
    if (this.logoutBarrier) return this.logoutBarrier
    const barrier = operation
    this.logoutBarrier = barrier
    const clear = () => {
      if (this.logoutBarrier === barrier) this.logoutBarrier = null
    }
    void barrier.then(clear, clear)
    return barrier
  }

  /** Explicit initiation. If a lock-only settlement is already running, wait for it and then honor the explicit
   * request; never mistake a no-op settlement for the user's Sign out. */
  private async confirmServerSignOut(): Promise<void> {
    this.logoutUnconfirmed = true
    this.explicitLogoutRequested = true
    while (this.logoutBarrier) {
      try {
        await this.logoutBarrier
      } catch {
        // An explicit request still gets its own attempt after a failed settlement barrier.
      }
    }
    if (!this.explicitLogoutRequested) return
    const barrier = this.installLogoutBarrier(this.serverSignOutWithRetry().then(() => true))
    try {
      await barrier
      this.explicitLogoutRequested = false
      this.logoutUnconfirmed = false
    } catch (error) {
      // Retain only the unconfirmed state. The next explicit auth settles the durable provider marker; keeping
      // a stale initiation flag could log out an account that another tab successfully established meanwhile.
      this.explicitLogoutRequested = false
      throw error
    }
  }

  /** Cross the provider's shared auth mutex on every auth/restore action. A provider with a durable marker
   * settles it under that lock. A legacy/custom provider is only asked to sign out when this controller already
   * knows an explicit logout is unconfirmed — never merely to acquire a lock. */
  private async settlePendingSignOutBeforeAuth(): Promise<boolean> {
    if (this.logoutBarrier) {
      const observed = await this.logoutBarrier
      if (this.explicitLogoutRequested) {
        await this.confirmServerSignOut()
        return true
      }
      return observed
    }

    const settle = this.deps.auth.settlePendingSignOut
    if (!settle) {
      if (this.logoutUnconfirmed || this.deps.auth.hasPendingSignOut?.() === true) {
        await this.confirmServerSignOut()
        return true
      }
      return false
    }

    const barrier = this.installLogoutBarrier(settle.call(this.deps.auth))
    try {
      const observed = await barrier
      if (!this.explicitLogoutRequested) this.logoutUnconfirmed = false
      if (this.explicitLogoutRequested) {
        await this.confirmServerSignOut()
        return true
      }
      return observed
    } catch (error) {
      this.logoutUnconfirmed = true
      throw error
    }
  }

  /** One provider call owns the whole logical logout. CookieAuthProvider keeps its bounded attempts inside one
   * cross-document lock; the controller must never release/reacquire that lock between retries. */
  private async serverSignOutWithRetry(): Promise<void> {
    await this.deps.auth.signOut()
  }

  /** Another same-origin document published logout intent. Tear down account/session authority synchronously,
   * before waiting on its auth lock, so no stale terminal or account-A continuation remains usable. */
  private onExternalPendingSignOut(): void {
    if (this.logoutUnconfirmed && this.view.phase === 'signed_out') return
    this.bumpAuthGeneration()
    this.disconnect()
    clearAllAccountState()
    this.deps.onAccountReset?.()
    this.logoutUnconfirmed = true
    this.update(freshAccountView())
    void this.settlePendingSignOutBeforeAuth().then(() => {
      this.logoutUnconfirmed = false
    }).catch((error) => {
      if (this.view.phase === 'signed_out') {
        this.update({ phase: 'signed_out', error: pendingLogoutWarning(error) })
      }
    })
  }

  private onExternalSignOutCleared(): void {
    if (this.logoutBarrier || this.explicitLogoutRequested) return
    this.logoutUnconfirmed = false
    if (
      this.view.phase === 'signed_out' &&
      (this.view.error === PENDING_LOGOUT_WARNING || this.view.error === AUTH_COORDINATION_WARNING)
    ) {
      this.update({ phase: 'signed_out', error: null })
    }
  }

  /** Leave the current connection and return to the DESKTOP LIST — WITHOUT signing out. Stops any
   * reconnect, closes the transport/session, and keeps auth (accountId + devices) intact. This is the safe
   * "go back" the user wants: from terminal/sessions/connecting/offline/error → back to choosing a desktop,
   * never killing the Clerk/Hydra session and never revoking the device. */
  backToDevices(options: { refreshPasskey?: boolean } = {}): void {
    this.disconnect()
    clearHints() // drop any saved hint pointing at the desktop we just left (esp. a revoked one) so we don't
    // immediately auto-reconnect to it; the fresh device list is the source of truth.
    // CLEAR a revoked/refused auth state — "Back to desktops" is a genuine recovery. A revoke can be transient (a
    // device un-revoked by a re-enroll, or the user picking a DIFFERENT desktop), and 'revoked' is otherwise a
    // dead-end (stopReconnect). Only reset the FAILED states; a healthy 'authenticated' back-out is left intact.
    const nextAuthState = this.view.authState === 'revoked' || this.view.authState === 'refused'
      ? 'idle'
      : this.view.authState
    this.update({
      phase: 'devices',
      selectedDevice: null,
      attachedSession: null,
      authState: nextAuthState,
      sessions: [],
      lastOpenedSessionId: null,
      favoriteSessions: [],
      sessionOrder: [],
      hiddenSessions: [],
      sessionCwds: {},
      workspaceMetadata: null,
      error: null,
    })
    this.stopReconnect = false // re-arm: leaving the revoked dead-end, a future connect may retry normally
    // Back on the device list → resume live polling (disconnect() above stopped it) + fetch once immediately.
    this.startDeviceRefresh()
    void this.refreshDevices()
    // A user can spend a long time in a terminal while another tab performs account recovery. Re-read the
    // account anchor when returning to the desktop list; this is event-driven, not another polling loop.
    if (options.refreshPasskey !== false) void this.refreshPasskeyStatus()
  }

  /** "Add desktop": issue a short-lived enrollment code for this account. The user either pastes it into
   * the desktop app or runs `hydraterms remote` on a Linux server and enters it at the hidden prompt. The code
   * never belongs in process arguments. Guarded against double-issue while one is in flight. */
  async addDesktop(): Promise<void> {
    if (this.view.enroll.issuing) return // don't spam code creation
    const s = this.deps.auth.current()
    if (!s) {
      this.update({ enroll: { issuing: false, code: null, expiresAtMs: null, error: 'session expired — sign in again' } })
      return
    }
    if (
      this.view.passkey.status !== 'present' ||
      !this.view.passkey.credentialId ||
      !Number.isSafeInteger(this.view.passkey.generation) ||
      Number(this.view.passkey.generation) < 1
    ) {
      const error = this.view.passkey.status === 'absent'
        ? 'Set up your account passkey before adding a desktop.'
        : 'Could not verify the current account passkey. Refresh account security and try again.'
      this.update({ enroll: { issuing: false, code: null, expiresAtMs: null, error } })
      return
    }
    const expected: { credentialId: string; generation: number } = {
      credentialId: this.view.passkey.credentialId,
      generation: Number(this.view.passkey.generation),
    }
    const abort = new AbortController()
    this.desktopEnrollmentAbort?.abort()
    this.desktopEnrollmentAbort = abort
    this.update({ enroll: { issuing: true, code: null, expiresAtMs: null, error: null } })
    const authGen = this.captureAuthGen()
    try {
      const r = await this.deps.issueLinkCode(s.credential, expected, {
        accountId: s.accountId,
        signal: abort.signal,
        onStage: (stage) => {
          if (!this.authGenChanged(authGen) && this.desktopEnrollmentAbort === abort && !abort.signal.aborted) {
            this.update({ enroll: { ...this.view.enroll, issuing: true, stage } })
          }
        },
      })
      // Abort if logged out / switched account while the code was minting — never show account A's
      // enrollment code to account B (it would enroll a desktop into A's account).
      if (this.authGenChanged(authGen)) return
      if (!r) {
        this.update({ enroll: { issuing: false, code: null, expiresAtMs: null, error: 'could not issue a code — try again' } })
        return
      }
      this.update({ enroll: { issuing: false, code: r.code, expiresAtMs: r.expiresAtMs, error: null } })
    } catch (error) {
      if (this.authGenChanged(authGen) || abort.signal.aborted) return
      const message = error instanceof Error && error.message
        ? error.message
        : 'Could not issue a code — try again.'
      this.update({ enroll: { issuing: false, code: null, expiresAtMs: null, error: message } })
    } finally {
      if (this.desktopEnrollmentAbort === abort) this.desktopEnrollmentAbort = null
    }
  }

  /** Dismiss the shown enrollment code (e.g. after the user copied/used it). */
  dismissEnrollCode(): void {
    this.update({ enroll: { issuing: false, code: null, expiresAtMs: null, error: null } })
  }

  /** ACCESS PASSKEY (#11): register the account passkey (WebAuthn) that authorizes new browsers. Runs the
   * ceremony via the entry-layer dep; on success future browser connections present a passkey-signed cert the
   * desktop verifies directly (independent of the cloud). No-op if the dep isn't wired. */
  async registerPasskey(): Promise<void> {
    if (!this.deps.registerAccountPasskey) return
    if (this.view.passkey.registering) return
    // Initial registration is absent-only. Existing anchors use current-anchor-authorized replacement.
    if (this.view.passkey.registered) {
      this.update({ passkey: {
        ...this.view.passkey,
        registering: false,
        registered: true,
        error: 'A passkey is already set up. Use Replace passkey in Security → Browser authorization.',
      } })
      return
    }
    if (
      this.deps.hasAccountPasskey &&
      (this.view.passkey.status === 'loading' || this.view.passkey.status === 'unavailable')
    ) {
      this.update({ passkey: {
        ...this.view.passkey,
        error: 'Could not verify whether this account already has a passkey. Retry the status check first.',
      } })
      return
    }
    const s = this.deps.auth.current()
    if (!s) {
      this.update({ passkey: { registering: false, registered: this.view.passkey.registered, error: 'session expired — sign in again' } })
      return
    }
    // Any GET already in flight describes the state before this mutation and must not win afterward.
    this.passkeyStatusGeneration++
    this.update({ passkey: { ...this.view.passkey, registering: true, error: null, stage: undefined } })
    const authGen = this.captureAuthGen()
    const abort = new AbortController()
    this.passkeyRegistrationAbort?.abort()
    this.passkeyRegistrationAbort = abort
    try {
      const registration = await this.deps.registerAccountPasskey(
        s.credential,
        {
          accountId: s.accountId,
          signal: abort.signal,
          onStage: (stage) => {
            if (
              this.authGenChanged(authGen) ||
              abort.signal.aborted ||
              this.passkeyRegistrationAbort !== abort
            ) return
            this.update({ passkey: { ...this.view.passkey, stage } })
          },
        },
      )
      if (this.authGenChanged(authGen)) return // logged out / switched account mid-ceremony
      this.passkeyStatusGeneration++ // invalidate a status read started during the ceremony
      if (registration.revokedDesktopCount > 0) this.backToDevices({ refreshPasskey: false })
      this.update({
        ...(registration.revokedDesktopCount > 0 ? { devices: [] } : {}),
        passkey: {
          registering: false,
          registered: true,
          replacing: false,
          status: 'present',
          credentialId: registration.credentialId,
          createdAtMs: registration.createdAtMs,
          generation: registration.generation,
          error: null,
          stage: undefined,
          notice: registration.revokedDesktopCount === 0
            ? 'Passkey created.'
            : registration.revokedDesktopCount === 1
              ? 'Passkey created. Re-enroll your desktop.'
              : `Passkey created. Re-enroll your ${registration.revokedDesktopCount} desktops.`,
        },
      })
    } catch (error) {
      if (this.authGenChanged(authGen)) return
      this.passkeyStatusGeneration++
      const detail = safeMessage(error instanceof Error ? error.message : String(error))
      this.update({
        passkey: {
          ...this.view.passkey,
          registering: false,
          registered: this.view.passkey.registered,
          error: detail || 'passkey setup failed — try again',
          stage: undefined,
        },
      })
    } finally {
      if (this.passkeyRegistrationAbort === abort) this.passkeyRegistrationAbort = null
    }
  }

  async replacePasskey(): Promise<void> {
    if (!this.deps.replaceAccountPasskey || this.view.passkey.replacing) return
    const s = this.deps.auth.current()
    if (!s) {
      this.update({ passkey: { ...this.view.passkey, error: 'session expired — sign in again' } })
      return
    }
    const credentialId = this.view.passkey.credentialId
    const generation = this.view.passkey.generation
    if (!credentialId || typeof generation !== 'number' || !Number.isSafeInteger(generation) || generation < 1) {
      this.update({ passkey: {
        ...this.view.passkey,
        error: 'Passkey security metadata is incomplete. Refresh its status before replacing it.',
      } })
      return
    }
    // A stale pre-recovery GET describes the old generation and must never overwrite a successful atomic swap.
    this.passkeyStatusGeneration++
    this.update({ passkey: {
      ...this.view.passkey,
      replacing: true,
      error: null,
      notice: undefined,
      stage: undefined,
    } })
    const authGen = this.captureAuthGen()
    const abort = new AbortController()
    this.passkeyReplacementAbort?.abort()
    this.passkeyReplacementAbort = abort
    try {
      const replacement = await this.deps.replaceAccountPasskey(
        s.credential,
        { credentialId, generation },
        {
          accountId: s.accountId,
          signal: abort.signal,
          onStage: (stage) => {
            if (
              this.authGenChanged(authGen) ||
              abort.signal.aborted ||
              this.passkeyReplacementAbort !== abort
            ) return
            this.update({ passkey: { ...this.view.passkey, stage } })
          },
        },
      )
      if (this.authGenChanged(authGen)) return
      this.passkeyStatusGeneration++ // invalidate reads started while recovery was in flight
      // Reuse the canonical intentional-leave lifecycle: stop reconnect/watchdog timers, close every renderer
      // channel, clear resume hints, re-arm future connections, and restart device-list polling. Merely closing the
      // current session leaves a scheduled reconnect able to race the just-revoked desktop trust.
      // The replacement response is the authoritative new anchor. Do not immediately start another GET from the
      // generic Back path: a lagging replica could return the old generation and overwrite this committed result.
      this.backToDevices({ refreshPasskey: false })
      this.update({
        devices: [],
        passkey: {
          registering: false,
          registered: true,
          replacing: false,
          status: 'present',
          credentialId: replacement.credentialId,
          createdAtMs: replacement.createdAtMs,
          generation: replacement.generation,
          error: null,
          stage: undefined,
          notice: replacement.revokedDesktopCount === 0
            ? 'Replacement passkey created.'
            : replacement.revokedDesktopCount === 1
              ? 'Replacement passkey created. Re-enroll your desktop.'
              : `Replacement passkey created. Re-enroll your ${replacement.revokedDesktopCount} desktops.`,
        },
      })
    } catch (error) {
      if (this.authGenChanged(authGen)) return
      this.passkeyStatusGeneration++
      // Create cancellation, verification failure, and transaction failure are non-destructive: retain current
      // metadata, desktop inventory, session, and phase. Only the recoverable action error changes.
      this.update({ passkey: {
        ...this.view.passkey,
        replacing: false,
        error: safeMessage(error instanceof Error ? error.message : String(error)),
        stage: undefined,
      } })
    } finally {
      if (this.passkeyReplacementAbort === abort) this.passkeyReplacementAbort = null
    }
  }

  /** Refresh whether the account already has a passkey (so the panel shows "registered" vs "set up"). */
  async refreshPasskeyStatus(
    session: { accountId: string; credential: string } | null = this.deps.auth.current(),
  ): Promise<void> {
    if (!this.deps.hasAccountPasskey) return
    if (!session) return
    const authGen = this.captureAuthGen()
    const statusGen = ++this.passkeyStatusGeneration
    if (this.view.accountId === session.accountId) {
      this.update({ passkey: { ...this.view.passkey, status: 'loading' } })
    }
    try {
      const result = await this.deps.hasAccountPasskey(session.credential)
      if (
        this.authGenChanged(authGen) ||
        statusGen !== this.passkeyStatusGeneration ||
        this.view.accountId !== session.accountId
      ) return
      const metadata = typeof result === 'object' ? result : null
      this.update({ passkey: {
        ...this.view.passkey,
        registered: !!result,
        status: result ? 'present' : 'absent',
        credentialId: metadata?.credentialId,
        createdAtMs: metadata?.createdAtMs,
        generation: metadata?.generation,
        notice: undefined,
      } })
    } catch {
      if (
        this.authGenChanged(authGen) ||
        statusGen !== this.passkeyStatusGeneration ||
        this.view.accountId !== session.accountId
      ) return
      // Unavailable is distinct from absent: fail closed and do not offer a replacement registration based on
      // a network/401/500 error. Keep last-known `registered` metadata for an honest degraded-state display.
      this.update({ passkey: { ...this.view.passkey, status: 'unavailable' } })
    }
  }

  // ---- device revoke (Login ≠ terminal access: revoke cuts live + future access) ----

  /** Begin revoking a desktop: ask for confirmation first (this controls remote-machine access). */
  confirmRevoke(deviceId: string): void {
    if (this.view.revoke.pendingDeviceId) return // a revoke is in flight — ignore
    this.update({ revoke: { confirmingDeviceId: deviceId, pendingDeviceId: null, error: null } })
  }

  /** Cancel a pending confirmation. */
  cancelRevoke(): void {
    if (this.view.revoke.pendingDeviceId) return
    this.update({ revoke: { confirmingDeviceId: null, pendingDeviceId: null, error: null } })
  }

  /** Execute the revoke after confirmation. On success the device is removed from the active list; on
   * failure the device stays visible with a recoverable error. */
  async revokeDesktop(deviceId: string): Promise<void> {
    if (this.view.revoke.pendingDeviceId) return // guard double-submit
    const s = this.deps.auth.current()
    if (!s) {
      this.update({ revoke: { confirmingDeviceId: null, pendingDeviceId: null, error: 'session expired — sign in again' } })
      return
    }
    this.update({ revoke: { confirmingDeviceId: deviceId, pendingDeviceId: deviceId, error: null } })
    const authGen = this.captureAuthGen()
    let ok = false
    try {
      ok = await this.deps.revokeDevice(s.credential, deviceId)
    } catch {
      ok = false
    }
    // Abort applying the result if the account context changed mid-revoke (logout / switch) — otherwise a
    // stale revoke could mutate account B's device list.
    if (this.authGenChanged(authGen)) return
    if (ok) {
      // remove the revoked device from the active list (the cloud now refuses its token mint + signaling).
      const devices = this.view.devices.filter((d) => d.deviceId !== deviceId)
      this.update({ devices, revoke: { confirmingDeviceId: null, pendingDeviceId: null, error: null } })
    } else {
      this.update({ revoke: { confirmingDeviceId: null, pendingDeviceId: null, error: 'could not remove that desktop — try again' } })
    }
  }

  async connectTo(targetDeviceId: string, options: ConnectOptions = {}): Promise<void> {
    // A controller has exactly one connection owner. Invalidate callbacks first, then close the previous peer so
    // its synchronous `closed` event and any queued late events cannot mutate this new attempt. This is also the
    // last line of defence when a caller opens desktop B without first using the canonical Back-to-Desktops path.
    this.finishActiveConnectionMetric('superseded')
    const previousTarget = this.view.selectedDevice
    const connectionGen = ++this.connectionGeneration
    // Revoke timer ownership at the same boundary as transport callbacks. clearTimeout prevents future dispatch;
    // the generation captured by each callback below also makes an already-queued callback inert.
    this.clearConnectWatchdog()
    this.clearSessionListWatchdog()
    this.clearAttachWatchdogs()
    this.clearPaneSwitchWatchdog()
    this.cancelWinsizeRefresh()
    this.cancelPaneHydrationState()
    this.pendingWireAttaches.clear()
    this.abandonedPendingAttaches.clear()
    const previousSession = this.session
    this.session = null
    previousSession?.close()
    const abandonedMutations = this.abandonRemoteCreations()
    for (const attempt of abandonedMutations) this.rollbackPendingSplitPane(attempt.splitPaneId)
    if (previousTarget && previousTarget !== targetDeviceId) this.resumeSessionId = null
    const ownsConnection = () => this.connectionGeneration === connectionGen
    this.restoredLayoutThisConnect = false // re-arm the one-time saved-layout restore for this connect
    this.layoutHydrated = false // and re-gate persistence until that restore's continuation hydrates the map
    this.knownProjectIds = new Set() // R8/R13: the ledger re-seeds from the restored cloud row + reconciles
    this.knownWindowIds = new Set()
    this.knownPaneIds = new Set()
    this.pendingLandingWindows = new Set() // R7: landing-pending designations re-derive per connect too
    this.pendingSelfCreated = new Map() // R7: creation completions never survive a reconnect
    this.recentlyCreatedSessions = new Map() // fresh connection → fresh session_list baseline, no stale-list guard
    this.attachAutoRetried = new Set() // recovery one-shots re-arm per connection
    this.deferredAgentSessionRefresh = false // auth below re-arms one optional inventory pass for this owner
    this.deferredAgentSessionFolderRefreshes.clear()
    this.activeProjectIdHint = null // eviction hint re-derives from the fresh connect's reconciles
    this.focusedWindowByProject.clear() // window ids and ownership are scoped to the selected desktop
    this.traceId = mintTraceId() // fresh correlation id for this connect attempt (threaded to the agent/cloud)
    connTrace.log(this.traceId, 'connect', 'start', 'pending', `device=${short(targetDeviceId)}`)
    connTrace.log(this.traceId, 'connect', 'browser_build', 'ok', buildStamp()) // stamp → drift visible vs agent_build
    const s = this.deps.auth.current()
    if (!s) {
      connTrace.log(this.traceId, 'connect', 'no_session', 'error', 'not signed in')
      this.update({ phase: 'signed_out' })
      return
    }
    const attemptMetric = beginConnectionAttempt(options.trigger ?? 'user')
    this.activeConnectionMetric = { generation: connectionGen, recorder: attemptMetric }
    const authGen = this.captureAuthGen() // abort if logout/account-switch happens during the async connect
    this.createSessionIfEmpty = options.createSessionIfEmpty
      ? { targetDeviceId, ...options.createSessionIfEmpty }
      : null
    this.clearReconnectTimer() // a connect supersedes any pending backoff
    this.update({
      phase: 'connecting',
      terminalAcquisition: 'connecting',
      selectedDevice: targetDeviceId,
      error: null,
      sessions: [],
      lastSessionListAtMs: undefined,
      lastOpenedSessionId: this.loadLastOpenedFor(targetDeviceId),
      sessionLabels: this.loadLabelsFor(targetDeviceId),
      sessionCwds: {},
      workspaceMetadata: null,
      favoriteSessions: this.loadFavoritesFor(targetDeviceId),
      sessionOrder: this.loadOrderFor(targetDeviceId),
      hiddenSessions: this.loadHiddenFor(targetDeviceId),
      connectionMode: 'unknown',
      diagnostics: defaultDiagnostics(),
      agentBuildGit: null,
      desktopAccess: UNKNOWN_DESKTOP_ACCESS,
      creatingSession: false,
      createSessionError:
        this.view.createSessionError === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
          ? null
          : this.view.createSessionError,
      desktopActionMessage:
        this.view.desktopActionMessage === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
          ? null
          : this.view.desktopActionMessage,
    })
    this.persistHints() // remember the selected desktop for resume
    this.armConnectWatchdog(connectionGen) // guard against a silent stall in `connecting`
    const connectDeadline = this.connectDeadline?.deadline
    if (!connectDeadline) return

    // Production preparation performs ONLY browser-device enrollment/account-ownership checks. It deliberately does
    // not mint a token: the WebRTC bridge creates signaling first and then mints the one authoritative token bound
    // to that exact source/target/session. Explicit legacy/fake transports retain their constructor-token seam, but
    // the two paths are a type-level exclusive choice and production can never downgrade into the legacy token.
    const requiresSessionBoundToken = !!this.deps.prepareConnection
    let constructorToken = ''
    if (this.deps.prepareConnection) {
      try {
        connTrace.log(this.traceId, 'connect', 'browser_prepare', 'pending')
        await this.deps.prepareConnection(s.credential, targetDeviceId, connectDeadline.signal)
        if (this.authGenChanged(authGen) || !ownsConnection()) {
          attemptMetric.finish('superseded')
          connTrace.log(this.traceId, 'connect', 'browser_prepare_stale', 'error', 'account changed during preparation')
          return
        }
        connectDeadline.progress('controller:browser-device-ready')
        attemptMetric.recordPhase('preparation_ready')
        connTrace.log(this.traceId, 'connect', 'browser_ready', 'ok')
      } catch {
        if (!ownsConnection() || connectDeadline.signal.aborted) return
        attemptMetric.finish('control_plane_failure')
        connTrace.log(this.traceId, 'connect', 'browser_prepare_failed', 'error', 'enrollment unavailable')
        this.update({ phase: 'offline', authState: 'idle', error: 'browser enrollment failed', nextRetryAtMs: undefined })
        this.scheduleReconnect()
        return
      }
    } else {
      try {
        connTrace.log(this.traceId, 'connect', 'legacy_token_mint', 'pending')
        constructorToken = await this.deps.legacyMintToken(s.credential, targetDeviceId, connectDeadline.signal)
        if (this.authGenChanged(authGen) || !ownsConnection()) {
          attemptMetric.finish('superseded')
          connTrace.log(this.traceId, 'connect', 'legacy_token_stale', 'error', 'account changed during mint')
          return
        }
        connectDeadline.progress('controller:legacy-constructor-token')
        connTrace.log(this.traceId, 'connect', 'legacy_token_ok', 'ok')
      } catch (e) {
        if (!ownsConnection() || connectDeadline.signal.aborted) return
        attemptMetric.finish(tokenMetricOutcome(e))
        connTrace.log(this.traceId, 'connect', 'legacy_token_failed', 'error', tokenMintReason(e))
        this.update({ phase: 'offline', authState: 'refused', error: 'token refresh failed', nextRetryAtMs: undefined })
        this.scheduleReconnect()
        return
      }
      // Defense-in-depth for the explicit legacy constructor-token path. Opaque/non-JWT tokens still pass because
      // the legacy agent remains authoritative; a clearly expired/wrong-device JWT is never presented.
      const scope = validateTokenScope(constructorToken, targetDeviceId, Date.now())
      if (!scope.ok) {
        attemptMetric.finish('auth_refused')
        this.update({ phase: 'offline', authState: 'refused', error: `token refresh failed (${scope.reason})`, nextRetryAtMs: undefined })
        this.scheduleReconnect()
        return
      }
    }
    const targetDevicePublicKeyB64 = this.view.devices.find((d) => d.deviceId === targetDeviceId)?.publicKey ?? null
    let transportRetired = false
    const ownsLiveTransport = () => ownsConnection() && !transportRetired
    const { transport, connect } = this.deps.makeTransport(
      targetDeviceId,
      (mode) => { if (ownsLiveTransport()) this.update({ connectionMode: mode }) },
      targetDevicePublicKeyB64,
      connectDeadline,
    )
    // A production preparation with a transport that cannot expose its freshly session-bound token is a wiring
    // error, not permission to reuse a constructor token. Stop before peer setup or terminal authentication.
    if (requiresSessionBoundToken && typeof transport.currentToken !== 'function') {
      attemptMetric.finish('auth_refused')
      connTrace.log(this.traceId, 'connect', 'bound_token_contract_missing', 'error', 'transport misconfigured')
      this.completeConnectWatchdog()
      transport.close()
      this.update({ phase: 'error', authState: 'refused', error: 'secure transport is unavailable' })
      return
    }
    // S3c-browser-smoke: surface the transport's diagnostics into the view (no secrets/bytes).
    transport.onDiagnostics?.((d) => {
      if (!ownsLiveTransport()) return
      this.noteConnectDiagnostics(connectionGen, d)
      attemptMetric.recordDiagnostics(d)
      this.update({ diagnostics: d })
    })
    transport.onConnectionPhase?.((phase: ConnectionAttemptPhase) => {
      if (ownsLiveTransport()) attemptMetric.recordPhase(phase)
    })
    const deviceId = await this.deps.identity.deviceId()
    if (!ownsConnection()) {
      attemptMetric.finish('superseded')
      transport.close()
      return
    }
    connectDeadline.progress('controller:device-identity')
    attemptMetric.recordPhase('identity_ready')
    this.multiAttach.clear()
    // A fresh connection has NO attaches in flight: drop the previous connection's pending-attach markers so the
    // in-flight dedupe in attach()/attachPlacedPanes() can never suppress this connection's focused resume attach.
    this.clearAttachWatchdogs()
    this.multiPaneTerminal = new MultiPaneTerminalSession()
    // Mark unread activity when a NON-active pane paints (content-blind: id only). The active pane is "read".
    this.multiPaneTerminal.setActivityObserver((sessionId) => this.noteSessionActivity(sessionId))
    this.multiPaneTerminal.setActiveSessionProvider(
      () => activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession,
    )
    this.multiPaneTerminal.setProgressObserver((sessionId) => this.noteAttachProgress(sessionId))
    this.multiPaneTerminal.setMaterializationObserver((sessionId) => {
      this.noteAttachMaterialized(sessionId, this.multiPaneTerminal.gridBounds(sessionId)?.rows)
    })
    this.multiPaneTerminal.setScrollbackReplyObserver((sessionId, offset, accepted) => {
      // A stale-generation/cross-session reply did not populate the cache and therefore cannot complete the
      // active pane's initial-history gate. Keep its bounded inactivity/absolute timers in charge instead.
      this.noteScrollbackReply(sessionId, offset, accepted)
    })
    this.multiPaneTerminal.setGridObserver((sessionId, grid) => {
      if (sessionId === this.view.attachedSession) {
        this.gridSnapshotHandler?.(grid)
      }
    })
    this.multiPaneOutputEnabled = false
    // New connection → the agent restarts its per-connection push epoch at 0; reset our applied-epoch guard to match,
    // else the first push (epoch 1) after reconnect would be ignored as "not newer".
    this.lastAppliedWorkspaceEpoch = 0

    const remoteSession = new RemoteSession(connectionOwnedTransport(transport, ownsLiveTransport), constructorToken, deviceId, {
      onAgentBuild: (git) => {
        if (ownsLiveTransport()) this.update({ agentBuildGit: git })
      },
      onDesktopAccessStatus: (status) => {
        if (!ownsLiveTransport()) return
        const desktopAccess: DesktopAccessView = {
          platform: status.platform,
          fullDiskAccess: status.full_disk_access,
        }
        if (status.platform === 'macos' && status.full_disk_access === 'required') {
          this.update({
            desktopAccess,
            desktopActionMessage: MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE,
          })
          return
        }
        if (status.full_disk_access === 'granted') {
          this.update({
            desktopAccess,
            desktopActionMessage: this.view.desktopActionMessage === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
              ? null
              : this.view.desktopActionMessage,
            createSessionError: this.view.createSessionError === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
              ? null
              : this.view.createSessionError,
            agentSessionManageError:
              this.view.agentSessionManageError === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
                ? null
                : this.view.agentSessionManageError,
            error: this.view.error === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE ? null : this.view.error,
            directoryBrowser: this.view.directoryBrowser?.error === MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
              ? { ...this.view.directoryBrowser, error: undefined }
              : this.view.directoryBrowser,
          })
          return
        }
        this.update({ desktopAccess })
      },
      onState: (st) => {
        if (
          st === 'revoked' ||
          st === 'authorization_required' ||
          st === 'entitlement_required' ||
          st === 'access_required' ||
          st === 'offline' ||
          st === 'auth_refused' ||
          st === 'error' ||
          st === 'closed'
        ) {
          // The connection generation remains stable during reconnect backoff so resume metadata survives. Retire
          // this transport separately before publishing its terminal state: already-queued mode/diagnostic
          // callbacks from the dead peer must not repopulate the staging evidence strip after it was cleared.
          transportRetired = true
        }
        if (st === 'authenticated') attemptMetric.recordPhase('control_auth_ok')
        const outcome = controlStateMetricOutcome(st)
        if (outcome) attemptMetric.finish(outcome)
        this.onControlState(st)
      },
      onSessions: (sessions, metadata = [], workspaceMetadata = null) => {
        // Startup race guard: an older/racing agent can deliver workspace_update before the first session_list
        // reply. That push is newer than the stale list reply, so the first list must not erase the pushed project
        // tree/sessions; otherwise a freshly created project appears grey/dead until manual refresh.
        const preservePreBaselinePush =
          this.lastAppliedWorkspaceEpoch > 0 &&
          this.view.lastSessionListAtMs === undefined &&
          this.view.workspaceMetadata !== null
        // AUTHORITATIVE-CREATION GUARD: a list snapshot that predates a just-committed remote creation
        // (split/create seed) must not erase the session its ok-reply named — see recentlyCreatedSessions.
        const effectiveSessions = this.mergeRecentlyCreated(
          preservePreBaselinePush ? Array.from(new Set([...sessions, ...this.view.sessions])) : sessions,
        )
        const effectiveWorkspaceMetadata = preservePreBaselinePush
          ? this.view.workspaceMetadata
          : workspaceMetadata
        // Content-blind counts (ids/shapes only, no terminal data) so a connection-log dump shows whether the metadata
        // itself is missing a window/pane (agent side) vs the browser dropping it (reconcile/render).
        const wm = effectiveWorkspaceMetadata
        const winCount = wm?.projects?.reduce((n, p) => n + (p.windows?.length ?? 0), 0) ?? 0
        const paneCount = wm?.projects?.reduce((n, p) => n + (p.windows?.reduce((m, w) => m + (w.panes?.length ?? 0), 0) ?? 0), 0) ?? 0
        connTrace.log(this.traceId, 'session_list', 'reply', 'ok', `${effectiveSessions.length} sessions, ${wm?.projects?.length ?? 0} projects, ${winCount} windows, ${paneCount} panes`)
        this.clearSessionListWatchdog() // session_list arrived → we're no longer stuck on "Loading its projects…"
        // Detect BEFORE pruning: did the recent-session marker the user currently sees just disappear?
        const recentSessionEnded = this.recentSessionJustEnded(effectiveSessions)
        const lastOpenedSessionId = this.pruneLastOpenedFor(targetDeviceId, effectiveSessions)
        const favoriteSessions = this.pruneFavoritesFor(targetDeviceId, effectiveSessions)
        const sessionOrder = this.pruneOrderFor(targetDeviceId, effectiveSessions)
        const hiddenSessions = this.pruneHiddenFor(targetDeviceId, effectiveSessions)
        const knownSessionsByDevice = this.saveKnownSessionsFor(targetDeviceId, effectiveSessions)
        // drop unread flags for sessions the desktop no longer reports (ended/closed while away).
        const unreadSessions = this.view.unreadSessions.filter((id) => effectiveSessions.includes(id))
        this.update({
          phase: 'sessions',
          // Only a connect/attach that ALREADY owns acquisition may advance to Loading. Later authoritative
          // session-list refreshes while the user is stably browsing Settings/Terminal must never re-arm it.
          terminalAcquisition: this.view.terminalAcquisition === null ? null : 'loading',
          sessions: effectiveSessions,
          sessionCwds: sessionCwdsFromMetadata(effectiveSessions, metadata),
          workspaceMetadata: effectiveWorkspaceMetadata,
          lastSessionListAtMs: Date.now(),
          lastOpenedSessionId,
          recentSessionEnded,
          sessionLabels: this.loadLabelsFor(targetDeviceId),
          favoriteSessions,
          sessionOrder,
          hiddenSessions,
          knownSessionsByDevice,
          unreadSessions,
        })
        // Existence-sync (pane existence contract, Task #600): every local pane that EXISTS becomes
        // browser-STASHED unless the browser already placed it; panes killed on local are dropped. ADDITIVE —
        // the placed grid the user built is preserved (only NEW panes go to stashed). First connect → all local
        // panes land stashed, the grid stays on its single default pane. Runs BEFORE bindDefault/resume so those
        // still drive the placed grid as before.
        // Restore the durable per-window layout from the cloud ONCE per connect, BEFORE reconcile, so the DB placement
        // is the `before` state and reconcileExistence KEEPS live panes placed (its delta only stashes NEW sessions +
        // drops GONE ones). Slice 2 ordering (pane lifecycle contract): while the restore is pending
        // it OWNS the whole connect tail — reconcile + default bind + resume all run inside its continuation, against
        // the HYDRATED layout (this removes the bind-vs-restore race the old note here documented; the adoption merge
        // in reconcilePaneExistence stays as a belt). Once hydrated (or when there's nothing to restore — no cloud dep
        // / no metadata), later lists run the same tail synchronously as before.
        const handledByRestore = this.restoreLayoutFromCloud(effectiveWorkspaceMetadata)
        if (!handledByRestore) {
          this.reconcilePaneExistence(effectiveWorkspaceMetadata)
          // Dashboard parity: on a FRESH connect with live sessions but nothing to resume (no prior pane/resume
          // state), pre-bind the active pane to a sensible default — the last-opened session if still live, else
          // the first visible one. resumePanes() then attaches it, so the user lands ON a session like the
          // desktop app instead of staring at a list. (No-op when a session is already bound/resumed, or none are
          // visible — e.g. all hidden — so "New session" stays the path when there's genuinely nothing to show.)
          this.bindDefaultSessionIfIdle(effectiveSessions, lastOpenedSessionId)
          this.resumePanes(effectiveSessions)
        }
        this.createInitialSessionIfRequested(targetDeviceId, effectiveSessions)
        // A synchronous connect tail either armed a real attach/create or proved there is nothing to acquire.
        // The async layout-restore tail owns this decision until finishLayoutRestore() runs.
        if (!handledByRestore) {
          this.settleTerminalAcquisitionIfIdle()
          this.scheduleStartupHydrationOrHistory()
        }
      },
      onWorkspaceUpdate: (epoch, workspaceMetadata, sessions) => {
        // Live-sync push: the desktop's workspace changed while we're attached — refresh the sidebar/tree WITHOUT a
        // page refresh. Ordering guard: apply only a NEWER epoch (a reliable-ordered channel + monotonic epoch means
        // a late re-push can't clobber a newer applied one). The apply is the SAME idempotent tail as onSessions:
        // update view.workspaceMetadata + reconcilePaneExistence (additive, content-blind). No session-list churn
        // (favorites/order/resume) — this is a workspace-tree delta only.
        if (epoch <= this.lastAppliedWorkspaceEpoch) return
        this.lastAppliedWorkspaceEpoch = epoch
        const wm = workspaceMetadata
        const winCount = wm?.projects?.reduce((n, p) => n + (p.windows?.length ?? 0), 0) ?? 0
        const paneCount = wm?.projects?.reduce((n, p) => n + (p.windows?.reduce((m, w) => m + (w.panes?.length ?? 0), 0) ?? 0), 0) ?? 0
        connTrace.log(this.traceId, 'workspace_update', 'push', 'ok', `epoch ${epoch}, ${wm?.projects?.length ?? 0} projects, ${winCount} windows, ${paneCount} panes`)
        // Self-sufficient push: adopt the live session list it carried. Without this, a session
        // created on the desktop existed in the pushed TREE but not in view.sessions — so clicking
        // its pane silently no-op'd (every attach path guards on sessions.includes) until a manual
        // refresh re-ran session_list. `sessions` null = older agent build → keep the current list.
        // A push is post-commit truth (see settleRecentlyCreatedFromPush): apply its session list as-is
        // and settle any recently-created guard entries it decides.
        if (sessions) this.settleRecentlyCreatedFromPush()
        this.update(sessions ? { workspaceMetadata, sessions } : { workspaceMetadata })
        this.reconcilePaneExistence(workspaceMetadata)
      },
      onDebugSyncSnapshot: (requestId, agent) => {
        const resolve = this.syncDebugWaiters.get(requestId)
        this.syncDebugWaiters.delete(requestId)
        resolve?.(agent)
      },
      shouldAcceptAttach: (sid) => {
        this.pendingWireAttaches.delete(sid)
        const placed = leaves(this.view.paneLayout.root).some((leaf) => leaf.sessionId === sid)
        const abandoned = this.abandonedPendingAttaches.delete(sid)
        const intentionallyDetached = this.intentionalDetachGeneration === this.connectionGeneration
        if (!placed || abandoned || intentionallyDetached) {
          if (this.backgroundAttachInFlight === sid) this.backgroundAttachInFlight = null
          this.pendingOwnershipReassert.delete(sid)
          this.clearAttachLifecycle(sid, true)
          this.settleTerminalAcquisitionIfIdle()
          this.schedulePaneHydration()
          return false
        }
        return true
      },
      onAttached: (sid, channel) => {
        this.clearPaneSwitchWatchdog(sid)
        this.baselineReattachPending.delete(sid) // recovery attach landed → future resyncs may re-request
        this.multiAttach.onAttached(sid, channel)
        this.multiPaneTerminal.attachPane(channel, sid)
        // Attach completions can still arrive after focus changes. A blind `attachedSession: sid` would let the
        // last completion steal the visible/input target. Prefer the ACTIVE pane once its channel is proven.
        const active = activeLeaf(this.view.paneLayout).sessionId
        const activeChannel = active ? this.multiAttach.channelForSession(active) : null
        if (active && activeChannel !== null) {
          this.multiAttach.setActive(active)
          this.session?.setActiveAttach(active, activeChannel)
        } else {
          // The viewed pane is still attaching. Demote the just-landed background channel immediately so its
          // decode cannot occupy the foreground lane while the viewed attach catches up.
          this.session?.setViewedChannel(null)
        }
        // Do not let a background attach_ok visually replace the pane the user chose while that pane's own
        // attach is still in flight. Input is separately gated on the active pane having a channel.
        this.update({ phase: 'terminal', attachedSession: active, terminalAcquisition: null })
        if (this.pendingOwnershipReassert.has(sid) && active === sid) {
          const size = this.measuredWinsizes.get(sid) ?? this.lastAttachSize
          this.session?.resizeSession(sid, size.cols, size.rows, true)
          this.pendingOwnershipReassert.delete(sid)
        } else if (active !== sid) {
          // This request was foreground when sent but focus moved before attach_ok. The newer focused pane's
          // ordered viewed resize is authoritative; never retain a stale reassert that could later steal it back.
          this.pendingOwnershipReassert.delete(sid)
        }
        if (this.winsizeRefreshAfterAttach.delete(sid)) this.refreshSessionAfterFirstWinsizeFrame(sid)
        this.schedulePaneHydration()
      },
      // Redact at the BOUNDARY: the agent-supplied `message` is untrusted free text — scrub any token/cookie/
      // key/JWT/oversized material BEFORE it enters view.error (don't rely only on the render layer). `code` is
      onWinsizeOwnerChanged: (owner) => {
        // Reflect the AGENT's effective owner (it applies serving>0 + the 10s grace) so the toggle shows the truth,
        // e.g. reverts to 'local' when the connection drops past the grace even though we optimistically set 'remote'.
        if (owner === 'local') this.cancelAllWinsizeSettleRepushes()
        if (this.view.winsizeOwner !== owner) this.update({ winsizeOwner: owner })
      },
      // an enum-ish protocol code; the message is bounded + scrubbed.
      onError: (code, message, correlation) => {
        let retiredAbandonedAttach = false
        const legacySinglePending = correlation === undefined &&
          LEGACY_UNAMBIGUOUS_ATTACH_ERROR_CODES.has(code) &&
          this.pendingWireAttaches.size === 1
          ? [...this.pendingWireAttaches][0]!
          : null
        const rejectedSession = correlation?.requestId && correlation.sessionId
          ? correlation.sessionId
          : legacySinglePending
        if (
          rejectedSession &&
          CORRELATED_ATTACH_ERROR_CODES.has(code) &&
          this.pendingWireAttaches.delete(rejectedSession)
        ) {
          if (this.backgroundAttachInFlight === rejectedSession) this.backgroundAttachInFlight = null
          this.pendingOwnershipReassert.delete(rejectedSession)
          retiredAbandonedAttach = this.abandonedPendingAttaches.delete(rejectedSession)
          this.clearAttachLifecycle(rejectedSession, true)
          if (
            this.view.attachedSession === rejectedSession &&
            this.multiAttach.channelForSession(rejectedSession) === null
          ) {
            this.update({ phase: 'sessions', attachedSession: null })
          }
          this.settleTerminalAcquisitionIfIdle()
          this.schedulePaneHydration()
        }
        // A generic agent error (bad_message / forbidden_field / too_large) while the folder browser is loading
        // means the request was rejected — most commonly a STALE desktop agent that predates list_directories and
        // can't parse it. Clear the spinner + show it IN the folder browser instead of an infinite spinner.
        const browser = this.view.directoryBrowser
        if (browser?.loading) {
          this.clearDirectoryBrowserTimer()
          const hint = code === MACOS_FULL_DISK_ACCESS_REQUIRED_CODE
            ? MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
            : code === 'bad_message'
            ? 'The desktop agent didn’t understand the folder request — it’s likely out of date. Restart the desktop agent from the latest checkout, then Refresh.'
            : `Folder browser error (${code}). Restart the desktop agent from the latest checkout, then Refresh.`
          this.update({ directoryBrowser: { ...browser, loading: false, error: hint } })
        }
        // The user already abandoned this request; its correlated rejection is cleanup, not a new product error.
        if (retiredAbandonedAttach) return
        this.update({
          error: code === MACOS_FULL_DISK_ACCESS_REQUIRED_CODE
            ? MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
            : `${code}: ${safeMessage(message)}`,
        })
      },
      // Slice E "New session": on created → attach it (drops the user into the terminal); on error → show a
      // friendly message on the sessions list, clear the pending flag.
      onSessionCreated: (sid, label, requestId) => {
        const attempt = this.takeRemoteCreation(requestId, 'create-session')
        if (!attempt) return
        this.noteCreatedSession(sid) // authoritative: a stale list snapshot must not erase it
        // F1: remember the label for this session id (the agent echoes back the sanitized label) so the
        // sessions list + terminal header can show it. Falls back to the id when absent.
        const labels = label ? { ...this.view.sessionLabels, [sid]: label } : this.view.sessionLabels
        this.saveLabelsForCurrentDesktop(labels)
        // F2: clear the input on success (a failed create leaves newSessionLabel intact for retry).
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: null, sessionLabels: labels, newSessionLabel: '' })
        this.attach(
          sid,
          attempt.geometry.cols,
          attempt.geometry.rows,
          attempt.targetPaneId,
          attempt.expectedTargetSessionId,
        )
      },
      onSessionCreateError: (code, _message, requestId) => {
        const attempt = this.takeRemoteCreation(requestId, 'create-session')
        if (!attempt) return
        this.rollbackPendingSplitPane(attempt.splitPaneId)
        this.update({
          creatingSession: false,
          createSessionError: createSessionMessage(code),
          terminalAcquisition: null,
        })
        this.scheduleStartupHydrationOrHistory()
      },
      onSplitPaneOk: (sid, tabId, requestId) => {
        const pending = this.pendingRemoteCreations.get(requestId)
        if (pending?.kind !== 'split-pane' && pending?.kind !== 'new-pane') return
        const attempt = this.takeRemoteCreation(requestId, pending.kind)
        if (!attempt) return
        connTrace.log(this.traceId, 'split', 'ok', 'ok', `sid=${short(sid)}`)
        this.noteCreatedSession(sid) // authoritative: the listSessions() below may still reply a PRE-COMMIT snapshot
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Split pane created.' })
        this.session?.listSessions()
        if (attempt.kind === 'split-pane') {
          // IDENTITY UPGRADE (single id-space, BUG-1 fix): the reserved optimistic leaf adopts the DESKTOP tab id
          // the split created, and any session-less stash row the redaction-race push minted for that desktop pane
          // is dropped — one pane, one identity. Without this the browser kept TWO records of the split result
          // (a `pane-N` placed leaf + a `{tabId, null}` stash row): a phantom "Empty pane" stash row forever, and
          // a refresh restored the dead shape (empty leaf + grey row — "the new pane never appears").
          this.adoptSplitReserve(attempt, tabId)
          this.attach(
            sid,
            attempt.geometry.cols,
            attempt.geometry.rows,
            attempt.targetPaneId,
            attempt.expectedTargetSessionId,
          )
        } else {
          // `new_pane` has no optimistic browser reserve. It creates a desktop pane and the next
          // session_list/workspace_update names its real desktop pane id. Do not attach into the
          // old active pane here; queue the self-created placement so metadata places it once under
          // the correct pane id, exactly like new-window/project-create seeded panes.
          this.noteSelfCreatedSession(sid, attempt.geometry)
        }
      },
      onSplitPaneError: (code, message, requestId) => {
        const pending = this.pendingRemoteCreations.get(requestId)
        if (pending?.kind !== 'split-pane' && pending?.kind !== 'new-pane') return
        const attempt = this.takeRemoteCreation(requestId, pending.kind)
        if (!attempt) return
        connTrace.log(this.traceId, 'split', 'error', 'error', code)
        // UNDO the browser-grid split made for this request: the desktop refused (e.g. its window already has
        // 4 live panes), so the empty pane reserved for the new session must not linger as a stray tile.
        this.rollbackPendingSplitPane(attempt.splitPaneId)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Split pane failed', code, message) })
      },
      onRevivePaneOk: (sid, requestId) => {
        const attempt = this.takeRemoteCreation(requestId, 'revive-pane')
        if (!attempt) return
        connTrace.log(this.traceId, 'revive', 'ok', 'ok', `sid=${short(sid)}`)
        this.noteCreatedSession(sid)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Pane restored.' })
        this.session?.listSessions()
        const paneId = attempt.desktopRevivePaneId
        if (paneId) {
          this.activateDesktopRevivedPane(paneId, sid, attempt.geometry.cols, attempt.geometry.rows)
        } else {
          this.attach(sid, attempt.geometry.cols, attempt.geometry.rows)
        }
      },
      onRevivePaneError: (code, message, requestId) => {
        if (this.rejectRemoteCreationReply(requestId, 'revive-pane')) return
        connTrace.log(this.traceId, 'revive', 'error', 'error', code)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Restore pane failed', code, message) })
      },
      onStartPaneSessionOk: (sid, requestId) => {
        const attempt = this.takeRemoteCreation(requestId, 'start-pane-session')
        if (!attempt) return
        connTrace.log(this.traceId, 'pane_start', 'ok', 'ok', `sid=${short(sid)}`)
        this.noteCreatedSession(sid)
        const paneId = attempt.virtualStartPaneId ?? this.desktopPaneIdForSession(sid) ?? sid
        this.activateDesktopRevivedPane(paneId, sid, attempt.geometry.cols, attempt.geometry.rows)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: null })
        this.session?.listSessions()
        globalThis.setTimeout(() => {
          if (this.view.attachedSession !== sid) return
          connTrace.log(this.traceId, 'pane_start', 'reattach', 'pending', `sid=${short(sid)}`)
          this.attach(sid, attempt.geometry.cols, attempt.geometry.rows)
          this.session?.listSessions()
        }, POST_CREATE_FRESH_ATTACH_MS)
      },
      onStartPaneSessionError: (code, message, requestId) => {
        if (this.rejectRemoteCreationReply(requestId, 'start-pane-session')) return
        connTrace.log(this.traceId, 'pane_start', 'error', 'error', code)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Start pane failed', code, message) })
      },
      onStashPaneOk: (requestId) => {
        if (!this.takeRemoteMutation(requestId, 'stash-pane')) return
        connTrace.log(this.traceId, 'stash', 'ok', 'ok')
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Pane closed.' })
        this.session?.listSessions()
      },
      onStashPaneError: (code, message, requestId) => {
        if (!this.takeRemoteMutation(requestId, 'stash-pane')) return
        connTrace.log(this.traceId, 'stash', 'error', 'error', code)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Close pane failed', code, message) })
      },
      onRemovePaneOk: (requestId) => {
        if (!this.takeRemoteMutation(requestId, 'remove-pane')) return
        connTrace.log(this.traceId, 'remove', 'ok', 'ok')
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Pane removed.' })
        this.session?.listSessions()
      },
      onRemovePaneError: (code, message, requestId) => {
        if (!this.takeRemoteMutation(requestId, 'remove-pane')) return
        connTrace.log(this.traceId, 'remove', 'error', 'error', code)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Remove pane failed', code, message) })
      },
      onRenameOk: (requestId) => {
        if (!this.takeRemoteMutation(requestId, ['rename-pane', 'rename-window'])) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Rename saved.' })
        this.session?.listSessions()
      },
      onRenameError: (code, message, requestId) => {
        if (!this.takeRemoteMutation(requestId, ['rename-pane', 'rename-window'])) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Rename failed', code, message) })
      },
      onFocusWindowOk: (requestId) => {
        if (!this.takeRemoteMutation(requestId, 'focus-window')) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Window focused.' })
        this.session?.listSessions()
      },
      onFocusWindowError: (code, message, requestId) => {
        if (!this.takeRemoteMutation(requestId, 'focus-window')) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Focus window failed', code, message) })
      },
      onCloseWindowOk: (requestId) => {
        if (!this.takeRemoteMutation(requestId, 'close-window')) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Window closed.' })
        this.session?.listSessions()
      },
      onCloseWindowError: (code, message, requestId) => {
        if (!this.takeRemoteMutation(requestId, 'close-window')) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Close window failed', code, message) })
      },
      onNewWindowOk: (_windowId, sid, requestId) => {
        const attempt = this.takeRemoteCreation(requestId, 'new-window')
        if (!attempt) return
        this.noteCreatedSession(sid)
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: 'Window created.' })
        this.session?.listSessions()
        // R7 (creation liveness): the browser initiated this window — its seeded pane must land LIVE in the
        // NEW window (never through the R4 stash landing, never bound into whatever window is active now).
        // Completed against the metadata the listSessions() above / the next push carries.
        this.noteSelfCreatedSession(sid, attempt.geometry)
      },
      onNewWindowError: (code, message, requestId) => {
        if (this.rejectRemoteCreationReply(requestId, 'new-window')) return
        this.update({ creatingSession: false, createSessionError: null, desktopActionMessage: desktopActionMessage('Create window failed', code, message) })
      },
      onProjectEditOk: (_projectId, sessionId, requestId) => {
        const pendingCreation = this.pendingRemoteCreations.get(requestId)
        const attempt = pendingCreation?.kind === 'project-create'
          ? this.takeRemoteCreation(requestId, 'project-create')
          : null
        const mutation = attempt
          ? null
          : this.takeRemoteMutation(requestId, ['project-update', 'project-delete'])
        if (!attempt && !mutation) return
        if (sessionId) this.noteCreatedSession(sessionId)
        this.update({
          creatingSession: false,
          createSessionError: null,
          desktopActionMessage: mutation?.kind === 'project-delete' ? 'Project deleted.' : 'Project saved.',
        })
        this.session?.listSessions()
        // Auto-attach after PROJECT CREATE (parity with onNewWindowOk): a create seeds an initial window+pane
        // and the agent echoes that pane's session id — drop the user straight into it instead of leaving them
        // on the sidebar. `sessionId` is absent on project UPDATE and from older agents (backward compatible).
        // R7 (creation liveness): the seeded window+pane land LIVE + ACTIVE in the new project's OWN window,
        // exactly like a locally-created project on local — never through the R4 stash landing rule.
        if (sessionId && attempt) this.noteSelfCreatedSession(sessionId, attempt.geometry)
      },
      onProjectEditError: (code, message, requestId) => {
        const pendingCreation = this.pendingRemoteCreations.get(requestId)
        const attempt = pendingCreation?.kind === 'project-create'
          ? this.takeRemoteCreation(requestId, 'project-create')
          : null
        const mutation = attempt
          ? null
          : this.takeRemoteMutation(requestId, ['project-update', 'project-delete'])
        if (!attempt && !mutation) return
        this.update({
          creatingSession: false,
          createSessionError: null,
          desktopActionMessage: desktopActionMessage(
            mutation?.kind === 'project-delete' ? 'Delete project failed' : 'Project update failed',
            code,
            message,
          ),
        })
      },
      onAgentSessions: (result) => {
        // Hidden-list replies (Removed sessions section) go to a SEPARATE bucket, not the visible list.
        if (this.pendingHiddenListRequests.has(result.request_id)) {
          this.pendingHiddenListRequests.delete(result.request_id)
          const hiddenCwd = this.pendingAgentSessionListCwds.get(result.request_id)
          const hiddenAgent = this.pendingAgentSessionListAgents.get(result.request_id)
          this.pendingAgentSessionListCwds.delete(result.request_id)
          this.pendingAgentSessionListAgents.delete(result.request_id)
          const hidden = result.sessions.map((s) => (hiddenCwd ? { ...s, listCwd: hiddenCwd } : s))
          const hiddenAgentSessions = hiddenCwd && hiddenAgent
            ? [
                ...this.view.hiddenAgentSessions.filter((s) => !(s.listCwd === hiddenCwd && s.agent === hiddenAgent)),
                ...hidden,
              ].sort((a, b) => (b.modifiedAtMs ?? 0) - (a.modifiedAtMs ?? 0))
            : hidden
          this.update({ hiddenAgentSessions, hiddenAgentSessionsListed: true })
          return
        }
        const listCwd = this.pendingAgentSessionListCwds.get(result.request_id)
        const listAgent = this.pendingAgentSessionListAgents.get(result.request_id)
        this.pendingAgentSessionListCwds.delete(result.request_id)
        this.pendingAgentSessionListAgents.delete(result.request_id)
        const existing = listCwd && listAgent
          ? this.view.agentSessions.filter((s) => !(s.listCwd === listCwd && s.agent === listAgent))
          : this.view.agentSessions
        const byId = new Map(existing.map((s) => [`${s.agent}:${s.id}`, s]))
        for (const s of result.sessions) {
          const key = `${s.agent}:${s.id}`
          const prior = byId.get(key)
          const next = { ...prior, ...s, ...(listCwd ? { listCwd } : {}) }
          if (!Object.prototype.hasOwnProperty.call(s, 'inUse')) {
            if (prior?.inUse !== undefined) {
              next.inUse = prior.inUse
            } else if (this.view.sessions.includes(s.id)) {
              next.inUse = true
            }
          }
          byId.set(key, next)
        }
        const agentSessions = [...byId.values()].sort((a, b) => (b.modifiedAtMs ?? 0) - (a.modifiedAtMs ?? 0))
        this.update({ agentSessions, agentSessionsListed: true })
      },
      onAgentSessionsError: (result) => {
        const hidden = this.pendingHiddenListRequests.delete(result.request_id)
        this.pendingAgentSessionListCwds.delete(result.request_id)
        this.pendingAgentSessionListAgents.delete(result.request_id)
        this.update({
          agentSessionManageError: trustedDesktopError(result.code, result.message),
          ...(hidden ? { hiddenAgentSessionsListed: true } : { agentSessionsListed: true }),
        })
      },
      onDirectoriesResult: (result) => {
        if (this.view.directoryBrowser?.requestId && this.view.directoryBrowser.requestId !== result.request_id) return
        this.clearDirectoryBrowserTimer()
        this.update({
          directoryBrowser: {
            loading: false,
            requestId: result.request_id,
            path: result.path,
            parent: result.parent,
            entries: result.entries,
            error: undefined,
          },
        })
        // Folder-scoped sessions (desktop parity: "Choose a working directory to list past sessions"): once the
        // browser lands on a folder, list the prior agent sessions FOR THAT FOLDER so the user can resume/delete
        // them in-place, like the local app. Content-blind (metadata only; rows carry listCwd = this folder).
        if (result.path) this.listAgentSessionsForFolder(result.path)
      },
      onDirectoriesError: (result) => {
        const browser = this.view.directoryBrowser
        if (!browser || browser.requestId !== result.request_id) return
        this.clearDirectoryBrowserTimer()
        this.update({
          directoryBrowser: {
            ...browser,
            loading: false,
            error: trustedDesktopError(result.code, result.message),
          },
        })
      },
      onAgentSessionPreview: (result) => {
        const key = this.pendingAgentPreviewRequests.get(result.request_id)
        if (!key) return
        this.pendingAgentPreviewRequests.delete(result.request_id)
        const next = { ...this.view.agentSessionPreviews }
        if (result.type === 'agent_session_preview') {
          next[key] = { lines: result.lines }
        } else {
          next[key] = { error: trustedDesktopError(result.code, result.message) || createSessionMessage(result.code) }
        }
        this.update({ agentSessionPreviews: next })
      },
      onAgentSessionManaged: (result) => {
        const managedCwd = this.pendingAgentSessionManageCwds.get(result.request_id)
        const managedAgent = this.pendingAgentSessionManageAgents.get(result.request_id)
        this.pendingAgentSessionManageCwds.delete(result.request_id)
        this.pendingAgentSessionManageAgents.delete(result.request_id)
        if (result.type === 'agent_session_managed') {
          // rename/hide/delete/unhide persisted on the desktop → re-list so the picker reflects it.
          this.update({ agentSessionManageError: null })
          this.refreshAgentSessions()
          // Also re-list the FOLDER BROWSER's current folder: the New Project / Split picker usually has no attached
          // pane, so refreshAgentSessions' pane-cwd scope misses it — without this a renamed name / hidden state
          // wouldn't show in the folder card.
          const folder = managedCwd || this.view.directoryBrowser?.path
          if (folder) {
            this.listAgentSessionsForFolder(folder)
            if (this.view.hiddenAgentSessionsListed && managedAgent) this.listHiddenAgentSessionsForFolder(folder, managedAgent)
          }
        } else {
          this.update({
            agentSessionManageError:
              trustedDesktopError(result.code, result.message) || createSessionMessage(result.code),
          })
        }
      },
      onScrollView: (v) => this.scrollViewHandler?.(v),
      onGridSnapshot: (grid) => {
        if (this.view.attachedSession) this.noteAttachMaterialized(this.view.attachedSession, grid.rows)
        this.gridSnapshotHandler?.(grid)
      },
      onRawOutput: (bytes) => {
        if (this.view.attachedSession) this.noteAttachMaterialized(this.view.attachedSession)
        this.rawOutputHandler?.(bytes)
      },
      onTerminalProgress: (sessionId) => this.noteAttachProgress(sessionId),
      onScrollbackRequest: (sessionId, offset, count, sessionTraceOwned) => {
        this.noteScrollbackWireRequest(sessionId, offset, count, sessionTraceOwned)
      },
      onScrollbackReply: (sessionId, offset, accepted) => {
        this.noteScrollbackReply(sessionId, offset, accepted)
      },
      onTerminalFrame: (frame) => {
        const frameSessionId = this.multiPaneTerminal.sessionForChannel(frame.channel)
        if (!frameSessionId) return false
        const settlementOnly = !this.multiPaneOutputEnabled
          && this.paneScrollbackInFlight.has(frameSessionId)
          && this.multiAttach.activeSession() !== frameSessionId
        if (!this.multiPaneOutputEnabled && !settlementOnly) return false
        const bankResult = this.multiPaneTerminal.onFrame(frame)
        // BASELINE RECOVERY: any local SyncState rejection (missing baseline, revision gap after a dropped Damage,
        // generation mismatch, etc.) needs a fresh attach to force a full Grid. The sole exception is the daemon's
        // explicit resync_required event: its protocol contract guarantees the next event is already a full Grid,
        // so another detach/attach would only race that recovery. Re-attach is deduped until attach_ok.
        if (
          !settlementOnly
          && bankResult?.kind === 'resync'
          && bankResult.reason !== 'daemon requested resync'
        ) {
          this.reattachForBaseline(frameSessionId)
        }
        // This frame is for one of our panes (frameSessionId matched above), so the pane bridge owns it — live
        // grid/damage AND scrollback replies (it now paints history to the pane's own renderer). Consume it so
        // the single-channel RemoteSession path never double-handles a pane frame (incl. mid-chunk accumulation).
        return true
      },
      onBaselineRequired: (sessionId, reason) => {
        connTrace.log(this.traceId, 'terminal', 'baseline_required', 'pending', `session=${short(sessionId)} reason=${reason}`)
        this.reattachForBaseline(sessionId)
      },
    }, this.traceId)
    // Multi-pane input encoding: keys/paste for the ACTIVE pane must use THAT pane's terminal modes (app_cursor
    // arrows, bracketed paste). In the N-up path the live grid — and thus those modes — lives in the per-pane
    // bank, not on the RemoteSession's `held`, so hand the session a provider that reports the attached session's
    // pane modes. Returns null when there's no multi-pane state (single-session path falls back to `held`).
    this.session = remoteSession
    remoteSession.setActivePaneModesProvider(() => {
      if (!this.multiPaneOutputEnabled) return null
      const active = this.multiAttach.activeSession() ?? this.view.attachedSession
      return active ? this.multiPaneTerminal.paneModes(active) : null
    })
    try {
      await connect()
    } catch (e) {
      if (!ownsConnection() || connectDeadline.signal.aborted) return
      attemptMetric.finish('network_failure')
      // A setup rejection has no viable peer to keep. Revoke callback/timer ownership before close so a
      // synchronous `closed` event cannot schedule reconnect underneath the explicit error state.
      this.connectionGeneration++
      this.clearConnectWatchdog()
      this.clearSessionListWatchdog()
      this.clearAttachWatchdogs()
      this.clearPaneSwitchWatchdog()
      if (this.session === remoteSession) this.session = null
      remoteSession.close()
      // surface a setup failure (e.g. RTCPeerConnection rejected the ICE config) instead of swallowing it.
      const msg = e instanceof Error ? e.message : String(e)
      this.update({ phase: 'error', error: `connect failed: ${safeMessage(msg)}` })
    }
  }

  private onControlState(st: ControlState): void {
    if (
      st === 'revoked' ||
      st === 'authorization_required' ||
      st === 'entitlement_required' ||
      st === 'access_required' ||
      st === 'offline' ||
      st === 'auth_refused' ||
      st === 'error' ||
      st === 'closed'
    ) {
      // Failure/user refusal is cancellation, not successful completion: abort every cloud request still owned
      // by this setup scope. Retire the transport first so protocol-originated failures (auth_refused/error) also
      // detach the bridge's abort listener before the signal fires; cancellation cannot recursively publish closed.
      this.session?.close()
      this.retireTerminalTransportState()
      this.clearConnectWatchdog()
    }
    switch (st) {
      case 'connected':
        this.noteConnectProgress('bridge:data-channel-open')
        // Align the opt-in benchmark origin to DataChannel open so first-Grid latency is directly comparable
        // between single/dual-channel and direct/relay runs. No-op when metrics are disabled.
        resetTransportMetrics()
        break
      case 'authenticated':
        // Arm the startup gate before publishing authenticated state. `update()` synchronously invokes UI
        // subscribers, and those renders may mount project forms that request folder-scoped provider history.
        // If the gate is armed afterwards, those scans enter the reliable/ordered channel ahead of session_list
        // and the focused terminal attach, turning a fast connection into a multi-second blank terminal.
        this.deferredAgentSessionRefresh = true
        connTrace.log(this.traceId, 'connect', 'auth_ok', 'ok')
        this.noteConnectProgress('controller:authenticated')
        this.completeConnectWatchdog() // reached auth → setup lifetime is complete without aborting the live peer
        // Stamp the successful-connect wall-clock for the "Connected … ago" line (content-blind: a timestamp).
        this.update({ authState: 'authenticated', nextRetryAtMs: undefined, lastConnectedAtMs: Date.now() })
        this.reconnectAttempt = 0 // a clean auth resets the backoff
        this.sessionListRetried = false
        connTrace.log(this.traceId, 'session_list', 'request', 'pending')
        // Remote terminal is a full-size remote surface: once authenticated, this browser should own the PTY
        // winsize by default. Local desktop layout geometry stays independent; this only makes Claude/TUIs redraw
        // for the browser viewport instead of the desktop pane's current size.
        this.setWinsizeOwner('remote')
        this.session?.listSessions()
        this.armSessionListWatchdog() // guard the "Loading its projects…" wait so it can't hang forever
        // Provider history is optional metadata and some stores are very large. Sending all scans here used to put
        // them ahead of the first attach on the one reliable/ordered channel. The hydration queue flushes this once
        // the focused Grid + initial history (then already-placed siblings) are ready; a genuinely empty desktop
        // flushes it as soon as session_list establishes that there is no terminal to acquire.
        break
      case 'revoked':
        connTrace.log(this.traceId, 'connect', 'revoked', 'error', 'cloud/agent refused: device revoked')
        // a revoked device must NEVER reconnect — stop the loop and show revoked.
        this.stopReconnect = true
        this.clearReconnectTimer()
        clearHints()
        this.update({
          phase: 'revoked',
          attachedSession: null,
          authState: 'revoked',
          connectionMode: 'unknown',
          ...this.clearPendingCreate('This desktop was unlinked.'),
        })
        break
      case 'authorization_required':
        // A passkey prompt was cancelled/unavailable (or its status endpoint failed). Retrying in the
        // background would reopen the browser/phone prompt on every backoff and can even race direct→relay.
        // Stop until the user explicitly taps Reconnect or returns to account recovery.
        connTrace.log(this.traceId, 'connect', 'authorization_required', 'warn', 'passkey needs explicit user action')
        this.stopReconnect = true
        this.clearReconnectTimer()
        // The selected desktop was persisted before WebAuthn began so healthy refreshes can resume. Once the user
        // cancels/refuses authorization that same hint becomes an automatic-prompt loop across page reloads: a fresh
        // controller restores it and immediately opens WebAuthn again. Forget only the auto-resume hint; the current
        // offline view retains selectedDevice so an explicit Reconnect still performs exactly one new attempt.
        clearHints()
        this.update({
          phase: 'offline',
          connectionMode: 'failed',
          error: 'Passkey authorization is required. Tap Reconnect to try again, or open Account & Security to recover it.',
          nextRetryAtMs: undefined,
          ...this.clearPendingCreate(CREATE_INTERRUPTED_MESSAGE),
        })
        break
      case 'access_required':
        // Only an explicit adapter refusal enters this state. Do not infer a payment or passkey policy.
        connTrace.log(this.traceId, 'connect', 'access_required', 'warn', 'adapter refused remote access')
        this.stopReconnect = true
        this.clearReconnectTimer()
        this.update({
          phase: 'offline',
          connectionMode: 'failed',
          error: 'Remote access was declined. Check access with your service, then tap Reconnect to try again.',
          nextRetryAtMs: undefined,
          ...this.clearPendingCreate('Remote access was declined.'),
        })
        break
      case 'entitlement_required':
        // This is durable account authority, not transient network state. Keep the selected desktop so an explicit
        // retry after changing plan can reconnect, but never schedule background attempts against the same 402.
        connTrace.log(this.traceId, 'connect', 'entitlement_required', 'warn', 'paid remote access required')
        this.stopReconnect = true
        this.clearReconnectTimer()
        this.update({
          phase: 'plan_required',
          connectionMode: 'failed',
          error: null,
          nextRetryAtMs: undefined,
          ...this.clearPendingCreate('A Hydra Remote plan is required.'),
        })
        break
      case 'offline':
        connTrace.log(this.traceId, 'connect', 'offline', 'warn', `attempt=${this.reconnectAttempt}`)
        this.update({ phase: 'offline', connectionMode: 'unknown', ...this.clearPendingCreate(CREATE_INTERRUPTED_MESSAGE) })
        this.scheduleReconnect()
        break
      case 'auth_refused':
        // bad/expired token → a reconnect would mint fresh, so retry ONCE via the backoff path; but a
        // hard refusal that keeps repeating will exhaust attempts and stop.
        connTrace.log(this.traceId, 'connect', 'auth_refused', 'error', 'token refused (not revoked)')
        this.update({ authState: 'refused' })
        this.update({ phase: 'offline', connectionMode: 'unknown', ...this.clearPendingCreate('Please sign in again.') })
        this.scheduleReconnect()
        break
      case 'error':
        connTrace.log(this.traceId, 'connect', 'error', 'error', 'transport error')
        this.update({ phase: 'offline', connectionMode: 'unknown', ...this.clearPendingCreate(CREATE_INTERRUPTED_MESSAGE) })
        this.scheduleReconnect()
        break
      case 'closed':
        if (this.view.phase === 'terminal' || this.view.phase === 'sessions' || this.view.phase === 'connecting') {
          connTrace.log(this.traceId, 'connect', 'closed', 'warn', `from=${this.view.phase}`)
          this.update({ phase: 'offline', connectionMode: 'unknown', ...this.clearPendingCreate(CREATE_INTERRUPTED_MESSAGE) })
          this.scheduleReconnect()
        }
        break
      default:
        break
    }
  }

  attach(
    sessionId: string,
    cols: number,
    rows: number,
    requestedTargetPaneId?: string | null,
    expectedTargetSessionId?: string | null,
  ): void {
    const requestedTarget = requestedTargetPaneId === undefined || requestedTargetPaneId === null
      ? null
      : findLeaf(this.view.paneLayout, requestedTargetPaneId)
    const targetUnavailable = requestedTargetPaneId !== undefined
      && requestedTargetPaneId !== null
      && (
        !requestedTarget
        || (
          expectedTargetSessionId !== undefined
          && requestedTarget.sessionId !== expectedTargetSessionId
          && requestedTarget.sessionId !== sessionId
        )
      )
    if (targetUnavailable) {
      const reason = requestedTarget ? 'target_reused' : 'target_gone'
      connTrace.log(
        this.traceId,
        'attach',
        reason,
        'warn',
        `sid=${short(sessionId)} pane=${short(requestedTargetPaneId)}`,
      )
      // The create itself succeeded, but its browser placement target was removed or deliberately rebound while
      // the request was in flight. Leave the new durable session discoverable in inventory without trapping the
      // user on a passive Loading surface or overwriting their newer placement.
      this.update({ terminalAcquisition: null })
      this.session?.listSessions()
      return
    }
    // Public attach is the acquisition boundary for explicit user/create/revive intents and approved reconnect
    // resume. It supersedes a prior detach; same-connection inventory refreshes are gated before they reach here.
    this.intentionalDetachGeneration = null
    // A manual session choice from the stable workspace is a fresh acquisition too. Render an inert Loading…
    // surface until attach_ok instead of exposing pane mutation actions that can cancel the in-flight attach.
    if (this.view.phase === 'sessions' && this.view.terminalAcquisition === null) {
      this.update({ terminalAcquisition: 'loading' })
    }
    const previousViewed = this.lastViewedSessionId
    if (previousViewed && previousViewed !== sessionId) {
      this.abandonPendingAttachOnDeparture(previousViewed)
    }
    if (
      previousViewed
      && previousViewed !== sessionId
      && !this.multiPaneOutputEnabled
      && this.paneScrollbackInFlight.has(previousViewed)
    ) {
      // Public attach is also a focus departure. Retire the former scalar channel before attach() resets the
      // RemoteSession-local trace, otherwise its controller owner survives alone and disconnects 45 s later.
      this.releaseSessionForOnDemandReattach(previousViewed)
    }
    this.resumeSessionId = sessionId // remember it for reconnect/resume
    this.saveLastOpenedForCurrentDesktop(sessionId)
    this.ensureRemoteWinsize(cols, rows)
    this.scheduleWinsizeSettleRepush(sessionId) // outlive the desktop's stale-ownership refit window for THIS pane
    // ISOLATED GEOMETRY (pane existence contract): the browser owns its OWN pane layout — it does NOT mirror
    // the desktop window's geometry. Binding a session just drops it into the browser's active pane. Multi-pane in
    // the browser happens when the USER splits HERE, with the browser's own geometry. This decouples local↔remote
    // layout so a local resize/split never re-drives the remote (the resize-storm/flash root cause). Pane EXISTENCE
    // still syncs via the sidebar; pane CONTENT still syncs via the channel — only geometry is independent.
    // DETERMINISTIC TARGET: prefer the pane captured by this correlated creation attempt over the
    // currently-active pane — async completions must land where the user acted, not where focus
    // drifted. A session ALREADY PLACED in the grid re-attaches into its OWN pane (multi-pane resume/restore
    // must not fold every survivor into the active pane, and re-opening a placed session must focus it, not
    // duplicate it — invariant 1). Falls back to the active pane for plain session-row clicks.
    const targetPaneId =
      requestedTargetPaneId && findLeaf(this.view.paneLayout, requestedTargetPaneId)
        ? requestedTargetPaneId
        : leaves(this.view.paneLayout.root).find((l) => l.sessionId === sessionId)?.id
          ?? this.view.paneLayout.activePaneId
    const paneLayout = {
      ...setPaneSessionInLayout(this.view.paneLayout, targetPaneId, sessionId),
      activePaneId: targetPaneId,
    }
    // Slice 3 (strict partition): binding a session into a pane is a PLACEMENT — clear any stash entry still
    // holding the same session, so an attach can never leave the session placed AND stashed at once.
    this.applyWorkspace(
      workspacePanesFrom(paneLayout, this.view.browserStashed.filter((s) => s.sessionId !== sessionId)),
      { paneLayout, lastOpenedSessionId: sessionId, recentSessionEnded: false },
    )
    // attach() itself made this pane active. Record that focus now so the first keystroke does not look like a
    // new focus transition and emit a redundant ownership resize; attach_session(viewed=true) is the assertion.
    this.lastViewedSessionId = sessionId
    this.persistHints()
    this.persistLastLayout() // a pane's session binding changed → keep the saved arrangement current
    // Other placed panes are intentionally NOT fanned out here. They remain on-demand and are acquired only when
    // focused; this pane's first Grid and bounded first-history warm keep strict foreground priority.
    this.schedulePaneHydration()
    this.lastAttachSize = { cols, rows } // remembered for baseline-recovery re-attaches (same viewport)
    const attachedChannel = this.multiAttach.channelForSession(sessionId)
    if (attachedChannel === null) {
      // attach() made this session's pane active above, but its channel is not proven yet. Demote the previously
      // viewed channel before any pending-attach early return so background decode cannot retain the foreground lane
      // while the newly viewed attach is in flight. attach_ok promotes the new channel before ordered binary output.
      this.session?.setViewedChannel(null)
    }
    // BASELINE GUARD: "already attached" is only reusable when the pane bank can actually PAINT this session —
    // i.e. it holds a baseline grid. A session attached while the legacy single-canvas path consumed its frames
    // (multiPaneOutputEnabled=false) has a channel but NO bank baseline; early-returning here left a revived
    // pane permanently blank — damage deltas are dropped without a baseline, and the daemon only resends a full
    // grid on a fresh attach. Fall through to a fresh attach in that case.
    const bankCanPaint = !this.multiPaneOutputEnabled || this.multiPaneTerminal.gridBounds(sessionId) !== null
    if (attachedChannel !== null && bankCanPaint) {
      // Production single-pane mode has only ONE held grid in RemoteSession. Reusing an already-attached channel
      // changes the active/green pane state, but the canvas can still contain the previously active session until
      // that newly selected pane happens to emit output. A full page refresh "fixes" it because attach_session
      // forces a fresh Grid. Do the same intentionally on pane switch in single-pane mode; the ?panes=1 bank can
      // reuse because it keeps per-session held grids.
      if (!this.multiPaneOutputEnabled) {
        this.update({ phase: 'terminal', attachedSession: sessionId })
        this.reattachSessionFresh(sessionId)
        this.schedulePaneHydration()
        return
      }
      this.multiAttach.setActive(sessionId)
      this.session?.setActiveAttach(sessionId, attachedChannel)
      this.update({ phase: 'terminal', attachedSession: sessionId })
      this.applyResizePane(sessionId, cols, rows) // internal echo of attach geometry, not an app measurement
      this.schedulePaneHydration()
      return
    }
    // IN-FLIGHT DEDUPE (same rule as the sibling loop above / attachPlacedPanes): an attach_session for
    // this session is already on the wire — a second send is GUARANTEED to bounce off the agent as an
    // `already_attached` error (the live create sent the seeded session twice, 80x24 then 100x30, and the
    // refusal surfaced as an error banner). The in-flight attach completes into this same placement.
    if (this.reclaimPendingAttach(sessionId)) {
      this.ensureForegroundAttach(sessionId)
      return
    }
    if (this.attachWatchdogs.has(sessionId)) return
    // xterm renderer ⇒ attach in raw mode (daemon streams raw PTY bytes). Structured ⇒ Grid/Damage.
    this.armAttachWatchdog(sessionId)
    this.scheduleWinsizeSettleRepush(sessionId)
    this.sendAttachRequest(sessionId, cols, rows)
    this.pendingOwnershipReassert.add(sessionId)
  }

  /** "New session": ask the agent to create a session on demand, then auto-attach it at `cols×rows` (the
   * app passes the current viewport). No-op unless authenticated. Sets a pending flag; the
   * onSessionCreated / onSessionCreateError callbacks clear it. F1: an optional `label` names the session
   * (deterministic default `Terminal N` when blank, N = sessions so far + 1). */
  createSession(cols: number, rows: number, label?: string, agent?: RemoteAgentKind, cwd?: string): void {
    if (this.view.creatingSession) return // guard double-submit
    const creation = this.beginRemoteCreation('create', 'create-session', cols, rows, {
      targetPaneId: this.view.paneLayout.activePaneId,
    })
    // Capture WHERE the user acted: the completion binds the new session to this pane even if the
    // active pane changes while the create round-trips (covers createSessionInPane too, which
    // focuses its target pane right before calling this).
    const typed = label?.trim() ?? ''
    const name = typed || `Terminal ${this.view.sessions.length + 1}`
    // F2: keep the typed label in view state so a FAILED create preserves it for an easy retry; a SUCCESS
    // clears it (in onSessionCreated). Blank typing leaves it empty (the default name is used, not stored).
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null, newSessionLabel: typed })
    // Gap-doc Step 1 (web half): pass real desktop CONTEXT, not just a label — the cwd of the project the user
    // is currently in (the attached session's cwd) and the agent inferred from its label, so a new session lands
    // in the same project/agent like the desktop's "New window/pane" does. Honest: derived from real session
    // context (no fabrication); cwd/agent omitted when unknown → the agent falls back to default home, as before.
    this.session?.createSession(creation.requestId, {
      label: name,
      ...this.createContext(agent, cwd),
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  resumeAgentSession(sessionId: string, agent: RemoteAgentKind, cols = 80, rows = 24, cwd?: string): void {
    const id = sessionId.trim()
    if (!id || this.view.creatingSession) return
    const creation = this.beginRemoteCreation('create', 'create-session', cols, rows, {
      targetPaneId: this.view.paneLayout.activePaneId,
    })
    const label = `${agent[0].toUpperCase()}${agent.slice(1)} resume`
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null, newSessionLabel: '' })
    this.session?.createSession(creation.requestId, {
      label,
      ...this.createContext(agent, cwd),
      agent,
      launchFlags: { resumeMode: 'resume', resumeSessionId: id },
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  previewAgentSessionRemote(sessionId: string, agent: RemoteAgentKind, maxLines = 40, cwdOverride?: string): void {
    const id = sessionId.trim()
    if (!id) return
    const key = `${agent}:${id}`
    // Toggle, like the local peek (👁): clicking it again on an already-open preview CLOSES it. Also drop any
    // in-flight preview request for this key, so a reply that lands AFTER the close doesn't re-open it (the
    // "closes then re-opens a second later" bug).
    if (this.view.agentSessionPreviews[key]) {
      const requestId = `agent-preview:${key}`
      this.pendingAgentPreviewRequests.delete(requestId)
      const next = { ...this.view.agentSessionPreviews }
      delete next[key]
      this.update({ agentSessionPreviews: next })
      return
    }
    const requestId = `agent-preview:${key}`
    this.pendingAgentPreviewRequests.set(requestId, key)
    this.update({ agentSessionPreviews: { ...this.view.agentSessionPreviews, [key]: { loading: true } } })
    const cwd = cwdOverride ?? (this.view.attachedSession ? this.view.sessionCwds[this.view.attachedSession] : undefined)
    this.session?.previewAgentSession(requestId, agent, id, cwd, maxLines)
  }

  /** SessionPicker manage (gap-doc §4.4): rename / hide / delete a prior agent session. Content-blind (ids/label
   * only). The reply (onAgentSessionManaged) re-lists on ok or sets agentSessionManageError on failure. */
  renameAgentSessionRemote(sessionId: string, agent: RemoteAgentKind, name: string, cwdOverride?: string): void {
    const trimmed = name.trim()
    this.optimisticRenameAgentSession(sessionId, agent, trimmed, cwdOverride)
    this.manageAgentSession('rename', sessionId, agent, { name: trimmed, ...(cwdOverride ? { cwd: cwdOverride } : {}) })
  }
  hideAgentSessionRemote(sessionId: string, agent: RemoteAgentKind, cwdOverride?: string): void {
    // Hide is keyed by (agent, session id) on the desktop, so keep the wire payload content-blind/no-cwd.
    // The optional cwd is only a browser refresh scope so folder pickers can drop the row immediately.
    this.optimisticHideAgentSession(sessionId, agent, cwdOverride)
    this.manageAgentSession('hide', sessionId, agent, {}, cwdOverride)
  }
  /** ＋ Add back: bring a ⊘-removed (hidden) session to the visible list — desktop unhide_folder_session. */
  unhideAgentSessionRemote(sessionId: string, agent: RemoteAgentKind, cwdOverride?: string): void {
    const cwd = cwdOverride ?? (this.view.attachedSession ? this.view.sessionCwds[this.view.attachedSession] : undefined)
    this.optimisticUnhideAgentSession(sessionId, agent, cwd)
    this.manageAgentSession('unhide', sessionId, agent, cwd ? { cwd } : {})
  }
  deleteAgentSessionRemote(sessionId: string, agent: RemoteAgentKind, cwdOverride?: string): void {
    // delete resolves the file from the folder listing, so it needs the active cwd context.
    const cwd = cwdOverride ?? (this.view.attachedSession ? this.view.sessionCwds[this.view.attachedSession] : undefined)
    this.optimisticDeleteAgentSession(sessionId, agent, cwd)
    this.manageAgentSession('delete', sessionId, agent, cwd ? { cwd } : {})
  }
  /** List the REMOVED (hidden) sessions for a folder+agent → view.hiddenAgentSessions (keyed by folder+agent). */
  listHiddenAgentSessionsForFolder(cwd: string, agent: RemoteAgentKind = 'claude'): void {
    const requestId = `agent-sessions-hidden:${agent}:${cwd}`
    this.pendingAgentSessionListCwds.set(requestId, cwd)
    this.pendingAgentSessionListAgents.set(requestId, agent)
    this.pendingHiddenListRequests.add(requestId)
    this.session?.listAgentSessions(requestId, agent, cwd, true)
  }
  private manageAgentSession(
    action: 'rename' | 'hide' | 'unhide' | 'delete',
    sessionId: string,
    agent: RemoteAgentKind,
    opts: { cwd?: string; name?: string } = {},
    refreshCwd: string | undefined = opts.cwd,
  ): void {
    const id = sessionId.trim()
    if (!id) return
    const requestId = `agent-manage:${action}:${agent}:${id}`
    this.pendingAgentSessionManageCwds.set(requestId, refreshCwd)
    this.pendingAgentSessionManageAgents.set(requestId, agent)
    this.session?.manageAgentSession(requestId, action, agent, id, opts)
  }

  private optimisticHideAgentSession(sessionId: string, agent: RemoteAgentKind, cwd?: string): void {
    const id = sessionId.trim()
    if (!id) return
    const visible = this.view.agentSessions
    const removed = visible.find((s) => s.id === id && s.agent === agent && (!cwd || !s.listCwd || s.listCwd === cwd))
    const agentSessions = visible.filter((s) => !(s.id === id && s.agent === agent && (!cwd || !s.listCwd || s.listCwd === cwd)))
    const hiddenCandidate: RemoteAgentSessionMeta = removed
      ? { ...removed, ...(cwd ? { listCwd: cwd } : {}) }
      : { id, agent, ...(cwd ? { listCwd: cwd } : {}) }
    const hiddenKey = `${hiddenCandidate.agent}:${hiddenCandidate.id}:${hiddenCandidate.listCwd ?? ''}`
    const hiddenAgentSessions = [
      hiddenCandidate,
      ...this.view.hiddenAgentSessions.filter((s) => `${s.agent}:${s.id}:${s.listCwd ?? ''}` !== hiddenKey),
    ].sort((a, b) => (b.modifiedAtMs ?? 0) - (a.modifiedAtMs ?? 0))
    this.update({ agentSessions, hiddenAgentSessions, hiddenAgentSessionsListed: true, agentSessionManageError: null })
  }

  private optimisticRenameAgentSession(sessionId: string, agent: RemoteAgentKind, name: string, cwd?: string): void {
    const id = sessionId.trim()
    if (!id) return
    const rename = (s: RemoteAgentSessionMeta): RemoteAgentSessionMeta =>
      s.id === id && s.agent === agent && (!cwd || !s.listCwd || s.listCwd === cwd)
        ? { ...s, ...(name ? { customName: name } : { customName: undefined }) }
        : s
    this.update({
      agentSessions: this.view.agentSessions.map(rename),
      hiddenAgentSessions: this.view.hiddenAgentSessions.map(rename),
      agentSessionManageError: null,
    })
  }

  private optimisticDeleteAgentSession(sessionId: string, agent: RemoteAgentKind, cwd?: string): void {
    const id = sessionId.trim()
    if (!id) return
    const sameScope = (s: RemoteAgentSessionMeta) => s.id === id && s.agent === agent && (!cwd || !s.listCwd || s.listCwd === cwd)
    this.update({
      agentSessions: this.view.agentSessions.filter((s) => !sameScope(s)),
      hiddenAgentSessions: this.view.hiddenAgentSessions.filter((s) => !sameScope(s)),
      agentSessionManageError: null,
    })
  }

  private optimisticUnhideAgentSession(sessionId: string, agent: RemoteAgentKind, cwd?: string): void {
    const id = sessionId.trim()
    if (!id) return
    const hidden = this.view.hiddenAgentSessions
    const restored = hidden.find((s) => s.id === id && s.agent === agent && (!cwd || !s.listCwd || s.listCwd === cwd))
    const hiddenAgentSessions = hidden.filter((s) => !(s.id === id && s.agent === agent && (!cwd || !s.listCwd || s.listCwd === cwd)))
    const visibleCandidate: RemoteAgentSessionMeta = restored
      ? { ...restored, ...(cwd ? { listCwd: cwd } : {}) }
      : { id, agent, ...(cwd ? { listCwd: cwd } : {}) }
    const visibleKey = `${visibleCandidate.agent}:${visibleCandidate.id}:${visibleCandidate.listCwd ?? ''}`
    const agentSessions = [
      visibleCandidate,
      ...this.view.agentSessions.filter((s) => `${s.agent}:${s.id}:${s.listCwd ?? ''}` !== visibleKey),
    ].sort((a, b) => (b.modifiedAtMs ?? 0) - (a.modifiedAtMs ?? 0))
    this.update({ agentSessions, hiddenAgentSessions, hiddenAgentSessionsListed: true, agentSessionManageError: null })
  }

  /** The desktop context to seed a new session with: the active project's cwd + its agent, derived from the
   * currently-attached session. Both optional — omitted when unknown (the agent then uses default home). */
  private createContext(agentOverride?: RemoteAgentKind, cwdOverride?: string, launchFlags?: RemoteLaunchFlags): { cwd?: string; agent?: RemoteAgentKind; launchFlags?: RemoteLaunchFlags } {
    const active = this.view.attachedSession
    const cwd = cwdOverride ?? (active ? this.view.sessionCwds[active] : undefined)
    const flags = launchFlags && Object.keys(launchFlags).length > 0 ? { launchFlags } : {}
    if (agentOverride) return { ...(cwd ? { cwd } : {}), agent: agentOverride, ...flags }
    if (!active) return flags
    // agentFromLabel returns the desktop AgentKind; runnable providers are valid launch agents on the wire,
    // while 'shell' (or null) means "no specific agent", so omit it. Cursor is inferred only from its product
    // name, never from its generic `agent` executable name.
    const inferred = agentFromLabel(sessionLabel(this.view, active))
    const agent: RemoteAgentKind | undefined = isRunnableAgentKind(inferred) ? inferred : undefined
    return { ...(cwd ? { cwd } : {}), ...(agent ? { agent } : {}), ...flags }
  }

  private refreshAgentSessions(): void {
    const cwd = this.view.attachedSession ? this.view.sessionCwds[this.view.attachedSession] : undefined
    for (const agent of HISTORY_AGENT_OPTIONS) {
      const requestId = `agent-sessions:${agent}`
      this.pendingAgentSessionListCwds.set(requestId, cwd)
      this.pendingAgentSessionListAgents.set(requestId, agent)
      this.session?.listAgentSessions(requestId, agent, cwd)
    }
  }

  private flushDeferredAgentSessionRefresh(): void {
    if (!this.session?.isAuthenticated) return
    const refreshGlobal = this.deferredAgentSessionRefresh
    const folders = [...this.deferredAgentSessionFolderRefreshes]
    if (!refreshGlobal && folders.length === 0) return
    this.deferredAgentSessionRefresh = false
    this.deferredAgentSessionFolderRefreshes.clear()
    if (refreshGlobal) this.refreshAgentSessions()
    for (const cwd of folders) this.requestAgentSessionsForFolder(cwd)
  }

  /** List prior agent sessions scoped to a SPECIFIC folder (the directory-browser's current path), for the
   * folder-scoped session list. Same content-blind list op as refreshAgentSessions, but the cwd is the picked
   * folder (not the attached pane) — rows come back with listCwd = this folder, so resume/delete act on it. */
  listAgentSessionsForFolder(cwd: string): void {
    if (this.deferredAgentSessionRefresh) {
      this.deferredAgentSessionFolderRefreshes.add(cwd)
      return
    }
    this.requestAgentSessionsForFolder(cwd)
  }

  private requestAgentSessionsForFolder(cwd: string): void {
    for (const agent of HISTORY_AGENT_OPTIONS) {
      const requestId = `agent-sessions-folder:${agent}:${cwd}`
      this.pendingAgentSessionListCwds.set(requestId, cwd)
      this.pendingAgentSessionListAgents.set(requestId, agent)
      this.session?.listAgentSessions(requestId, agent, cwd)
    }
  }

  listDirectoriesRemote(path?: string): void {
    const requestId = `directories:${Date.now()}`
    const current = this.view.directoryBrowser
    const trimmed = path?.trim()
    this.clearDirectoryBrowserTimer()
    // Fail fast ONLY when genuinely sitting on the device picker (phase 'devices' / 'revoked' / 'error' with no
    // session): there's no desktop selected, so browsing is impossible. During 'connecting' the session is being
    // established — do NOT hard-fail there; fall through to the retry loop, which waits for auth/channel to come up
    // (this was the "Connect to a desktop first" bug that fired while the desktop was still loading its projects).
    const preConnectPhase = this.view.phase === 'devices' || this.view.phase === 'revoked'
      || this.view.phase === 'error' || this.view.phase === 'signed_out'
    const noDesktopConnection = !this.session && preConnectPhase && !this.view.reconnectingNow
    if (noDesktopConnection) {
      this.update({
        directoryBrowser: {
          loading: false,
          requestId,
          path: trimmed || current?.path || '',
          parent: current?.parent,
          entries: current?.entries ?? [],
          error: 'Connect to a desktop first — pick one from the Desktops list, then open New Project.',
        },
      })
      return
    }
    // Otherwise we ARE connected (or reconnecting): show the spinner and let the retry loop re-send once auth/channel
    // is back. The control channel briefly de-authenticates during a reconnect; clicking Choose in that window must
    // self-heal, not hard-fail.
    this.update({
      directoryBrowser: {
        loading: true,
        requestId,
        path: trimmed || current?.path || '',
        parent: current?.parent,
        entries: current?.entries ?? [],
        error: undefined,
      },
    })
    // listDirectories returns false when the request could NOT be sent — either the DataChannel isn't open (flap) OR
    // the control channel is mid-reconnect and not yet re-authenticated (auth flag resets until hello+auth completes).
    // Both are transient: RETRY across a realistic reconnect window (~15s) so the picker self-heals instead of erroring
    // with "not connected yet" the instant you click during a reconnect. Only after the window do we show the hint.
    const RETRY_MS = 500
    const MAX_TRIES = 30 // ~15s — long enough for a full WebRTC reconnect + re-auth
    const attempt = (tries: number): void => {
      // Bail if this request was superseded (a newer browse) or already resolved.
      const active = this.view.directoryBrowser
      if (!active || active.requestId !== requestId || !active.loading) return
      // `session` is null when we're not connected to a desktop (offline / mid-reconnect). authed:undefined in the
      // console means exactly this. Actively kick a reconnect so the picker RECOVERS instead of passively spinning.
      if (!this.session && !this.view.reconnectingNow && this.view.phase === 'offline') {
        void this.reconnect()
      }
      const sent = this.session?.listDirectories(requestId, trimmed || undefined) ?? false
      if (sent) return // reply (or the timeout below) will resolve it
      if (tries >= MAX_TRIES) {
        this.clearDirectoryBrowserTimer()
        const disconnected = !this.session
        this.update({
          directoryBrowser: {
            loading: false,
            requestId,
            path: trimmed || current?.path || '',
            parent: current?.parent,
            entries: current?.entries ?? [],
            error: disconnected
              ? 'Not connected to the desktop. Use "Back to sessions" / reconnect, then open New Project again.'
              : 'Folder browser could not reach the desktop (still reconnecting?). Wait a moment and press Refresh.',
          },
        })
        return
      }
      this.directoryBrowserRetryTimer = setTimeout(() => attempt(tries + 1), RETRY_MS)
    }
    attempt(0)
    // Backstop: if a send DID land but no reply comes (e.g. a stale agent), don't spin forever. 18s > the retry
    // window so a still-retrying request isn't cut off early.
    this.directoryBrowserTimer = setTimeout(() => {
      const active = this.view.directoryBrowser
      if (!active || active.requestId !== requestId || !active.loading) return
      this.update({
        directoryBrowser: {
          ...active,
          loading: false,
          error: 'Folder listing timed out. Check that the desktop agent is running (hydra-agent health), then Refresh.',
        },
      })
    }, 18000)
  }

  private clearDirectoryBrowserTimer(): void {
    if (this.directoryBrowserRetryTimer) {
      clearTimeout(this.directoryBrowserRetryTimer)
      this.directoryBrowserRetryTimer = null
    }
    if (!this.directoryBrowserTimer) return
    clearTimeout(this.directoryBrowserTimer)
    this.directoryBrowserTimer = null
  }

  private createInitialSessionIfRequested(targetDeviceId: string, sessions: readonly string[]): void {
    const pending = this.createSessionIfEmpty
    if (!pending || pending.targetDeviceId !== targetDeviceId) return
    this.createSessionIfEmpty = null
    if (sessions.length > 0 || this.view.creatingSession) return
    this.createSession(pending.cols, pending.rows)
  }

  /** End the passive startup/loading surface once the current connect tail has conclusively produced neither
   * an attach nor a create. This is intentionally called only after the synchronous or hydrated connect tail,
   * never on the intermediate `sessions: []` publication (create-on-empty starts just after that publication). */
  private settleTerminalAcquisitionIfIdle(): void {
    if (this.view.terminalAcquisition === null || this.view.phase !== 'sessions') return
    if (this.view.creatingSession || this.attachWatchdogs.size > 0) return
    this.update({ terminalAcquisition: null })
  }

  private clearPendingCreate(message: string | null): Partial<RemoteClientView> {
    if (!this.view.creatingSession && this.pendingRemoteCreations.size === 0) return {}
    const abandoned = this.abandonRemoteCreations()
    for (const attempt of abandoned) this.rollbackPendingSplitPane(attempt.splitPaneId)
    return { creatingSession: false, createSessionError: message }
  }

  // ── browser placed/stashed existence model (pane existence contract) ──────────────────
  //
  // The browser runs its OWN layout: `view.paneLayout` is the PLACED grid, `view.browserStashed` the stash of
  // panes that EXIST on local but aren't placed here. We keep the two fields separate (rather than a single
  // WorkspacePanes) so the ~68 existing paneLayout refs keep working; these helpers bridge to the pure model.

  /** Assemble the pure {@link WorkspacePanes} from the mirror view fields for a model call. The placed grid is
   * `null` when nothing meaningful is placed (a single empty placeholder pane = "empty grid"), matching the
   * model's empty-grid convention so reconcile/revive treat it as such. */
  private workspacePanes(): WorkspacePanes {
    return workspacePanesFrom(this.view.paneLayout, this.view.browserStashed)
  }

  /** Split a {@link WorkspacePanes} result back into the view's MIRROR (`paneLayout` + `browserStashed`) AND, when a
   * window is active, the per-window source of truth `paneLayoutsByWindow[activeWindowId]` — in ONE update so the
   * mirror and the map can never diverge across a render. A null placed layout (empty grid) becomes a fresh single
   * empty pane so the ~68 non-null paneLayout refs stay valid. `extra` is applied LAST (a caller passing
   * `extra.paneLayout`, e.g. revive setting activePaneId, still wins for the mirror). */
  private applyWorkspace(next: WorkspacePanes, extra: Partial<RemoteClientView> = {}): void {
    const mirror: Partial<RemoteClientView> = {
      paneLayout: next.layout ?? singlePane(),
      browserStashed: [...next.stashed],
      ...extra,
    }
    const patch: Partial<RemoteClientView> = { ...mirror }
    const active = this.view.activeWindowId
    if (active) {
      // Store the canonical WorkspacePanes for the active window, derived from the SAME mirror we just set (so the map
      // entry always equals what workspacePanes() would produce). Use the merged mirror's layout/stashed (extra wins).
      const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
      map[active] = preserveWindowStashed(
        workspacePanesFrom(mirror.paneLayout ?? singlePane(), mirror.browserStashed ?? []),
        map[active],
      )
      patch.paneLayoutsByWindow = map
    }
    this.update(patch)
  }

  /** Layout-only mutation helper: routes a raw new PaneLayout through applyWorkspace (keeping the current stash) so the
   * per-window map stays in sync. This is the funnel every direct `update({ paneLayout })` mutator must use. */
  private setActiveLayout(layout: PaneLayout, extra: Partial<RemoteClientView> = {}): void {
    this.applyWorkspace(workspacePanesFrom(layout, this.view.browserStashed), extra)
  }

  /** Local panes that EXIST (live or stashed on the desktop) from workspaceMetadata, as the reconcile input. */
  private existingLocalPanes(
    metadata: RemoteWorkspaceMetadata | null,
    windowId?: string,
  ): { paneId: string; sessionId: string | null; name?: string }[] {
    const out: { paneId: string; sessionId: string | null; name?: string }[] = []
    if (!metadata) return out
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        if (windowId !== undefined && window.id !== windowId) continue // per-window filter
        for (const pane of window.panes) {
          // The agent REDACTS a pane's session_id to "" while its session isn't live/visible (mid-creation,
          // hidden, or ended — remote_bridge filter_workspace_metadata). Normalize to null so the browser's
          // rows carry "no session yet" instead of a bogus ""-identity that can never match, attach, or revive.
          out.push({ paneId: pane.id, sessionId: pane.sessionId ? pane.sessionId : null, name: pane.name })
        }
      }
    }
    return out
  }

  /** The desktop window that OWNS `sessionId` (the window whose metadata panes include it), or null when the
   * metadata doesn't know the session. The containment source of truth. */
  private homeWindowForSession(metadata: RemoteWorkspaceMetadata | null, sessionId: string): string | null {
    if (!metadata) return null
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        if (window.panes.some((p) => p.sessionId === sessionId)) return window.id
      }
    }
    return null
  }

  /** CONTAINMENT: may `sessionId` be placed into the ACTIVE window's grid? True when its parent desktop window
   * IS the active window, when the metadata doesn't know the session (no containment info), or when no window
   * model is active (pre-metadata single-grid mode). */
  private sessionAllowedInActiveWindow(sessionId: string): boolean {
    const activeWin = this.view.activeWindowId
    if (!activeWin) return true
    const home = this.homeWindowForSession(this.view.workspaceMetadata, sessionId)
    return home === null || home === activeWin
  }

  /** CONTAINMENT (hard constraint): a pane/session must NEVER be placed — or stashed — under a browser window
   * other than its parent desktop window. Sanitize one restored per-window entry against current metadata:
   * every placed leaf / stash entry whose session's home window differs from `windowId` is DROPPED here
   * (survivors re-snap canonically); the per-window reconcile then re-stashes the session under its OWN home
   * window's entry — it is never re-placed cross-window. Sessions the metadata doesn't know keep their slot
   * (no containment info; the existence reconcile handles gone sessions). */
  private sanitizeRestoredEntry(
    windowId: string,
    ws: WorkspacePanes,
    metadata: RemoteWorkspaceMetadata | null,
  ): WorkspacePanes {
    const foreign = (sessionId: string | null) => {
      if (!sessionId) return false
      const home = this.homeWindowForSession(metadata, sessionId)
      return home !== null && home !== windowId
    }
    let out: WorkspacePanes = ws
    if (out.layout) {
      for (const leaf of leaves(out.layout.root)) {
        if (foreign(leaf.sessionId)) out = removePaneEverywhere(out, leaf.id)
      }
    }
    if (out.stashed.some((s) => foreign(s.sessionId))) {
      out = { ...out, stashed: out.stashed.filter((s) => !foreign(s.sessionId)) }
    }
    return out
  }

  /** R14 EVICTION (empty desktop): the metadata says NOTHING exists any more (last project deleted). The old
   * early-return left the whole stale world painted — dead grid, dead attachedSession, activeWindowId pointing
   * at a window that no longer exists ("panes visible after delete, focus undefined"). Evict: every held
   * channel detaches, every browser record and the ledger drop (deleted means gone, no tombstones), and the
   * view lands on the honest empty canvas (no active window, nothing attached), persisted immediately. */
  private evictEmptyDesktop(ownsRestore?: () => boolean): void {
    const placedNow = new Set<string>()
    for (const leaf of leaves(this.view.paneLayout.root)) if (leaf.sessionId) placedNow.add(leaf.sessionId)
    for (const ws of Object.values(this.view.paneLayoutsByWindow ?? {})) {
      if (ws?.layout) for (const leaf of leaves(ws.layout.root)) if (leaf.sessionId) placedNow.add(leaf.sessionId)
    }
    for (const sid of placedNow) {
      if (this.multiAttach.channelForSession(sid) !== null) this.detachSessionChannel(sid)
    }
    this.knownProjectIds.clear()
    this.knownWindowIds.clear()
    this.knownPaneIds.clear()
    this.pendingLandingWindows.clear()
    this.activeProjectIdHint = null
    this.focusedWindowByProject.clear()
    this.update({
      activeWindowId: null,
      paneLayout: singlePane(),
      browserStashed: [],
      paneLayoutsByWindow: {},
      attachedSession: null,
    })
    if (ownsRestore && !ownsRestore()) return
    this.persistLastLayout()
  }

  /** Desktop-authoritative visibility used when an existence mutation has made the active window unavailable.
   * Browser-local placement remains independent everywhere else; this predicate only chooses a non-blank landing
   * after the active window itself has no surviving browser placement. */
  private desktopWindowIsVisible(window: RemoteWorkspaceWindowMetadata): boolean {
    return !window.stashed && window.panes.some((pane) => !pane.stashed)
  }

  /** R14 EVICTION preference: when the ACTIVE window's project SURVIVES, stay in that project's first durably
   * visible window. Falls back to the visible Terminal system window, then any visible ordinary window. */
  private evictionFallbackWindowId(
    metadata: RemoteWorkspaceMetadata,
    preferredProjectId: string | null = this.activeProjectIdHint,
  ): string | null {
    const sameProject = preferredProjectId
      ? metadata.projects.find((p) => p.id === preferredProjectId)
      : undefined
    if (sameProject && sameProject.id !== PRODUCT_RECOVERY_PROJECT_ID) {
      const win = sameProject.windows.find((window) => this.desktopWindowIsVisible(window))?.id ?? null
      if (win) return win
    }
    return this.terminalFallbackWindowId(metadata)
      ?? metadata.projects
        .filter((project) => project.id !== PRODUCT_RECOVERY_PROJECT_ID)
        .flatMap((project) => project.windows)
        .find((window) => this.desktopWindowIsVisible(window))
        ?.id
      ?? null
  }

  /** The project that owns `windowId` per current metadata (containment lookup for the eviction hint). */
  private projectIdOfWindow(metadata: RemoteWorkspaceMetadata | null, windowId: string | null | undefined): string | null {
    if (!metadata || !windowId) return null
    return metadata.projects.find((p) => p.windows.some((w) => w.id === windowId))?.id ?? null
  }

  /** Browser visibility is presentation-local: an explicit browser window stash wins, then a browser placement;
   * only an untouched entry falls back to the desktop's durable stash/live flags. */
  private browserWindowIsVisible(
    window: RemoteWorkspaceWindowMetadata,
    map: Readonly<Record<string, WorkspacePanes>>,
  ): boolean {
    const ws = map[window.id]
    if (ws?.windowStashed && !ws.layout) return false
    if (ws?.layout) return true
    if (window.stashed) return false
    return window.panes.some((pane) => !pane.stashed)
  }

  private rememberProjectWindow(windowId: string): void {
    const projectId = this.projectIdOfWindow(this.view.workspaceMetadata, windowId)
    if (projectId) this.focusedWindowByProject.set(projectId, windowId)
  }

  /** R14 EVICTION target: the TERMINAL system project's first durably visible window. The Terminal project is
   * undeletable and normally supplies the guaranteed landing spot when the ACTIVE project is deleted. */
  private terminalFallbackWindowId(metadata: RemoteWorkspaceMetadata): string | null {
    const system = metadata.projects.find((p) => p.system)
    if (!system) return null
    return system.windows.find((window) => this.desktopWindowIsVisible(window))?.id ?? null
  }

  /** All desktop window ids in metadata, and which one should be active (focused → first with live panes → first). */
  private windowIdsFrom(metadata: RemoteWorkspaceMetadata): { ids: string[]; focused: string | null } {
    const ids: string[] = []
    let focused: string | null = null
    let firstLive: string | null = null
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        ids.push(window.id)
        if (window.focused && !focused) focused = window.id
        if (!firstLive && window.panes.some((p) => !p.stashed)) firstLive = window.id
      }
    }
    return { ids, focused: focused ?? firstLive ?? ids[0] ?? null }
  }

  /** ONCE per connect: fetch the durable per-window layout from the cloud (keyed by this device), seed
   * `paneLayoutsByWindow` for every window that still exists, then run the WHOLE connect tail (reconcile → default
   * bind → resume) against the hydrated map (Slice 2 ordering). Async + best-effort: a missing/failed fetch leaves the
   * map empty (everything reconciles to stashed, as before) and never blocks the grid. */
  /** Returns TRUE when the restore OWNS the connect tail for this list (the caller must NOT reconcile/bind/resume):
   * the first connect with metadata, AND any later list that arrives while the fetch is still in flight — the
   * continuation re-reads the CURRENT view, so nothing from those lists is lost, and the default bind can never fire
   * against a pre-hydration layout. Returns FALSE when there's nothing to restore (no metadata / no cloud dep) or the
   * restore already completed → the caller runs the tail synchronously as before. */
  private restoreLayoutFromCloud(metadata: RemoteWorkspaceMetadata | null): boolean {
    if (this.restoredLayoutThisConnect) return !this.layoutHydrated // in flight → continuation owns the tail
    const desk = this.view.selectedDevice
    if (!desk || !metadata || !this.deps.remoteLayout) return false
    this.restoredLayoutThisConnect = true
    // Logout/leave retires ownership even before a successor connect re-mints traceId. Both response paths must
    // preserve that retirement instead of hydrating, publishing or persisting the old account's layout.
    const gen = this.traceId
    const authGen = this.captureAuthGen()
    const connectionGen = this.connectionGeneration
    const ownsRestore = (): boolean => this.traceId === gen && !this.authGenChanged(authGen) &&
      this.connectionGeneration === connectionGen
    // Own the tail: run it inside the fetch continuation so the DB is seeded FIRST. Whether the DB has data, is
    // null, or errors, the tail runs exactly once here — onSessions skips its synchronous tail meanwhile.
    // SINGLE .then link (seed + tail together): splitting them across chained .then()s adds microtask
    // hops that reorder against callers awaiting the connect — keep the restore atomic from the queue's view.
    void this.deps.remoteLayout.fetchLayout(desk).then((json) => {
      if (!ownsRestore()) return
      const saved = json ? parseRemoteLayout(json) : null // exact safe v1/v2/v3 row; unsafe legacy rows fail closed
      if (saved) {
        const md = this.view.workspaceMetadata ?? metadata
        const metaWindowIds = new Set(this.windowIdsFrom(md).ids)
        const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
        // DB is AUTHORITATIVE on first connect: seed EVERY still-existing window with its saved WorkspacePanes (the
        // once-per-connect guard is the dedupe, not a "notPlaced" check — that defeated live restore). reconcile then
        // keeps placed sessions placed, stashes only genuinely-new local sessions, drops gone ones. Each entry is
        // CONTAINMENT-sanitized against current metadata first: a leaf/stash row whose session belongs to another
        // desktop window is dropped from this entry (its home window's reconcile re-stashes it there).
        for (const [windowId, ws] of Object.entries(saved.windows)) {
          if (metaWindowIds.has(windowId) && ws) map[windowId] = this.sanitizeRestoredEntry(windowId, ws, md)
        }
        // R8/R13: seed the known-id ledger from the row. v3 rows carry the REAL ledger; v1/v2 rows derive
        // known windows from the window keys ONCE (tolerant read). The R7 landing never re-applies to
        // recorded entities; the reconcile that follows prunes ids that no longer exist (R14).
        if (saved.known) {
          for (const id of saved.known.projects) this.knownProjectIds.add(id)
          for (const id of saved.known.windows) this.knownWindowIds.add(id)
          for (const id of saved.known.panes) this.knownPaneIds.add(id)
        } else {
          for (const windowId of Object.keys(saved.windows)) this.knownWindowIds.add(windowId)
        }
        this.update({ paneLayoutsByWindow: map })
      }
      // Publishing the seed may synchronously notify a subscriber that signs out or leaves.
      if (ownsRestore()) this.finishLayoutRestore(saved?.activeWindowId ?? null, ownsRestore)
    }, () => {
      if (!ownsRestore()) return
      this.finishLayoutRestore(null, ownsRestore) // a FAILED fetch must still run the tail (was: silently skipped)
    })
    return true
  }

  /** The connect tail that must run AGAINST the hydrated layout (Slice 2): mark hydration (persistence un-gates,
   * Slice 1), reconcile with the DB seed preferred over a trivial mirror + the persisted active window (S2-R2/R3),
   * then default-bind + resume. Reads the CURRENT view — a session_list/workspace_update that arrived while the
   * fetch was in flight is folded in here, not lost. */
  private finishLayoutRestore(savedActiveWindowId: string | null, ownsRestore: () => boolean): void {
    this.layoutHydrated = true
    this.reconcilePaneExistence(this.view.workspaceMetadata, { restoredActiveWindowId: savedActiveWindowId, ownsRestore })
    if (!ownsRestore()) return
    this.bindDefaultSessionIfIdle(this.view.sessions, this.view.lastOpenedSessionId)
    if (!ownsRestore()) return
    this.resumePanes(this.view.sessions, ownsRestore)
    if (!ownsRestore()) return
    this.settleTerminalAcquisitionIfIdle()
    if (!ownsRestore()) return
    this.scheduleStartupHydrationOrHistory()
  }

  /** True when the active mirror carries no user-built placement: an empty grid, or a single pane that is empty or
   * holds only the default-bound/resume session. Used by the restore-owned reconcile (S2-R2): a trivial mirror must
   * not beat the DB seed as the `before` state; a mirror with real structure (splits / other sessions — e.g. a live
   * reconnect layout) always wins. */
  private mirrorIsTrivial(): boolean {
    const ws = this.workspacePanes()
    if (!ws.layout) return true
    const ls = leaves(ws.layout.root)
    if (ls.length > 1) return false
    const sid = ls[0]!.sessionId
    return sid === null || sid === this.resumeSessionId
  }

  /**
   * Existence-sync (Task #600), PER WINDOW: reconcile each desktop window's browser layout against the panes that
   * EXIST in that window on local. New local panes land in that window's `browserStashed`; killed panes are dropped;
   * the placed layout + activePaneId of the ACTIVE window are preserved. Windows gone from metadata are pruned from the
   * map. The active window is (re)chosen from metadata's focused window on first connect / when the current active
   * window disappears. BROWSER-LOCAL, content-blind. No-op when metadata is null.
   *
   * `restore` is passed ONLY by the DB-restore continuation (finishLayoutRestore) and carries the persisted active
   * window (v2 rows; null for v1). It makes this reconcile SEED-PREFERRING (S2-R2/R3): land on the persisted active
   * window when it still exists, and when the current mirror is TRIVIAL (a raced workspace_update / second
   * session_list adopted a window before the fetch landed) force re-adoption so the seeded map entry — not the
   * near-empty mirror — is the `before` state, with any mirror-bound session MERGED in via the adoption funnel. */
  /** Lifecycle observability (pane lifecycle contract): the windows currently in the `landing-pending` state —
   * designated for the R7 first-sight landing but with nothing placeable yet (mid-creation pushes carry the
   * pane's session_id redacted to "" until its session is live). Read-only; for tests, the scenario-matrix
   * generator, and diagnostics. Content-blind (window ids only). */
  landingPendingWindowIds(): readonly string[] {
    return [...this.pendingLandingWindows]
  }

  /** Shell UX: surface a transient status hint through the SAME channel as desktop action results
   * (`desktopActionMessage` — cleared by the next action, exactly like 'Pane closed.' etc.). Content-blind
   * (fixed UI copy only). Lets app-shell explain a click on a still-starting (landing-pending) row. */
  noteTransientMessage(text: string): void {
    this.update({ desktopActionMessage: text })
  }

  private reconcilePaneExistence(
    metadata: RemoteWorkspaceMetadata | null,
    restore?: { restoredActiveWindowId: string | null; ownsRestore: () => boolean },
  ): void {
    if (!metadata) {
      // R14 EVICTION (window model went away entirely): deleting the LAST project reaches us as a null
      // metadata — the agent parse collapses an empty project list to null. If this browser WAS in window
      // mode (an active window / per-window rows exist), nothing exists on the desktop any more → evict to
      // the honest empty canvas. A metadata-less agent (single-grid mode) never set those, so it keeps its
      // legacy early-return.
      if (this.view.activeWindowId || Object.keys(this.view.paneLayoutsByWindow ?? {}).length > 0) {
        this.evictEmptyDesktop(restore?.ownsRestore)
      }
      return
    }
    const { ids: metaWindowIds, focused } = this.windowIdsFrom(metadata)
    if (metaWindowIds.length === 0) {
      // R14 EVICTION (projects exist but carry no windows): same as above — nothing placeable exists.
      this.evictEmptyDesktop(restore?.ownsRestore)
      return
    }

    // R14 (pruning): the ledger retains ONLY currently existing entities — deleted means gone, no tombstones.
    // A project/window/pane that left the metadata leaves the ledger too (if it ever reappears under the same
    // id, it is first-handoff again). `prevKnownPaneIds` is snapshotted BEFORE the prune for the per-window
    // gone-desktop-row sweep below (a just-deleted pane must still be recognizable as desktop-owned).
    const metaProjectIds = new Set(metadata.projects.map((p) => p.id))
    const metaPaneIds = new Set<string>()
    for (const project of metadata.projects) for (const w of project.windows) for (const p of w.panes) metaPaneIds.add(p.id)
    const prevKnownPaneIds = new Set(this.knownPaneIds)
    for (const id of [...this.knownProjectIds]) if (!metaProjectIds.has(id)) this.knownProjectIds.delete(id)
    for (const id of [...this.knownWindowIds]) if (!metaWindowIds.includes(id)) this.knownWindowIds.delete(id)
    for (const id of [...this.knownPaneIds]) if (!metaPaneIds.has(id)) this.knownPaneIds.delete(id)
    for (const [projectId, windowId] of [...this.focusedWindowByProject]) {
      const owner = metadata.projects.find((project) => project.id === projectId)
      if (!owner?.windows.some((window) => window.id === windowId)) this.focusedWindowByProject.delete(projectId)
    }

    // Item A (channel leak): snapshot every session PLACED anywhere (the active-window mirror + every window in
    // the map) BEFORE reconciling. A reconcile can remove placed panes (the desktop closed them / their window is
    // gone from metadata); the removed sessions' live channels must be detached like the user-initiated close
    // path does, or the daemon keeps streaming into a bank nobody renders. Compared against placedAfter below.
    const placedBefore = new Set<string>()
    for (const leaf of leaves(this.view.paneLayout.root)) if (leaf.sessionId) placedBefore.add(leaf.sessionId)
    for (const ws of Object.values(this.view.paneLayoutsByWindow ?? {})) {
      if (ws?.layout) for (const leaf of leaves(ws.layout.root)) if (leaf.sessionId) placedBefore.add(leaf.sessionId)
    }

    // Repair the active window: keep it if still present, else adopt metadata's focused/first. Load its map entry into
    // the mirror so the loop below reconciles the ACTIVE window against the mirror (and preserves its active pane).
    let activeWindowId = this.view.activeWindowId
    // R14 EVICTION (active project deleted): the window the user is LOOKING AT left the metadata mid-session
    // (project/window deleted on either side — the remote's own delete ack and a desktop-initiated delete both
    // arrive HERE as a push without it). The guaranteed fallback is the TERMINAL system project (undeletable,
    // never loses its last window/pane): switch to its live window; the generic focused/first pick stays only
    // as a defensive fallback when Terminal is somehow absent. `restore` reconciles are NOT deletions.
    const activeDied = !restore && Boolean(activeWindowId) && !metaWindowIds.includes(activeWindowId!)
    const mapBefore = { ...(this.view.paneLayoutsByWindow ?? {}) }
    // Restore-owned reconcile (S2-R2/R3): decide the adoption target from the persisted active window + the DB seed.
    let adoptPreferred: string | null = null
    if (restore) {
      const preferred =
        restore.restoredActiveWindowId && metaWindowIds.includes(restore.restoredActiveWindowId)
          ? restore.restoredActiveWindowId
          : null
      const seedTarget = preferred ?? activeWindowId ?? null // v1 rows: prefer the seed of whatever window is active
      if (this.mirrorIsTrivial() && (preferred || (seedTarget && mapBefore[seedTarget]?.layout))) {
        // The mirror has nothing the user built here — force re-adoption below so the DB seed becomes `before`
        // (and the user lands back on the persisted window). Mirror-bound sessions are merged, never clobbered.
        adoptPreferred = seedTarget
        activeWindowId = null
      } else if (preferred) {
        adoptPreferred = preferred // non-trivial mirror keeps its window; used only if adoption runs anyway
      }
    }
    if (!activeWindowId || !metaWindowIds.includes(activeWindowId)) {
      activeWindowId = adoptPreferred && metaWindowIds.includes(adoptPreferred)
        ? adoptPreferred
        : (activeDied ? this.evictionFallbackWindowId(metadata) : null) ?? focused
      let target = (activeWindowId && mapBefore[activeWindowId]) || emptyWorkspace()
      // MERGE the mirror's bound sessions into the adopted target — do NOT clobber them. The synchronous
      // default bind (bindDefaultSessionIfIdle) + resumePanes may already have bound AND attached a session
      // while the DB restore was in flight. Replacing the mirror wholesale left that session attached but
      // UNPLACED (often still in the target's stashed list) — one session with two contradictory homes. The
      // renderer then fell back to the legacy full-height single canvas (no pane chrome, overflowing), and a
      // later revive reused the stale channel with no baseline grid → a permanently blank pane. Re-place each
      // bound session through the canonical revive funnel (same as setActiveWindow's auto-place) so
      // placed/stashed stays a strict partition and the live attach stays valid.
      for (const leaf of leaves(this.view.paneLayout.root)) {
        const sid = leaf.sessionId
        if (!sid) continue
        // R14: a session the desktop no longer runs must NOT be merged forward — a deleted project's placed
        // panes used to ride the adoption into the fallback window and survive every later reconcile (the
        // "deleted project's panes stay visible" half of the delete bug). Dead sessions simply drop here.
        if (!this.view.sessions.includes(sid)) continue
        if (target.layout && leaves(target.layout.root).some((l) => l.sessionId === sid)) continue // already placed
        // CONTAINMENT: never merge a session into a window that is not its parent desktop window — it stays
        // (or reappears via the per-window reconcile) in its OWN window's stash instead of leaking here.
        const home = this.homeWindowForSession(metadata, sid)
        if (home && activeWindowId && home !== activeWindowId) continue
        // Prefer the pane id the session already has here: the target's stash entry, else the DESKTOP pane id
        // (so the placed leaf matches what a stashed-row revive would produce), else the mirror leaf id.
        const entry = target.stashed.find((s) => s.sessionId === sid)
        const desktopPaneId = activeWindowId
          ? this.existingLocalPanes(metadata, activeWindowId).find((e) => e.sessionId === sid)?.paneId
          : undefined
        const paneId = entry?.paneId ?? desktopPaneId ?? leaf.id
        const base = entry ? target : addStashed(target, paneId, sid)
        const placed = reviveInWorkspace(base, paneId)
        if (placed !== base) target = placed // grid full → leave it stashed; reconcile below keeps it revivable
      }
      // Set the mirror + activeWindowId so workspacePanes() below reflects the (possibly new) active window.
      this.update({
        activeWindowId,
        paneLayout: target.layout ?? singlePane(),
        browserStashed: [...target.stashed],
      })
      // Subscribers may synchronously retire this restore; do not carry captured metadata into their new view.
      if (restore && !restore.ownsRestore()) return
    }

    // R12 (desktop non-mutation after handoff): the desktop's per-pane `stashed` flag feeds ONLY the R7
    // landing decision below (a desktop-stashed pane never auto-places on first sight). After a project's
    // first handoff the desktop must NOT mutate the remote's layout/stash — existence add/remove is its only
    // influence. The former R2/R3 mirroring (desktop stash transition → unplace the remote pane) is REMOVED:
    // a desktop stash of a known entity leaves the remote placement untouched.
    const desktopStashedNow = new Map<string, boolean>()
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        for (const pane of window.panes) {
          if (pane.sessionId) desktopStashedNow.set(pane.sessionId, Boolean(pane.stashed))
        }
      }
    }

    // R7 (first-sight landing) + R8/R13 (first-handoff dedup, PROJECT-scoped via the persisted ledger): the R4
    // stash landing rule is SOFTENED exactly once per project — a project not yet in the known-project ledger
    // (not in the restored cloud row's ledger, not recorded by any post-hydration reconcile) prefers landing
    // its FIRST window's first live pane PLACED, so the first click knows what to draw (local model: a freshly
    // seeded project is one window + one pane, always live — maestro-app seed_default_project_window /
    // bootstrap_system_terminal_if_empty). Every other window/pane of a known project keeps the R4 landing
    // (stashed). Gated on hydration so a push racing the cloud fetch can't consume the one-shot against a
    // pre-restore ledger.
    const landingEligible = this.layoutHydrated || !this.deps.remoteLayout
    const liveLandingWindows = new Set<string>()
    if (landingEligible) {
      for (const project of metadata.projects) {
        if (project.windows.length === 0) continue
        if (this.knownProjectIds.has(project.id)) continue // R13: handed-off project → R4 for new windows
        if (project.windows.some((w) => this.knownWindowIds.has(w.id))) continue // v1/v2 rows: window-derived known
        liveLandingWindows.add(project.windows[0]!.id)
      }
      // Landing-PENDING windows stay eligible across pushes even though line ~2034 already recorded them as
      // known (a desktop create arrives as several pushes; the first sight often has nothing placeable yet —
      // the pane's session_id is redacted until the session is live). Lifecycle: `landing-pending` state.
      for (const id of this.pendingLandingWindows) {
        if (metaWindowIds.includes(id)) liveLandingWindows.add(id)
      }
    }
    // Prune pending designations for windows that no longer exist on the desktop.
    for (const id of [...this.pendingLandingWindows]) {
      if (!metaWindowIds.includes(id)) this.pendingLandingWindows.delete(id)
    }

    // Reconcile EACH window. The active window writes through applyWorkspace (mirror + map); non-active windows
    // accumulate into a map patch (not visible, so no mirror change).
    const nextMap: Record<string, WorkspacePanes> = {}
    let activeLostPlacedSessionExistence = false
    for (const windowId of metaWindowIds) {
      const isActive = windowId === activeWindowId
      const before = isActive ? this.workspacePanes() : (mapBefore[windowId] ?? emptyWorkspace())
      const existing = this.existingLocalPanes(metadata, windowId)
      // SAFETY: treat this window's PLACED sessions as existing so metadata lag can't stash a just-attached
      // active pane — but ONLY while the session is still in the live list. An unconditional pass here kept a
      // DESKTOP-KILLED pane (gone from metadata AND from `sessions`) placed forever: the deleted pane/project
      // stayed painted through every later push (R14 violation; the visible half of the delete-project bug).
      const existingSessions = new Set(existing.map((e) => e.sessionId).filter((s): s is string => !!s))
      if (
        isActive
        && !restore
        && !activeDied
        && before.layout
        && leaves(before.layout.root).some((leaf) =>
          leaf.sessionId
          && !existingSessions.has(leaf.sessionId)
          && !this.view.sessions.includes(leaf.sessionId))
      ) {
        // This is an existence loss, not a deliberate browser-local empty/stash action: a previously placed
        // live session disappeared from both the durable pane rows and daemon inventory during this reconcile.
        activeLostPlacedSessionExistence = true
      }
      if (before.layout) {
        for (const leaf of leaves(before.layout.root)) {
          if (leaf.sessionId && !existingSessions.has(leaf.sessionId) && this.view.sessions.includes(leaf.sessionId)) {
            existing.push({ paneId: leaf.sessionId, sessionId: leaf.sessionId })
          }
        }
      }
      // BUG-1 heal precompute: stash rows that are still SESSION-LESS going into this reconcile — if the push
      // names one of them while this window's grid holds an optimistic split-reserve leaf, the naming completes
      // INTO the reserve (see the heal below), not as a grey stash row next to an "Empty pane".
      const sessionlessBefore = new Set(before.stashed.filter((s) => !s.sessionId).map((s) => s.paneId))
      let after = reconcileExistence(before, existing)
      // R14 (pruning): reconcileExistence prunes by SESSION identity, but a row that never got a session
      // (redacted mid-creation pane whose desktop pane was killed before its session went live) has none.
      // Prune session-less rows whose DESKTOP pane id is gone: rows in a landing-pending window, or rows
      // whose pane id is in the known-pane ledger, are desktop-owned — a browser-minted empty split leaf
      // (pane-N id, never in metadata/ledger, window not pending) is never touched.
      {
        const existingPaneIds = new Set(existing.map((e) => e.paneId))
        const pendingWindow = this.pendingLandingWindows.has(windowId)
        const goneDesktopRow = (paneId: string, sessionId: string | null): boolean =>
          !sessionId && !existingPaneIds.has(paneId) && (pendingWindow || prevKnownPaneIds.has(paneId))
        if (after.stashed.some((s) => goneDesktopRow(s.paneId, s.sessionId))) {
          after = { ...after, stashed: after.stashed.filter((s) => !goneDesktopRow(s.paneId, s.sessionId)) }
        }
        if (after.layout) {
          for (const l of leaves(after.layout.root)) {
            if (goneDesktopRow(l.id, l.sessionId)) after = removePaneEverywhere(after, l.id)
          }
        }
      }
      // SPLIT-RESERVE HEAL (BUG-1; lifecycle `session-named` completing INTO the reserve): a browser-initiated
      // split reserves an optimistic EMPTY leaf, but the desktop's redaction race pushes the new pane as a
      // SEPARATE record ({desktopPaneId, session:""} stash row) — and a refresh persists exactly that split
      // world (empty leaf + session-less row). When the push that NAMES the row arrives while this window's
      // grid still holds an empty NON-desktop leaf (the reserve — a browser-minted id, so provably not a
      // desktop pane), the upgrade completes into the reserve: the leaf adopts the desktop pane id + session
      // and the stash row drops. One pane, one identity — instead of "Empty pane · active" + a grey row that
      // never lights up (the live "split pane never appears" bug). R4 is not weakened: a reserve leaf only
      // exists while a browser-side create is in flight (or restored from one) — plain desktop-created panes
      // still land stashed because no reserve exists to adopt them.
      if (after.layout) {
        const windowPaneIds = new Set(existing.map((e) => e.paneId))
        for (const row of [...after.stashed]) {
          if (!after.layout) break
          if (!row.sessionId || !sessionlessBefore.has(row.paneId)) continue
          const reserve = leaves(after.layout.root).find((l) => !l.sessionId && !windowPaneIds.has(l.id))
          if (!reserve) break
          const renamed = renamePaneId(after.layout, reserve.id, row.paneId)
          if (renamed === after.layout) continue // id collision → leave the row stashed (revive still works)
          after = {
            ...after,
            layout: setPaneSessionInLayout(renamed, row.paneId, row.sessionId),
            stashed: after.stashed.filter((s) => s !== row),
          }
          for (const attempt of this.pendingRemoteCreations.values()) {
            if (attempt.targetPaneId === reserve.id) attempt.targetPaneId = row.paneId
            if (attempt.splitPaneId === reserve.id) attempt.splitPaneId = null // completed by the push
          }
        }
      }
      // R7 first-sight landing: nothing placed yet in a first-seen project's FIRST window → place its first
      // desktop-LIVE pane (the rest stay stashed/revivable, R4). Desktop-stashed panes never auto-place.
      // Lifecycle transitions (pane lifecycle contract): `landing-placed` (pane live → placed),
      // `landing-deferred` (nothing placeable yet → landing-pending), `landing-burned` (deliberate desktop
      // stash, or the window already has state → the one-shot is consumed and R4 stands).
      if (liveLandingWindows.has(windowId)) {
        if (!after.layout && !after.windowStashed) {
          const firstLive = after.stashed.find((s) =>
            s.sessionId && this.view.sessions.includes(s.sessionId) && desktopStashedNow.get(s.sessionId) !== true)
          if (firstLive) {
            const placed = reviveInWorkspace(after, firstLive.paneId)
            if (placed !== after) after = placed
            this.pendingLandingWindows.delete(windowId) // landing-placed (or defensively burned)
          } else if (after.stashed.some((s) => s.sessionId && this.view.sessions.includes(s.sessionId))) {
            // A live pane exists but every live pane is DESKTOP-stashed — a deliberate stash is a decided
            // presentation. Burn the one-shot: landing never auto-revives a desktop-stashed pane (R4 stands).
            this.pendingLandingWindows.delete(windowId)
          } else {
            // Nothing placeable YET (mid-creation push: the pane's session_id stays redacted until its session
            // is live — agent remote_bridge filter). Keep the landing PENDING so the push that finally names a
            // live session completes it. This is the fix for "desktop-created project lands all grey":
            // the redacted first push used to burn the one-shot here.
            this.pendingLandingWindows.add(windowId)
          }
        } else {
          this.pendingLandingWindows.delete(windowId) // window already has state (placed / user-stashed) → burned
        }
      }
      if (isActive) {
        // Preserve the active pane id when the placed layout still contains it.
        const active = this.view.paneLayout.activePaneId
        const layout = after.layout && findLeaf(after.layout, active) ? { ...after.layout, activePaneId: active } : after.layout
        this.applyWorkspace({ ...after, layout }) // updates mirror + nextMap[activeWindowId] indirectly
        if (restore && !restore.ownsRestore()) return
        nextMap[windowId] = this.workspacePanes() // capture the post-apply active window state
      } else {
        nextMap[windowId] = after
      }
    }

    // If existence reconciliation removed the placed pane but the SAME durable window still has another
    // non-stashed pane, keep project/window focus stable. Prefer its first live survivor; an exited-only survivor
    // is started after the reconciled patch commits. This runs only for the placed-session loss detected above,
    // so a user-deliberate browser stash/empty layout is never auto-filled by an unrelated metadata refresh.
    let activeExistenceRecoveryPlaced = false
    let activeExistenceStartPaneId: string | null = null
    if (activeLostPlacedSessionExistence && activeWindowId && !nextMap[activeWindowId]?.layout) {
      const owner = metadata.projects.find((project) => project.windows.some((window) => window.id === activeWindowId))
      const activeWindow = owner?.windows.find((window) => window.id === activeWindowId)
      if (
        owner
        && owner.id !== PRODUCT_RECOVERY_PROJECT_ID
        && activeWindow
        && this.desktopWindowIsVisible(activeWindow)
      ) {
        const liveSurvivor = activeWindow.panes.find((pane) =>
          !pane.stashed
          && Boolean(pane.sessionId)
          && this.view.sessions.includes(pane.sessionId))
        if (liveSurvivor) {
          const entry = nextMap[activeWindowId] ?? emptyWorkspace()
          const cleaned: WorkspacePanes = {
            layout: entry.layout,
            stashed: entry.stashed.filter((pane) =>
              pane.paneId !== liveSurvivor.id && pane.sessionId !== liveSurvivor.sessionId),
          }
          const seeded = addStashed(cleaned, liveSurvivor.id, liveSurvivor.sessionId)
          const placed = reviveInWorkspace(seeded, liveSurvivor.id)
          if (placed !== seeded) {
            nextMap[activeWindowId] = placed
            this.pendingLandingWindows.delete(activeWindowId)
            activeExistenceRecoveryPlaced = true
          }
        } else {
          activeExistenceStartPaneId = activeWindow.panes.find((pane) => !pane.stashed)?.id ?? null
        }
      }
    }

    // A guarded final-pane Remove can leave its WINDOW record in metadata while making that window durably
    // non-visible (zero non-stashed durable panes, or the window/final pane is stashed). `activeDied` does not catch
    // that case
    // because the id still exists. Once reconciliation proves the active browser entry has no placement either,
    // treat it like an eviction: stay in a visible sibling window when possible, then use Terminal/global fallback.
    // A browser-revived desktop-stashed window with a surviving placement remains active (R12 independence).
    let activeBecameUnavailable = false
    if (!restore && activeWindowId) {
      const owner = metadata.projects.find((project) => project.windows.some((window) => window.id === activeWindowId))
      const activeWindow = owner?.windows.find((window) => window.id === activeWindowId)
      const activeEntry = nextMap[activeWindowId]
      if (
        owner
        && owner.id !== PRODUCT_RECOVERY_PROJECT_ID
        && activeWindow
        && !this.desktopWindowIsVisible(activeWindow)
        && !activeEntry?.layout
      ) {
        const fallback = this.evictionFallbackWindowId(metadata, owner.id)
        if (fallback && fallback !== activeWindowId) {
          activeWindowId = fallback
          activeBecameUnavailable = true
        }
      }
    }

    // R8/R13: everything this reconcile recorded is now KNOWN — recorded in the persisted ledger, so landing
    // never re-applies to it. First-handoff is PROJECT-scoped: a project whose landing is still PENDING
    // (nothing placeable yet) is NOT recorded — the next push may still complete its landing, and a refresh
    // mid-creation re-derives it as unknown. Only post-hydration reconciles record (a pre-hydration push must
    // not burn the one-shot before the cloud row seeded the ledger).
    if (landingEligible) {
      for (const project of metadata.projects) {
        if (project.windows.some((w) => this.pendingLandingWindows.has(w.id))) continue // landing unresolved
        this.knownProjectIds.add(project.id)
        for (const w of project.windows) {
          this.knownWindowIds.add(w.id)
          for (const p of w.panes) this.knownPaneIds.add(p.id)
        }
      }
    }
    // R14 EVICTION fallback placement: landing on the Terminal window after a deletion must show a live
    // terminal, not a blank grid — when the eviction target ended this reconcile with nothing placed,
    // auto-place its first LIVE stashed pane through the normal revive path (the same rule as
    // setActiveWindow's empty-grid auto-place; attachPlacedPanes below attaches it).
    let evictionPlaced = false
    let evictionStartPaneId: string | null = null
    if ((activeDied || activeBecameUnavailable) && activeWindowId && nextMap[activeWindowId] && !nextMap[activeWindowId].layout) {
      const entry = nextMap[activeWindowId]
      const first = entry.stashed.find((s) => s.sessionId && this.view.sessions.includes(s.sessionId))
      if (first) {
        const placed = reviveInWorkspace(entry, first.paneId)
        if (placed !== entry) {
          nextMap[activeWindowId] = placed
          this.pendingLandingWindows.delete(activeWindowId)
          evictionPlaced = true
        }
      }
      // A durable survivor can be visible yet contain only Exited panes (`live:false`, or a session id absent
      // from the daemon list). Native focus restarts that pane instead of landing on a permanent blank grid;
      // queue the same start/confirm path after the active-window patch commits below.
      if (!nextMap[activeWindowId].layout) {
        evictionStartPaneId = metadata.projects
          .flatMap((project) => project.windows)
          .find((window) => window.id === activeWindowId)
          ?.panes
          .find((pane) => !pane.stashed)?.id
          ?? null
      }
    }
    // Slice 3 partition invariant: repair any placed/stashed inconsistency toward metadata BEFORE committing —
    // a session placed in two windows keeps only its metadata home window's placement; an in-window stash
    // duplicate of a placed session is dropped. When the ACTIVE window's entry was repaired, re-sync the mirror
    // in the same update so mirror and map can never diverge across a render.
    const repaired = this.repairPartition(nextMap, metadata) || evictionPlaced || activeExistenceRecoveryPlaced
    const activeWindowChanged = activeWindowId !== this.view.activeWindowId
    const patch: Partial<RemoteClientView> = { paneLayoutsByWindow: nextMap }
    if (activeWindowChanged) patch.activeWindowId = activeWindowId
    if ((repaired || activeWindowChanged) && activeWindowId && nextMap[activeWindowId]) {
      const entry = nextMap[activeWindowId]
      const active = this.view.paneLayout.activePaneId
      const layout = entry.layout && findLeaf(entry.layout, active) ? { ...entry.layout, activePaneId: active } : entry.layout
      patch.paneLayout = layout ?? singlePane()
      patch.browserStashed = [...entry.stashed]
    }
    // Commit the pruned/updated map (drops windows no longer in metadata). Mirror already set for the active window.
    this.update(patch)
    if (restore && !restore.ownsRestore()) return
    // Item A (channel leak): any session that LOST its placement in this reconcile (its pane/window was closed on
    // the desktop, or it fell back to the stash) must release its live channel — the same detach sequence the
    // user-initiated close path (closePane/stashBrowserPane) runs. Only sessions that actually HOLD a channel are
    // detached (a DB-restored placement that never attached has nothing to release; a bare wire-detach for it
    // could wrongly decrement the daemon's serving count). Stash-fallen sessions match stash semantics: revive
    // re-attaches freshly, so dropping the channel here is the correct baseline-safe behavior.
    const placedAfter = new Set<string>()
    for (const leaf of leaves(this.view.paneLayout.root)) if (leaf.sessionId) placedAfter.add(leaf.sessionId)
    for (const ws of Object.values(this.view.paneLayoutsByWindow ?? {})) {
      if (ws?.layout) for (const leaf of leaves(ws.layout.root)) if (leaf.sessionId) placedAfter.add(leaf.sessionId)
    }
    for (const sid of placedBefore) {
      if (placedAfter.has(sid)) continue
      if (this.multiAttach.channelForSession(sid) === null) continue // never attached → nothing to release
      this.detachSessionChannel(sid)
    }
    // A reconcile can PLACE panes that were never attached this connection (DB-restored multi-pane layout, the
    // adoption merge above). Attach them now so their tiles paint instead of sitting on placeholders.
    this.attachPlacedPanes()
    // Invariant 3 (Slice 4): a reconcile that dropped the attached session's placement must clear it — the
    // legacy full-height canvas must never paint an unplaced ("stashed") session.
    this.enforceAttachedSessionPlacement()
    if (restore && !restore.ownsRestore()) return
    // Slice 1: make the reconciled partition durable — the old gap (reconcile never persisted) meant the healed
    // in-memory state was lost unless the user happened to perform a persisting mutation before the next refresh.
    // No-op until the restore continuation hydrated the map (invariant 4).
    this.persistLastLayout()
    if (restore && !restore.ownsRestore()) return
    // Track the ACTIVE window's project for the R14 eviction preference (same-project before Terminal).
    this.activeProjectIdHint = this.projectIdOfWindow(metadata, this.view.activeWindowId) ?? this.activeProjectIdHint
    if (this.view.activeWindowId) this.rememberProjectWindow(this.view.activeWindowId)
    const startPaneId = activeExistenceStartPaneId ?? evictionStartPaneId
    if (startPaneId) {
      this.startPaneSessionForRemote(
        startPaneId,
        this.lastAttachSize.cols,
        this.lastAttachSize.rows,
      )
      if (restore && !restore.ownsRestore()) return
    }
    // R7 (creation liveness): a create THIS BROWSER initiated may have been waiting for this metadata to name
    // its home window — complete it now (place live + make the window active + attach + persist).
    this.completeSelfCreatedPlacements()
  }

  /** R7 — try to complete every pending self-created placement against CURRENT metadata. A session whose home
   * window is now known lands PLACED in that window (desktop-pane-id keyed), the window becomes active, its
   * terminal attaches at the create's viewport size, and the row persists immediately ("born known": R8's
   * dedup then keeps every later push/refresh from re-landing it). Sessions metadata doesn't know yet stay
   * queued for the next reconcile. */
  private completeSelfCreatedPlacements(): void {
    if (this.pendingSelfCreated.size === 0) return
    for (const [sessionId, size] of [...this.pendingSelfCreated]) {
      const home = this.homeWindowForSession(this.view.workspaceMetadata, sessionId)
      if (!home) continue // metadata hasn't caught up — keep it queued
      const paneId = this.desktopPaneIdForSession(sessionId)
      if (!paneId) continue
      if (this.desktopPaneIsStashed(paneId)) {
        // Keep this placement queued while another desktop mutation owns the single creation UI lane. Starting
        // an internal revive concurrently used to overwrite the user's pending geometry/target and let either
        // reply clear the other's busy state. The next metadata/reconcile pass retries this strictly in order.
        if (this.view.creatingSession) continue
        this.pendingSelfCreated.delete(sessionId)
        this.startPaneSessionForRemote(paneId, size.cols, size.rows)
        continue
      }
      this.pendingSelfCreated.delete(sessionId)
      // placeDesktopPaneRemote is the canonical funnel: switches to the home window, places the pane under its
      // desktop id (or focuses it if the R7 landing already placed it), attaches, and persists.
      this.placeDesktopPaneRemote(paneId, size.cols, size.rows)
      this.schedulePostCreateFreshAttach(sessionId, size)
      // R13 "born known": record the whole self-created project in the ledger immediately, so no later
      // push/refresh can re-land it (its row + ledger persist in the same PUT).
      this.knownWindowIds.add(home)
      const project = this.view.workspaceMetadata?.projects.find((p) => p.windows.some((w) => w.id === home))
      if (project) {
        this.knownProjectIds.add(project.id)
        for (const w of project.windows) {
          this.knownWindowIds.add(w.id)
          for (const p of w.panes) this.knownPaneIds.add(p.id)
        }
      }
      this.persistLastLayout()
    }
  }

  /** R7 — record a session THIS BROWSER just created (project_create seed / new_window). When metadata already
   * knows its home window the placement completes immediately; otherwise it completes on the next reconcile.
   * With no window model at all (metadata-less agent → single-grid mode) fall back to the classic immediate
   * attach into the active pane — there is no landing rule to bypass there. */
  private noteSelfCreatedSession(sessionId: string, size: { cols: number; rows: number }): void {
    if (!this.view.workspaceMetadata) {
      this.attach(sessionId, size.cols, size.rows)
      return
    }
    this.pendingSelfCreated.set(sessionId, size)
    this.completeSelfCreatedPlacements()
  }

  /** A remote-created pane can attach before the local desktop has finished spreading/repainting the new pane at
   * the browser-requested size. A page refresh repairs that by reattaching and receiving a fresh full Grid; this
   * performs the same repair narrowly for the just-created session after its first attach has had time to land. */
  private schedulePostCreateFreshAttach(sessionId: string, size: { cols: number; rows: number }): void {
    const existing = this.postCreateFreshAttachTimers.get(sessionId)
    if (existing) clearTimeout(existing)
    const timer = setTimeout(() => {
      this.postCreateFreshAttachTimers.delete(sessionId)
      if (!this.view.sessions.includes(sessionId)) return
      if (!leaves(this.view.paneLayout.root).some((leaf) => leaf.sessionId === sessionId)) return
      // If the first attach is still in flight, the attach watchdog's existing one-shot retry owns recovery.
      // Sending another attach now would duplicate the pending request and surface already_attached noise.
      if (this.attachWatchdogs.has(sessionId) && this.multiAttach.channelForSession(sessionId) === null) return
      this.lastAttachSize = size
      this.reattachSessionFresh(sessionId)
    }, POST_CREATE_FRESH_ATTACH_MS)
    timer.unref?.()
    this.postCreateFreshAttachTimers.set(sessionId, timer)
  }

  /** Pane lifecycle partition invariant: within one window entry a
   * session appears at most ONCE (placed XOR stashed); across the whole map a session is PLACED in at most one
   * window. Repairs toward metadata: a doubly-placed session keeps its metadata HOME window's placement
   * (fallback: the first holder in metadata window order); in-window stash duplicates of placed sessions are
   * dropped. Mutates `map` in place; returns true when anything changed. */
  private repairPartition(map: Record<string, WorkspacePanes>, metadata: RemoteWorkspaceMetadata | null): boolean {
    let changed = false
    // (a) cross-window: a session placed in >1 window keeps only its home window's leaf.
    const holders = new Map<string, string[]>() // sessionId → windowIds where it is PLACED
    for (const [windowId, ws] of Object.entries(map)) {
      if (!ws.layout) continue
      for (const leaf of leaves(ws.layout.root)) {
        if (!leaf.sessionId) continue
        holders.set(leaf.sessionId, [...(holders.get(leaf.sessionId) ?? []), windowId])
      }
    }
    for (const [sid, wins] of holders) {
      if (wins.length <= 1) continue
      const home = this.homeWindowForSession(metadata, sid)
      const keep = home && wins.includes(home) ? home : wins[0]!
      for (const windowId of wins) {
        if (windowId === keep) continue
        const ws = map[windowId]!
        const leaf = ws.layout ? leaves(ws.layout.root).find((l) => l.sessionId === sid) : undefined
        if (leaf) {
          map[windowId] = removePaneEverywhere(ws, leaf.id)
          changed = true
        }
      }
    }
    // (b) within one window's LAYOUT a session holds at most ONE leaf (a legacy `pane-place-` hybrid next to
    // the real desktop pane id produced two leaves sharing one session — the user-reported grey twin pane).
    // Keep the first in reading order; later duplicates reduce out via the canonical super-rule.
    for (const windowId of Object.keys(map)) {
      let ws = map[windowId]!
      if (!ws.layout) continue
      const seen = new Set<string>()
      const dupPaneIds: string[] = []
      for (const p of readingOrderPanes(ws.layout)) {
        if (!p.sessionId) continue
        if (seen.has(p.sessionId)) dupPaneIds.push(p.paneId)
        else seen.add(p.sessionId)
      }
      for (const paneId of dupPaneIds) {
        ws = removePaneEverywhere(ws, paneId)
        changed = true
      }
      if (dupPaneIds.length > 0) map[windowId] = ws
    }
    // (c) in-window: placed XOR stashed — drop stash rows whose session is placed in the SAME window.
    for (const windowId of Object.keys(map)) {
      const ws = map[windowId]!
      if (!ws.layout || ws.stashed.length === 0) continue
      const placedHere = new Set(leaves(ws.layout.root).map((l) => l.sessionId).filter((s): s is string => !!s))
      const stashed = ws.stashed.filter((s) => !s.sessionId || !placedHere.has(s.sessionId))
      if (stashed.length !== ws.stashed.length) {
        map[windowId] = { layout: ws.layout, stashed }
        changed = true
      }
    }
    return changed
  }

  /** Clear every browser-side timer/marker associated with one attach lifecycle. This never sends a wire
   * operation: callers must first prove agent ownership from a completed MultiAttach binding. */
  private clearAttachLifecycle(sessionId: string, forgetMeasurement = false): void {
    this.cancelWinsizeSettleRepush(sessionId, forgetMeasurement)
    this.clearAttachWatchdog(sessionId)
    this.clearPaneSwitchWatchdog(sessionId)
    this.baselineReattachPending.delete(sessionId)
    this.attachAutoRetried.delete(sessionId)
    this.winsizeRefreshAfterAttach.delete(sessionId)
    this.winsizeRefreshAfterMaterialize.delete(sessionId)
    const fallback = this.winsizeRefreshFallbackTimers.get(sessionId)
    if (fallback) clearTimeout(fallback)
    this.winsizeRefreshFallbackTimers.delete(sessionId)
    this.hydratedSessions.delete(sessionId)
    this.materializedRows.delete(sessionId)
    this.historyWarmSettled.delete(sessionId)
    this.retirePaneScrollbackFlow(sessionId, false)
    this.pendingOwnershipReassert.delete(sessionId)
    if (this.backgroundAttachInFlight === sessionId) this.backgroundAttachInFlight = null
  }

  /** Fully release a session's live channel — wire detach + attach-map binding + router/bank renderer state —
   * the SAME sequence the user-initiated close path runs (closePane / stashBrowserPane). Shared so the
   * existence-reconcile can release channels for panes the DESKTOP closed; without it those channels kept
   * streaming into a bank nobody rendered (the reconcile channel leak). Also drops any pending attach
   * watchdog for the session (nothing will materialize on a detached channel). A pending attach has no channel
   * to release yet, so it is cleaned up locally and its eventual attach_ok is drained by shouldAcceptAttach. */
  private detachSessionChannel(sessionId: string): void {
    const channel = this.multiAttach.channelForSession(sessionId)
    if (channel !== null) {
      this.session?.detachSession(sessionId)
      this.multiAttach.detachSession(sessionId)
      this.multiPaneTerminal.detachPane(channel)
      this.pendingWireAttaches.delete(sessionId)
      this.abandonedPendingAttaches.delete(sessionId)
    } else if (this.pendingWireAttaches.has(sessionId)) {
      this.abandonedPendingAttaches.add(sessionId)
    }
    this.clearAttachLifecycle(sessionId, true)
  }

  /** Pane lifecycle attachment invariant: `attachedSession` must always be a
   * PLACED leaf of the ACTIVE window's mirror, or null. Enforced at every placement-drop path (reconcile,
   * window switch, stash). Clearing it (phase stays 'terminal' — the empty-pane UI is the deliberate render)
   * kills the legacy-canvas ghost: `shouldRenderPaneTerminal` can then only fail when nothing is attached, so
   * a "stashed" session can never keep painting full-height. */
  private enforceAttachedSessionPlacement(): void {
    const sid = this.view.attachedSession
    if (!sid) return
    if (leaves(this.view.paneLayout.root).some((l) => l.sessionId === sid)) return
    this.update({ attachedSession: null })
  }

  /** BUG-1 fix (split identity): rekey the pending split's reserved EMPTY leaf (`pane-N`, browser-minted) to the
   * DESKTOP tab id the split created, and drop any session-less stash row already minted for that desktop pane
   * (the redaction-race push lands `{tabId, session:""}` before split_pane_ok). Lifecycle: this is the
   * `session-named`/`remote-create` identity upgrade of the reserve — one pane, one id, no phantom stash row.
   * No-op when nothing is pending, the reserve is gone, or the tab id is already a leaf. */
  private adoptSplitReserve(attempt: PendingRemoteCreationAttempt, tabId: string | undefined): void {
    const reserveId = attempt.splitPaneId
    if (!reserveId || !tabId || reserveId === tabId) return
    const ws = this.workspacePanes()
    if (!ws.layout || !findLeaf(ws.layout, reserveId)) return
    const renamed = renamePaneId(ws.layout, reserveId, tabId)
    if (renamed === ws.layout) return // tabId collision → keep the reserve as-is (attach still lands by target id)
    if (attempt.targetPaneId === reserveId) attempt.targetPaneId = tabId
    attempt.splitPaneId = null
    this.applyWorkspace({
      layout: renamed,
      stashed: ws.stashed.filter((s) => !(s.paneId === tabId && !s.sessionId)),
    })
  }

  /** Undo the browser-grid split a pending splitWithSessionRemote made (the desktop refused / never replied):
   * close the still-EMPTY pane that was reserved for the in-flight session. No-op when nothing is pending, the
   * pane is gone (user closed it), or it got a session bound meanwhile (never close real content). */
  private rollbackPendingSplitPane(paneId?: string | null): void {
    if (!paneId) return
    const leaf = findLeaf(this.view.paneLayout, paneId)
    if (!leaf || leaf.sessionId !== null) return
    this.closePane(paneId)
  }

  /** Queue focused-pane hydration. Siblings remain placed but wire-detached until the user focuses them. The
   * deferred tick lets resumePanes provide the exact measured active size synchronously before this fallback runs. */
  private attachPlacedPanes(): void {
    this.schedulePaneHydration()
  }

  /**
   * Revive a BROWSER-STASHED pane into the browser's OWN grid (canonical revive geometry) and attach its
   * session live — no wire to the desktop. If `paneId` resolves to no stash entry, falls through to
   * {@link placeDesktopPaneRemote} so desktop panes the browser never stashed keep working.
   *
   * Single-identity rule (`pane lifecycle contract`): the stash lookup resolves by the
   * DESKTOP pane id FIRST, then by the pane's SESSION — a legacy stash entry keyed under a browser leaf id
   * (pre-single-id-space rows restored from the cloud) is still found instead of falling through and placing
   * a DUPLICATE while the stale entry survives (the §B-S1 placed-AND-stashed bug). */
  reviveBrowserPane(paneId: string, cols = 80, rows = 24): void {
    // CONTAINMENT (hard): a pane revives only into its parent desktop window's grid. Clicking a pane row that
    // belongs to ANOTHER window switches the active window to its home first (like local: clicking a pane in
    // window B shows window B), then revives there.
    const sessionId = this.desktopSessionForPane(paneId)
      ?? this.view.browserStashed.find((s) => s.paneId === paneId)?.sessionId
      ?? null
    if (sessionId) {
      const home = this.homeWindowForSession(this.view.workspaceMetadata, sessionId)
      // R10: clicking ONE pane of a stashed window revives the window with ONLY that pane (full-size) — the
      // preferPaneId makes the empty-grid auto-place pick the CLICKED pane, not the window's first stash row.
      if (home && this.view.activeWindowId && home !== this.view.activeWindowId) this.setActiveWindow(home, { preferPaneId: paneId, attachSize: { cols, rows } })
    }
    const ws = this.workspacePanes()
    const stashed = ws.stashed.find((s) => s.paneId === paneId)
      ?? (sessionId ? ws.stashed.find((s) => s.sessionId === sessionId) : undefined)
    // Not in the browser's own stash → it's a desktop pane the remote simply hasn't PLACED yet. Place it into the
    // remote's OWN grid (NOT a desktop-revive command — local↔remote layouts are separate), then attach.
    if (!stashed) { this.placeDesktopPaneRemote(paneId, cols, rows); return }
    // A session-less DESKTOP row is not revivable yet: its session hasn't been named (redacted mid-creation).
    // Placing it would show a dead shell and lose the row to the lone-empty-leaf canonicalization; it stays
    // stashed until the `session-named` upgrade binds the session. (A browser-minted empty pane, which has no
    // desktop existence, keeps its legacy revive.)
    if (!stashed.sessionId && this.desktopPaneTarget(stashed.paneId)) {
      this.startPaneSessionForRemote(stashed.paneId, cols, rows)
      return
    }
    // Partition repair (the "grey twin pane" symptom): the stash entry's session may ALREADY be placed (a
    // legacy placed-AND-stashed row, e.g. a restored `pane-place-` hybrid next to its real stash entry).
    // NEVER place a second leaf for the same session — drop the stale stash row and focus the placed pane.
    if (stashed.sessionId && ws.layout) {
      const placedLeaf = leaves(ws.layout.root).find((l) => l.sessionId === stashed.sessionId)
      if (placedLeaf) {
        this.applyWorkspace(
          { layout: ws.layout, stashed: ws.stashed.filter((s) => s !== stashed) },
          { paneLayout: { ...ws.layout, activePaneId: placedLeaf.id } },
        )
        this.attach(stashed.sessionId, cols, rows)
        this.persistLastLayout()
        return
      }
    }
    if (ws.layout && paneCount(ws.layout) >= 4) return // grid full
    let next = reviveInWorkspace(ws, stashed.paneId)
    if (next === ws) return // no-op (unknown / full)
    // Partition repair on the way through: reviving a session clears ANY other stash entry still holding it
    // (placed XOR stashed — invariant 1), so a duplicate can never survive a revive.
    if (stashed.sessionId) {
      next = { layout: next.layout, stashed: next.stashed.filter((s) => s.sessionId !== stashed.sessionId) }
    }
    // The revived pane leaf uses the stash entry's pane id; focus it so input/attach lands there.
    if (this.view.activeWindowId) this.pendingLandingWindows.delete(this.view.activeWindowId) // landing-burned (user revive)
    this.applyWorkspace(next, next.layout ? { paneLayout: { ...next.layout, activePaneId: stashed.paneId } } : {})
    // Attach the pane's live session channel so the revived tile paints. Reuses the normal attach path.
    if (stashed.sessionId) this.attach(stashed.sessionId, cols, rows)
    this.persistLastLayout()
  }

  /**
   * PLACE a desktop pane (identified by its metadata `paneId`) into the REMOTE's OWN grid as a NEW pane bound to that
   * pane's live session, then attach it. This is the "click a not-yet-placed pane → add it here" path — it adds a
   * pane to the browser layout instead of switching the single placed pane (the old bug) or commanding the desktop to
   * revive (which would couple the layouts). If the session is already placed, just focus it. No-op if the grid is
   * full (4) or the session isn't live on the desktop. */
  placeDesktopPaneRemote(paneId: string, cols = 80, rows = 24): void {
    const sessionId = this.desktopSessionForPane(paneId)
    if (!sessionId || !this.view.sessions.includes(sessionId)) return
    // CONTAINMENT (hard): a desktop pane is placed only into its parent window's grid — switch there first.
    // R10: prefer auto-placing THIS pane when the target grid is empty (single-pane revive of a stashed window).
    const home = this.homeWindowForSession(this.view.workspaceMetadata, sessionId)
    if (home && this.view.activeWindowId && home !== this.view.activeWindowId) this.setActiveWindow(home, { preferPaneId: paneId, attachSize: { cols, rows } })
    // Already placed in the remote grid → just focus that pane + bring its session up (don't add a duplicate).
    const existing = readingOrderPanes(this.view.paneLayout).find((p) => p.sessionId === sessionId)
    if (existing) { this.focusPane(existing.paneId); this.attach(sessionId, cols, rows); return }
    // Single identity (`pane identity contract`): the placed leaf id IS the desktop pane
    // id — the `pane-place-${id}` hybrid is abolished (it fused two id spaces and left stale stash entries
    // behind, the §B-S1 duplication). Placing a session also CLEARS its matching stash entries: route through
    // the canonical addStashed→revive funnel so placed/stashed stays a strict partition by construction.
    const ws = this.workspacePanes()
    if (ws.layout && paneCount(ws.layout) >= 4) return // grid full
    const cleaned: WorkspacePanes = {
      layout: ws.layout,
      stashed: ws.stashed.filter((s) => s.sessionId !== sessionId && s.paneId !== paneId),
    }
    const base = addStashed(cleaned, paneId, sessionId)
    const next = reviveInWorkspace(base, paneId)
    if (next === base) return
    if (this.view.activeWindowId) this.pendingLandingWindows.delete(this.view.activeWindowId) // landing-burned (user placed)
    this.applyWorkspace(next, next.layout ? { paneLayout: { ...next.layout, activePaneId: paneId } } : {})
    this.attach(sessionId, cols, rows)
    this.persistLastLayout()
  }

  /** A desktop revive reply is authoritative: the desktop has just made `paneId` live and returned its preserved
   * session id. Do not route this through placeDesktopPaneRemote, because that path intentionally refuses when the
   * browser grid is full or when a racing session_list has not named the session yet. Remote production mode is a
   * single visible pane, so install the revived pane directly and attach fresh content. */
  private activateDesktopRevivedPane(paneId: string, sessionId: string, cols: number, rows: number): void {
    const home = this.homeWindowForSession(this.view.workspaceMetadata, sessionId)
      ?? this.desktopPaneTarget(paneId)?.windowId
      ?? this.view.activeWindowId
    const currentByWindow = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) {
      currentByWindow[this.view.activeWindowId] = preserveWindowStashed(this.workspacePanes(), currentByWindow[this.view.activeWindowId])
    }
    const existingStash = home ? currentByWindow[home]?.stashed ?? this.view.browserStashed : this.view.browserStashed
    const targetLayout = singlePane(sessionId, paneId)
    const targetWorkspace = workspacePanesFrom(
      targetLayout,
      existingStash.filter((s) => s.sessionId !== sessionId && s.paneId !== paneId),
    )
    const sessions = this.view.sessions.includes(sessionId) ? this.view.sessions : [...this.view.sessions, sessionId]
    const patch: Partial<RemoteClientView> = {
      sessions,
      paneLayout: targetLayout,
      browserStashed: [...targetWorkspace.stashed],
    }
    if (home) {
      patch.activeWindowId = home
      patch.paneLayoutsByWindow = { ...currentByWindow, [home]: targetWorkspace }
      this.activeProjectIdHint = this.projectIdOfWindow(this.view.workspaceMetadata, home) ?? this.activeProjectIdHint
      this.rememberProjectWindow(home)
    }
    this.pendingLandingWindows.delete(home ?? '')
    this.beginPaneSwitch(sessionId)
    this.update(patch)
    this.attach(sessionId, cols, rows)
    this.persistLastLayout()
  }

  /** Focus/switch to a live pane row from the sidebar.
   *
   * Production remote is a SINGLE visible terminal pane: clicking any green pane should replace the visible terminal
   * context with that pane's live session. If the session is already placed in the current browser layout we focus it;
   * otherwise we install a one-leaf layout for the pane in its own window and attach it. The optional multi-pane
   * terminal can still build grids through the split/revive paths, but the sidebar's default click never grows the
   * visible layout. */
  focusPlacedSessionRemote(sessionId: string, cols = 80, rows = 24): void {
    if (this.view.winsizeOwner !== 'remote') this.update({ winsizeOwner: 'remote' })
    this.session?.setWinsizeOwner(true)
    this.pushActivePaneResize()
    // Prefer the MEASURED browser viewport over the sidebar's fallback size — but only when a real measurement
    // exists. Before any resize() has run, lastAttachSize is just the 80×24 default; clobbering an explicit
    // caller size with it shrank first opens (e.g. the headless start→attach path) to 80×24.
    if (this.viewportMeasured) {
      cols = this.lastAttachSize.cols
      rows = this.lastAttachSize.rows
    }
    const placed = readingOrderPanes(this.view.paneLayout).find((p) => p.sessionId === sessionId)
    if (!placed) {
      const desktopPaneId = this.desktopPaneIdForSession(sessionId)
      if (!desktopPaneId) return
      // A desktop-stashed pane can still have a persisted SessionRecord marked Live, so `view.sessions` may
      // include it even when the daemon attach path will not produce content. Treat stashed metadata as needing
      // a start/confirm handshake; the agent no-ops if the session is already daemon-live, otherwise it restarts
      // the recorded launch without mutating the local layout.
      if (!this.view.sessions.includes(sessionId) || this.desktopPaneIsStashed(desktopPaneId)) {
        this.startPaneSessionForRemote(desktopPaneId, cols, rows)
        return
      }
      const home = this.homeWindowForSession(this.view.workspaceMetadata, sessionId)
      const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
      if (this.view.activeWindowId) {
        map[this.view.activeWindowId] = preserveWindowStashed(this.workspacePanes(), map[this.view.activeWindowId])
      }
      const targetLayout = singlePane(sessionId, desktopPaneId)
      const target = workspacePanesFrom(targetLayout, (map[home ?? '']?.stashed ?? this.view.browserStashed).filter((s) => s.sessionId !== sessionId && s.paneId !== desktopPaneId))
      if (home) {
        this.rememberProjectWindow(home)
        this.update({
          activeWindowId: home,
          paneLayoutsByWindow: { ...map, [home]: target },
          paneLayout: targetLayout,
          browserStashed: [...target.stashed],
        })
        this.activeProjectIdHint = this.projectIdOfWindow(this.view.workspaceMetadata, home) ?? this.activeProjectIdHint
      } else {
        this.applyWorkspace(target, { paneLayout: targetLayout })
      }
      this.pendingLandingWindows.delete(home ?? '')
      this.beginPaneSwitch(sessionId)
      const wasAttached = this.multiAttach.channelForSession(sessionId) !== null
      this.attach(sessionId, cols, rows)
      this.pushRemoteSizeAfterPaint()
      if (!wasAttached && this.view.winsizeOwner === 'remote') this.refreshSessionAfterWinsizeClaim(sessionId)
      this.persistLastLayout()
      return
    }
    this.focusPane(placed.paneId)
    this.beginPaneSwitch(sessionId)
    const wasAttached = this.multiAttach.channelForSession(sessionId) !== null
    this.attach(sessionId, cols, rows)
    this.pushRemoteSizeAfterPaint()
    if (!wasAttached && this.view.winsizeOwner === 'remote') this.refreshSessionAfterWinsizeClaim(sessionId)
  }

  private startPaneSessionForRemote(paneId: string, cols = 80, rows = 24): void {
    if (this.view.creatingSession) {
      connTrace.log(this.traceId, 'pane_start', 'blocked', 'warn', `creatingSession pane=${short(paneId)}`)
      return
    }
    if (!this.session?.isAuthenticated) {
      connTrace.log(this.traceId, 'pane_start', 'blocked', 'warn', `unauthenticated pane=${short(paneId)}`)
      return
    }
    const target = this.desktopPaneTarget(paneId)
    if (!target) {
      connTrace.log(this.traceId, 'pane_start', 'blocked', 'warn', `no desktop target pane=${short(paneId)}`)
      return
    }
    const creation = this.beginRemoteCreation('start-pane-session', 'start-pane-session', cols, rows, {
      virtualStartPaneId: target.paneId,
    })
    connTrace.log(this.traceId, 'pane_start', 'request', 'pending', `window=${short(target.windowId)} pane=${short(target.paneId)}`)
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.startPaneSession(creation.requestId, target.windowId, target.paneId, {
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  /**
   * Stash a PLACED pane back to `browserStashed` (BROWSER-LOCAL): the pane leaves the grid, survivors re-snap
   * via the canonical super-rule. Does NOT stash on the desktop. No-op if `paneId` isn't placed.
   *
   * Slice 4 (local parity, `window_layout.rs` CannotStashLastPane): stashing the LAST placed pane is REFUSED —
   * the grid must never empty under the user (the old behavior emptied the grid, left `attachedSession`
   * dangling, and the legacy full-height canvas painted the "stashed" session's frozen frame).
   * Slice 3 (single identity): the stash entry is keyed by the DESKTOP pane id when the session has one (only
   * a pane with no desktop existence keeps its browser leaf id), so a later tree revive — which passes desktop
   * ids — hits THIS entry instead of minting a duplicate placement. */
  stashBrowserPane(paneId: string): void {
    const closing = findLeaf(this.view.paneLayout, paneId)
    if (!closing) return
    if (leaves(this.view.paneLayout.root).length <= 1) {
      this.update({ desktopActionMessage: 'The last open pane cannot be stashed.' })
      return
    }
    const ws = this.workspacePanes()
    // Partition repair on the way through: drop any PRE-EXISTING stash entry for the same session so the stash
    // never holds two rows for one session (placed XOR stashed, invariant 1).
    const base: WorkspacePanes = closing.sessionId
      ? { layout: ws.layout, stashed: ws.stashed.filter((s) => s.sessionId !== closing.sessionId) }
      : ws
    let next = stashPaneInWorkspace(base, paneId)
    if (next === base) return
    const desktopId = closing.sessionId ? this.desktopPaneIdForSession(closing.sessionId) : null
    if (desktopId && desktopId !== paneId) {
      next = {
        layout: next.layout,
        stashed: next.stashed.map((s) => (s.paneId === paneId ? { ...s, paneId: desktopId } : s)),
      }
    }
    // Detach the stashed pane's live channel FULLY — wire + attach map + router/bank — mirroring
    // clearPaneSession. The session keeps running on the desktop; revive goes through a FRESH attach, whose
    // attach_ok + full grid repaint the pane deterministically. (The old partial detach kept the daemon
    // streaming a hidden pane, used a truthiness check that skipped channel 0, and left the bank holding a
    // channel with no future baseline — the revived-pane-stays-blank state.)
    if (closing.sessionId) this.detachSessionChannel(closing.sessionId)
    this.applyWorkspace(next)
    if (next.layout) this.activatePaneSession(activeLeaf(next.layout).sessionId)
    this.enforceAttachedSessionPlacement()
    this.persistLastLayout()
  }

  /** The BROWSER-LAYOUT pane id (placed or stashed) currently holding `sessionId`, or null. Bridges a desktop
   * metadata pane id (used in the sidebar rows) to the browser's own pane id via the shared session identity. */
  private browserPaneIdForSession(sessionId: string): string | null {
    for (const l of leaves(this.view.paneLayout.root)) if (l.sessionId === sessionId) return l.id
    for (const s of this.view.browserStashed) if (s.sessionId === sessionId) return s.paneId
    return null
  }

  /** REMOTE stash of a pane the sidebar row identifies by its DESKTOP metadata pane id — but applied BROWSER-ONLY (to
   * the remote's own layout), NOT sent to the desktop. This is the fix for "stash/revive on remote broke local": the
   * desktop must NOT be told to stash; only the remote's own arrangement changes (local↔remote layouts are separate). */
  stashPaneRemoteLocalId(desktopPaneId: string): void {
    const sid = this.desktopSessionForPane(desktopPaneId)
    const browserId = sid ? this.browserPaneIdForSession(sid) : null
    if (browserId) this.stashBrowserPane(browserId)
  }

  /** REMOVE a pane from the REMOTE's own layout only (browser stash + placed), by its desktop metadata pane id. Never
   * touches the desktop — the underlying session keeps running on local. */
  removePaneRemoteLocalId(desktopPaneId: string): void {
    const sid = this.desktopSessionForPane(desktopPaneId)
    if (!sid) return
    const browserId = this.browserPaneIdForSession(sid)
    // Slice 4 (local parity): like the stash guard, the LAST placed pane cannot be removed from the browser
    // grid — the grid must never empty under the user (local disables Remove from shelf on the last live pane).
    if (browserId && findLeaf(this.view.paneLayout, browserId) && leaves(this.view.paneLayout.root).length <= 1) {
      this.update({ desktopActionMessage: 'The last open pane cannot be removed.' })
      return
    }
    if (browserId) this.stashBrowserPane(browserId) // drop from the placed grid → browser stash
    // also drop it from the browser stash list so it's fully removed from the remote view (route through applyWorkspace
    // so the per-window map's stashed list stays in sync)
    const stashedEntry = this.view.browserStashed.find((s) => s.sessionId === sid)
    if (stashedEntry) {
      this.applyWorkspace({ layout: this.workspacePanes().layout, stashed: this.view.browserStashed.filter((s) => s !== stashedEntry) })
    }
    this.persistLastLayout()
  }

  /** Start a new terminal in a specific pane. The existing create path binds the eventual session_created id
   * to the ACTIVE pane, so this focuses the requested pane first and then reuses createSession. */
  createSessionInPane(paneId: string, cols: number, rows: number, label?: string, agent?: RemoteAgentKind): void {
    if (!findLeaf(this.view.paneLayout, paneId)) return
    this.focusPane(paneId)
    this.createSession(cols, rows, label, agent)
  }

  /** Split the REMOTE's OWN layout (like local splits its own grid) and start a session in the new pane with the
   * chosen agent + launch flags (resume/model). This is the split the dialog uses — NOT splitPaneRemote, which
   * commanded the DESKTOP to split (coupling layouts and failing for browser-placed panes). */
  newPaneRemote(
    cols: number,
    rows: number,
    agent?: RemoteAgentKind,
    launchFlags?: RemoteLaunchFlags,
    paneName?: string,
    cwd?: string,
  ): void {
    if (this.view.creatingSession) return
    const activePaneId = activeLeaf(this.view.paneLayout).id
    const anchor = this.desktopWindowForPane(activePaneId)
    if (!anchor) {
      this.createSession(cols, rows, paneName, agent, cwd?.trim() || undefined)
      return
    }
    if (!this.session?.isAuthenticated) return
    this.focusPane(activePaneId)
    const creation = this.beginRemoteCreation('new-pane', 'new-pane', cols, rows)
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.newPane(creation.requestId, anchor.windowId, anchor.paneId, {
      ...(cwd?.trim() ? { cwd: cwd.trim() } : {}),
      ...(agent ? { agent } : {}),
      ...(launchFlags ? { launchFlags } : {}),
      ...(paneName?.trim() ? { paneName: paneName.trim() } : {}),
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  splitWithSessionRemote(
    paneId: string,
    dir: SplitDir,
    cols: number,
    rows: number,
    agent?: RemoteAgentKind,
    launchFlags?: RemoteLaunchFlags,
    paneName?: string,
    cwd?: string,
  ): void {
    if (this.view.creatingSession) return
    if (!findLeaf(this.view.paneLayout, paneId)) return
    // P1 (ghost panes): resolve the SOURCE pane's DESKTOP anchor first. A split must create the same
    // durable record chain local creates (Session inheriting the source workspace + a TabRecord via
    // the desktop-authoritative split_pane op) — otherwise the new pane exists ONLY in this browser's
    // grid: no store row, so it can never appear in any sidebar/tab-strip/dashboard (they all render
    // workspace_metadata) nor be seen by repair/invariants. GEOMETRY stays browser-owned either way —
    // the desktop split persists EXISTENCE; we still do NOT mirror the desktop's layout here.
    const anchor = this.desktopWindowForPane(paneId)
    // DESKTOP-SIDE 4-PANE GATE: when the split will be persisted under a desktop window (source pane has an
    // anchor), check THAT window's live pane count FIRST — the desktop refuses a 5th pane, and refusing here
    // (before touching the browser grid) means no split-then-rollback churn and an immediate honest message.
    if (anchor) {
      const anchorWindow = this.view.workspaceMetadata?.projects
        .flatMap((p) => p.windows)
        .find((w) => w.id === anchor.windowId)
      const livePanes = anchorWindow?.panes.filter((p) => !p.stashed && p.live !== false).length ?? 0
      if (livePanes >= 4) {
        this.update({ desktopActionMessage: 'This desktop window already has 4 panes.' })
        return
      }
    }
    const before = this.view.paneLayout.activePaneId
    this.splitPane(paneId, dir) // split the browser's OWN grid
    const newActive = this.view.paneLayout.activePaneId
    if (newActive === before) return // no-op (MAX_PANES) → don't create a stray session
    this.focusPane(newActive)
    const creation = this.beginRemoteCreation(
      anchor ? 'split-pane' : 'create',
      anchor ? 'split-pane' : 'create-session',
      cols,
      rows,
      {
        targetPaneId: newActive,
        splitPaneId: newActive,
      },
    )
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    if (anchor && this.session?.isAuthenticated) {
      // onSplitPaneOk auto-attaches the returned session → lands in the attempt's reserved browser pane.
      // The desktop may refuse (e.g. its window already has 4 live panes) —
      // the error surfaces via desktopActionMessage and the empty browser pane can be closed.
      this.session.splitPane(creation.requestId, anchor.windowId, anchor.paneId, dir === 'vertical' ? 'right' : 'down', {
        ...(cwd?.trim() ? { cwd: cwd.trim() } : {}),
        ...(agent ? { agent } : {}),
        ...(launchFlags ? { launchFlags } : {}),
        // The dialog's pane name rides the wire → the desktop TabRecord title (was dropped here, so a
        // named split always fell back to the agent-derived title).
        ...(paneName?.trim() ? { paneName: paneName.trim() } : {}),
        cols: creation.geometry.cols,
        rows: creation.geometry.rows,
      })
      return
    }
    // FALLBACK (source pane has no desktop anchor — itself a record-less session): the old bare
    // create_session path. This is the only remaining way a record-less pane is born.
    this.session?.createSession(creation.requestId, {
      // The split dialog's pane name (defaults to "Pane N") wins; else the friendly "Terminal N".
      label: paneName?.trim() || `Terminal ${this.view.sessions.length + 1}`,
      // cwd omitted → createContext inherits the split source pane's cwd (the active session's cwd), matching the
      // desktop contract ("This pane's folder"). A picked folder overrides it.
      ...this.createContext(agent, cwd?.trim() || undefined, launchFlags),
      ...(agent ? { agent } : {}),
      ...(launchFlags ? { launchFlags } : {}),
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  /** §4 N-up: attach an EXISTING session into a specific pane (without replacing the active pane). attach()
   * binds to the active pane, so this focuses the target pane first. No-op for an unknown pane or session. */
  attachSessionInPane(paneId: string, sessionId: string, cols: number, rows: number): void {
    if (this.view.creatingSession) return
    if (!findLeaf(this.view.paneLayout, paneId)) return
    if (!this.view.sessions.includes(sessionId)) return
    this.focusPane(paneId)
    this.attach(sessionId, cols, rows)
  }

  /** F1: the display name for a session id — its custom label if set, else a FRIENDLY "Terminal N" by the
   * session's position in the daemon list (parity with the desktop dashboard), not the raw `s-…` id. Mirrors
   * model/session-row.ts `sessionLabel` (kept inline to avoid a circular import). */
  labelFor(sessionId: string): string {
    return displaySessionLabel(this.view, sessionId)
  }

  /** Rename a session's browser-local label. A blank/whitespace name REMOVES the custom label → the session
   * falls back to its id. This persists only in this browser for the same account+desktop+session id; it
   * does not call the agent/cloud or make daemon sessions durable. */
  renameSession(sessionId: string, label: string): void {
    const trimmed = label.trim()
    const labels = { ...this.view.sessionLabels }
    if (trimmed) labels[sessionId] = trimmed
    else delete labels[sessionId] // blank → drop the custom label, fall back to the id
    this.saveLabelsForCurrentDesktop(labels)
    this.update({ sessionLabels: labels })
  }

  /** Browser-local favorite/pin for a session id. Scoped by account+desktop; does not call agent/cloud. */
  toggleFavorite(sessionId: string): void {
    const id = sessionId.trim()
    if (!id || !this.view.sessions.includes(id)) return
    const favoriteSessions = toggleFavorite(this.view.favoriteSessions, id)
    this.saveFavoritesForCurrentDesktop(favoriteSessions)
    this.update({ favoriteSessions })
  }

  /** Browser-local manual session ordering. Moves within the full effective order; favorites still render
   * pinned first in the row model, but both pinned and unpinned groups respect this saved order. */
  moveSession(sessionId: string, delta: -1 | 1): void {
    const id = sessionId.trim()
    if (!id || !this.view.sessions.includes(id)) return
    const sessionOrder = moveSessionInOrder(this.view.sessions, this.view.sessionOrder, id, delta)
    this.saveOrderForCurrentDesktop(sessionOrder)
    this.update({ sessionOrder })
  }

  /** Browser-local hide/archive for session rows. Non-destructive: it only filters this browser's list and
   * never asks the daemon to kill/delete a session. */
  hideSession(sessionId: string): void {
    const hiddenSessions = hideSessionInView(this.view.sessions, this.view.hiddenSessions, sessionId)
    this.saveHiddenForCurrentDesktop(hiddenSessions)
    this.update({ hiddenSessions })
  }

  unhideSession(sessionId: string): void {
    const hiddenSessions = unhideSessionInView(this.view.hiddenSessions, sessionId)
    this.saveHiddenForCurrentDesktop(hiddenSessions)
    this.update({ hiddenSessions })
  }

  /** Browser-local desktop label override. Blank label removes the override (falls back to cloud label). */
  renameDevice(deviceId: string, label: string): void {
    const acct = this.view.accountId
    const id = deviceId.trim()
    if (!acct || !id || !this.view.devices.some((d) => d.deviceId === id)) return
    const trimmed = label.trim().replace(/\s+/g, ' ')
    const deviceLabels = { ...this.view.deviceLabels }
    if (trimmed) deviceLabels[id] = trimmed
    else delete deviceLabels[id]
    this.update({ deviceLabels })
    saveDeviceLabels(acct, deviceLabels)
  }

  /** Roadmap §8: save the CURRENT pane layout as a named preset (browser-local, persisted). */
  saveLayoutPreset(name: string): void {
    const nowMs = Date.now()
    this.commitLayoutPresetState(createPreset(this.view.layoutPresetState, {
      id: this.nextLayoutPresetId(nowMs),
      name,
      layout: this.view.paneLayout,
      nowMs,
    }))
  }

  renameLayoutPreset(presetId: string, name: string): void {
    this.commitLayoutPresetState(renamePreset(this.view.layoutPresetState, presetId, name))
  }

  deleteLayoutPreset(presetId: string): void {
    this.commitLayoutPresetState(deletePreset(this.view.layoutPresetState, presetId))
  }

  setDefaultLayoutPreset(presetId: string | null): void {
    this.commitLayoutPresetState(setDefaultPreset(this.view.layoutPresetState, presetId))
  }

  /** One action from the panes view: save the CURRENT pane layout under `name` AND mark it the default, so a
   * fresh connect reopens exactly this workspace. Saves + sets-default in a single commit. */
  saveCurrentLayoutAsDefault(name: string): void {
    const nowMs = Date.now()
    const id = this.nextLayoutPresetId(nowMs)
    const withPreset = createPreset(this.view.layoutPresetState, { id, name, layout: this.view.paneLayout, nowMs })
    this.commitLayoutPresetState(setDefaultPreset(withPreset, id))
  }

  /**
   * Restore a saved layout. Keeps panes whose session is still live, frees the rest into empty slots (§8
   * "restore live where possible, fresh when needed"). Applies the restored layout to the view and returns the
   * pane ids that need a fresh session (spawning into them is a later slice). No-op for an unknown id.
   */
  restoreLayoutPreset(presetId: string): readonly string[] {
    const preset = this.view.layoutPresetState.presets.find((p) => p.id === presetId)
    if (!preset) return []
    const { layout, freshPaneIds } = restorePreset(preset, this.view.sessions)
    this.setActiveLayout(layout)
    return freshPaneIds
  }

  /** Roadmap §4 multi-pane: split a pane into two along `dir` (the new empty pane becomes active). No-op at
   * MAX_PANES. Pure layout state only — no session attach yet. */
  splitPane(paneId: string, dir: SplitDir): void {
    if (!findLeaf(this.view.paneLayout, paneId)) return
    const focused = focusPaneInLayout(this.view.paneLayout, paneId)
    const paneLayout = splitActive(focused, dir)
    this.setActiveLayout(paneLayout)
    // splitActive focuses the newly-created empty pane. Treat that as the same ownership transition as an explicit
    // focus click: demote/retire the old surface now, and quarantine any attach that proves ownership only later.
    this.activatePaneSession(activeLeaf(paneLayout).sessionId)
    this.persistLastLayout() // remember the multi-pane arrangement for a fresh reconnect
  }

  /** Split `paneId` along `dir` and start a fresh session in the new (now-active) pane — one quick action for
   * "give me another terminal alongside this one". No-op for an unknown pane (or at MAX_PANES, where splitActive
   * is a no-op → no session is created since the active pane didn't change to a new empty one). */
  splitWithNewSession(paneId: string, dir: SplitDir, cols: number, rows: number): void {
    if (!findLeaf(this.view.paneLayout, paneId)) return
    const before = this.view.paneLayout.activePaneId
    this.splitPane(paneId, dir)
    const newActive = this.view.paneLayout.activePaneId
    if (newActive === before) return // split was a no-op (MAX_PANES) → don't create a stray session
    this.createSessionInPane(newActive, cols, rows)
  }

  /** Desktop-authoritative split: ask the local desktop to persist the split under its Project→Window→Pane
   * layout, then attach the returned session. Falls back to no-op when this pane came from the cwd-only tree
   * and has no desktop window id. */
  splitPaneRemote(paneId: string, dir: SplitDir, cols = 80, rows = 24, agent?: RemoteAgentKind, launchFlags?: RemoteLaunchFlags): void {
    if (this.view.creatingSession) return
    const leaf = findLeaf(this.view.paneLayout, paneId)
    if (!leaf) return
    const target = this.desktopWindowForPane(paneId)
    if (!target) return
    if (!this.session?.isAuthenticated) return
    this.focusPane(paneId)
    const creation = this.beginRemoteCreation('split-pane', 'split-pane', cols, rows, {
      // This retained desktop-authoritative API has no optimistic browser reserve. Preserve its legacy
      // replacement behavior, but bind the reply to the pane the user acted on so focus drift cannot make the
      // returned session overwrite some unrelated pane.
      targetPaneId: paneId,
    })
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    // Desktop-parity (screens/local/splitright.jpg): a split can choose its AGENT (Claude/Codex/Gemini). When none
    // is chosen the pane inherits its sibling's agent, as before. createContext already threads an agent override.
    this.session?.splitPane(
      creation.requestId,
      target.windowId,
      target.paneId,
      dir === 'vertical' ? 'right' : 'down',
      {
        ...this.createContext(agent, undefined, launchFlags),
        cols: creation.geometry.cols,
        rows: creation.geometry.rows,
      },
    )
  }

  private desktopWindowForPane(paneId: string): { windowId: string; paneId: string } | null {
    const metadata = this.view.workspaceMetadata
    if (!metadata) return null
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        if (window.panes.some((pane) => pane.id === paneId)) {
          return { windowId: window.id, paneId }
        }
      }
    }
    const leaf = findLeaf(this.view.paneLayout, paneId)
    if (!leaf?.sessionId) return null
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        const pane = window.panes.find((p) => p.sessionId === leaf.sessionId && p.live !== false && !p.stashed)
        if (pane) return { windowId: window.id, paneId: pane.id }
      }
    }
    return null
  }

  // ---- DESKTOP-MUTATING pane ops (`pane identity contract`) ----
  // These three command the DESKTOP's own layout over the wire (revive_pane / stash_pane / remove_pane). They
  // are deliberately named `…OnDesktop` so their blast radius is unmistakable: browser-layout UI (grid, tree
  // rows, stash list) must NEVER bind to them — it binds only to the browser-local twins (reviveBrowserPane /
  // stashBrowserPane / stashPaneRemoteLocalId / removePaneRemoteLocalId). One mis-wired handler here re-creates
  // the "stash/revive on remote broke local" bug. Reachable only from explicit "on desktop" affordances.

  /** Ask the DESKTOP to revive one of ITS stashed panes (mutates the local layout). Not a browser-layout op. */
  revivePaneOnDesktop(paneId: string, cols = 80, rows = 24): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    const target = this.desktopPaneTarget(paneId)
    if (!target) return
    const creation = this.beginRemoteCreation('revive-pane', 'revive-pane', cols, rows, {
      desktopRevivePaneId: target.paneId,
    })
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.revivePane(creation.requestId, target.windowId, target.paneId, {
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  /** Ask the DESKTOP to stash one of ITS live panes (mutates the local layout). Not a browser-layout op. */
  stashPaneOnDesktop(paneId: string): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    const target = this.desktopPaneTarget(paneId)
    if (!target) return
    const mutation = this.beginRemoteMutation('stash-pane', 'stash-pane')
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.stashPane(mutation.requestId, target.windowId, target.paneId)
  }

  /** Ask the DESKTOP to remove one of ITS panes (destructive on local). Not a browser-layout op.
   * Accepts a metadata pane id OR a browser grid leaf id: a leaf minted before the split adoption renamed it
   * still resolves through its bound SESSION, so 'Remove from shelf' from a pane tile can never silently
   * no-op the way the raw-id lookup did. */
  removePaneOnDesktop(paneId: string): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    const target = this.desktopPaneTargetForBrowserPane(paneId)
    if (!target) return
    const mutation = this.beginRemoteMutation('remove-pane', 'remove-pane')
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.removePane(mutation.requestId, target.windowId, target.paneId)
  }

  /** Resolve a browser pane id to its desktop {windowId, paneId}: directly when the id IS a metadata pane id,
   * else via the pane's bound session (placed leaf or browser stash row) → the desktop pane holding it. */
  private desktopPaneTargetForBrowserPane(paneId: string): { windowId: string; paneId: string } | null {
    const direct = this.desktopPaneTarget(paneId)
    if (direct) return direct
    const sessionId = findLeaf(this.view.paneLayout, paneId)?.sessionId
      ?? this.view.browserStashed.find((s) => s.paneId === paneId)?.sessionId
      ?? null
    if (!sessionId) return null
    const desktopId = this.desktopPaneIdForSession(sessionId)
    return desktopId ? this.desktopPaneTarget(desktopId) : null
  }

  renamePaneRemote(paneId: string, name: string): void {
    const trimmed = name.trim()
    if (!trimmed) return
    // (1) Always set the BROWSER-LOCAL label so the remote reflects the rename immediately — works for browser-placed
    // panes too (which have no desktop metadata id). Uses the pane's bound session.
    const leaf = findLeaf(this.view.paneLayout, paneId)
    if (leaf?.sessionId) this.renameSession(leaf.sessionId, trimmed)
    // (2) ALSO push to the DESKTOP when this pane maps to a desktop pane (remote→local flow), so local updates too.
    // Best-effort: skip the desktop hop for browser-only panes (no desktop target) — the browser label already applied.
    const target = this.desktopPaneTarget(paneId)
    if (target && this.session?.isAuthenticated && !this.view.creatingSession) {
      const mutation = this.beginRemoteMutation('rename-pane', 'rename-pane')
      this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
      this.session.rename(mutation.requestId, target.windowId, trimmed, target.paneId)
    }
  }

  renameWindowRemote(windowId: string, name: string): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    const trimmed = name.trim()
    if (!trimmed || !this.desktopWindowExists(windowId)) return
    const mutation = this.beginRemoteMutation('rename-window', 'rename-window')
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.rename(mutation.requestId, windowId, trimmed)
  }

  closeWindowRemote(windowId: string): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    if (!this.desktopWindowExists(windowId)) return
    const mutation = this.beginRemoteMutation('close-window', 'close-window')
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.closeWindow(mutation.requestId, windowId)
  }

  /** Rule R2 — closing a window from the topbar tab × STASHES it (local parity: the desktop topbar × stashes a
   * window, it never deletes; delete stays behind the explicit "Remove from shelf" menu → closeWindowRemote).
   * BROWSER-LOCAL: every placed pane of the window falls to that window's own browser stash (desktop-id keyed),
   * its channels detach, and the window is flagged user-stashed so its topbar tab hides until it is reopened
   * (setActiveWindow clears the flag). The desktop is NOT touched — existence model, invariant I10. Refused for
   * globally last visible window. Stashing the ACTIVE window prefers that project's next visible window, then
   * falls back to the first visible window in the remaining projects. */
  stashWindowInBrowser(windowId: string): void {
    const metadata = this.view.workspaceMetadata
    if (!metadata || !this.desktopWindowExists(windowId)) return
    const project = metadata.projects.find((p) => p.windows.some((w) => w.id === windowId))
    if (!project) return
    const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) {
      map[this.view.activeWindowId] = preserveWindowStashed(this.workspacePanes(), map[this.view.activeWindowId])
    }
    const thisWindow = project.windows.find((w) => w.id === windowId)!
    const globallyVisible = metadata.projects
      .filter((candidate) => candidate.id !== PRODUCT_RECOVERY_PROJECT_ID)
      .flatMap((candidate) => candidate.windows)
      .filter((window) => this.browserWindowIsVisible(window, map))
    if (this.browserWindowIsVisible(thisWindow, map) && globallyVisible.length <= 1) {
      this.update({ desktopActionMessage: 'The globally last visible window cannot be stashed.' })
      return
    }
    let entry = map[windowId] ?? emptyWorkspace()
    if (entry.layout) {
      for (const p of readingOrderPanes(entry.layout)) {
        entry = stashPaneInWorkspace(entry, p.paneId)
        if (!p.sessionId) continue
        // single id-space: the stash entry keys by the desktop pane id when the session has one (Slice 3).
        const desktopId = this.desktopPaneIdForSession(p.sessionId)
        if (desktopId && desktopId !== p.paneId) {
          entry = { ...entry, stashed: entry.stashed.map((s) => (s.paneId === p.paneId ? { ...s, paneId: desktopId } : s)) }
        }
        if (this.multiAttach.channelForSession(p.sessionId) !== null) this.detachSessionChannel(p.sessionId)
      }
    }
    entry = { layout: entry.layout, stashed: entry.stashed, windowStashed: true }
    const wasActive = windowId === this.view.activeWindowId
    this.pendingLandingWindows.delete(windowId) // lifecycle `landing-burned`: an explicit user stash decides it (R2)
    this.update({ paneLayoutsByWindow: { ...map, [windowId]: entry } })
    if (wasActive) {
      // Reflect the emptied grid in the mirror, clear a now-unplaced attachedSession (invariant 3), and land
      // on the same project's next visible window when possible, then another project's first visible
      // window. This mirrors the desktop's global-last invariant without destructively touching it.
      this.update({ paneLayout: singlePane(), browserStashed: [...entry.stashed] })
      this.enforceAttachedSessionPlacement()
      const next = project.windows.find((w) => w.id !== windowId && this.browserWindowIsVisible(w, map))
        ?? metadata.projects
          .filter((candidate) => candidate.id !== project.id && candidate.id !== PRODUCT_RECOVERY_PROJECT_ID)
          .flatMap((candidate) => candidate.windows)
          .find((w) => w.id !== windowId && this.browserWindowIsVisible(w, map))
      if (next) this.setActiveWindow(next.id)
    }
    this.persistLastLayout()
  }

  /** R10/R11 — WINDOW revive (bulk), the inverse of {@link stashWindowInBrowser} and the sidebar's
   * stashed-window click (R11(1)): revive ALL of the window's stashed panes (≤4, the rest stay stashed) into
   * the dictated canonical shape for the count — 1 full · 2 A|B · 3 (A/C)|B · 4+ (A/B)|(C/D) — clear the
   * user-stashed flag, SWITCH to the window (the previously-open window remains untouched as a topbar tab —
   * R1/R6: switch, not swap), attach its panes, and persist. BROWSER-LOCAL: the desktop is never touched. */
  reviveWindowInBrowser(windowId: string, cols = 80, rows = 24): void {
    if (!this.desktopWindowExists(windowId)) return
    const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) {
      map[this.view.activeWindowId] = preserveWindowStashed(this.workspacePanes(), map[this.view.activeWindowId])
    }
    const isActive = windowId === this.view.activeWindowId
    const entry = isActive ? this.workspacePanes() : (map[windowId] ?? emptyWorkspace())
    const revived = reviveWindowInWorkspace(entry) // drops windowStashed by construction
    // Lifecycle `landing-burned`: an explicit user revive decides the window — but only when it actually
    // placed something. A landing-pending window has only session-less rows (not revivable), so the click
    // just switches; the designation survives and the landing completes on the next session-named push.
    if (revived.layout !== entry.layout) this.pendingLandingWindows.delete(windowId)
    this.update({ paneLayoutsByWindow: { ...map, [windowId]: revived } })
    if (!isActive) {
      // The map entry now holds a placed grid → setActiveWindow performs a plain switch (no auto-place) and
      // attaches the active pane; the outgoing window's grid is snapshotted untouched (R1/R6).
      this.setActiveWindow(windowId)
    } else {
      this.applyWorkspace(revived, revived.layout ? { paneLayout: revived.layout } : {})
    }
    // Acquire only the revived window's focused pane at the caller's viewport. Other placed panes remain
    // on-demand and are acquired when focused.
    this.lastAttachSize = { cols, rows }
    this.attachPlacedPanes()
    this.persistLastLayout()
  }

  focusWindowRemote(windowId: string): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    if (!this.desktopWindowExists(windowId)) return
    const mutation = this.beginRemoteMutation('focus-window', 'focus-window')
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.focusWindow(mutation.requestId, windowId)
  }

  /** Sidebar project navigation mirrors the desktop: return to that project's remembered visible window; if the
   * memory is no longer visible, choose its first durable window and revive it when needed. Window ordering comes
   * directly from authoritative desktop metadata. */
  openProjectInBrowser(projectId: string, cols = 80, rows = 24): void {
    const metadata = this.view.workspaceMetadata
    const project = metadata?.projects.find((candidate) => candidate.id === projectId)
    if (!metadata || !project || project.windows.length === 0) return

    const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) {
      map[this.view.activeWindowId] = preserveWindowStashed(this.workspacePanes(), map[this.view.activeWindowId])
    }
    const rememberedId = this.focusedWindowByProject.get(projectId)
    const remembered = rememberedId
      ? project.windows.find((window) =>
          window.id === rememberedId && this.browserWindowIsVisible(window, map))
      : undefined
    const target = remembered ?? project.windows[0]
    if (!target) return

    this.focusedWindowByProject.set(projectId, target.id)
    if (this.browserWindowIsVisible(target, map)) {
      this.setActiveWindow(target.id, { attachSize: { cols, rows } })
    } else {
      this.reviveWindowInBrowser(target.id, cols, rows)
    }
  }

  /** PER-WINDOW: switch which window's grid the REMOTE shows. Swaps the mirror (paneLayout/browserStashed) to the
   * target window's WorkspacePanes from the map, sets activeWindowId, and attaches that window's active pane session.
   * Does NOT tell the desktop (remote↔local layouts are separate — no focusWindow wire). No-op if already active or the
   * window doesn't exist. R11(3): switching to an ALIVE window (one with a placed grid) never changes its layout.
   * `opts.preferPaneId` (R10 single-pane revive of a stashed window): when the target grid is EMPTY, auto-place THAT
   * stashed pane instead of the first one — clicking one pane of a stashed window must revive the window with ONLY
   * that pane, full-size. */
  setActiveWindow(windowId: string, opts: { preferPaneId?: string | null; attachSize?: { cols: number; rows: number } } = {}): void {
    if (!this.desktopWindowExists(windowId)) return
    this.rememberProjectWindow(windowId)
    if (windowId === this.view.activeWindowId) return
    // Defensively snapshot the current active window's live mirror into the map before swapping (applyWorkspace keeps
    // it current, but this covers any edge where the mirror led the map). The outgoing window's user-stashed
    // flag (R2) is preserved; the TARGET's flag clears below (opening a window un-stashes it — the
    // workspacePanesFrom rebuild deliberately drops `windowStashed`).
    const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) {
      map[this.view.activeWindowId] = preserveWindowStashed(this.workspacePanes(), map[this.view.activeWindowId])
    }
    let target = map[windowId] ?? emptyWorkspace()
    // AUTO-PLACE on first view: a window whose grid is empty but has stashed panes would show a blank grid — the user
    // clicks the tab and "nothing opens". So place the window's FIRST stashed pane into its grid (the rest stay
    // revivable), matching how the active window lands on a session on connect. Once placed, the map remembers it.
    if (!target.layout && target.stashed.length > 0) {
      // Only a stash row that HAS a session auto-places. A session-less row is a desktop pane whose session
      // isn't named yet (redacted mid-creation) — placing it would show a dead shell and the lone-empty-leaf
      // canonicalization would drop the row. It stays stashed; the `session-named` upgrade (+ landing or a
      // later click) brings it live (pane lifecycle contract §0).
      const preferred = opts.preferPaneId ? target.stashed.find((s) => s.paneId === opts.preferPaneId) : undefined
      const first = (preferred?.sessionId ? preferred : undefined) ?? target.stashed.find((s) => s.sessionId)
      if (first) {
        const placed = reviveInWorkspace(target, first.paneId)
        if (placed !== target) {
          target = placed
          // Lifecycle `landing-burned` (user action): the user opened this window and the browser placed a
          // pane for them — the R7 landing designation is consumed.
          this.pendingLandingWindows.delete(windowId)
        }
      }
    }
    this.update({
      activeWindowId: windowId,
      paneLayoutsByWindow: { ...map, [windowId]: workspacePanesFrom(target.layout ?? singlePane(), target.stashed) },
      paneLayout: target.layout ?? singlePane(),
      browserStashed: [...target.stashed],
    })
    // Track the ACTIVE window's project for the R14 eviction preference (same-project before Terminal).
    this.activeProjectIdHint = this.projectIdOfWindow(this.view.workspaceMetadata, windowId) ?? this.activeProjectIdHint
    // Attach the newly-placed / active pane's session so its terminal paints + takes input.
    const sid = target.layout ? activeLeaf(target.layout).sessionId : null
    if (sid) {
      // Attach at the CALLER's intended viewport when it has one (a create/revive completion knows its
      // size). The old hardcoded 80x24 raced the completion's correctly-sized attach: the second send
      // bounced off the agent as `already_attached`, so the create viewport never took effect on the wire.
      const size = opts.attachSize ?? { cols: 80, rows: 24 }
      this.lastAttachSize = size
      this.activatePaneSession(sid)
      this.attach(sid, size.cols, size.rows)
    }
    // A multi-pane target window may hold placed sessions that were never attached this connection —
    // attach the rest too so every tile paints, not just the active one.
    this.attachPlacedPanes()
    // Invariant 3 (Slice 4): the previous window's attached session must not survive the switch unplaced —
    // without this, switching to a pane-less window left `attachedSession` set and the legacy full-height
    // canvas painted the OLD window's session over the empty grid (the ghost fullscreen canvas).
    this.enforceAttachedSessionPlacement()
    // Slice 1+2: window switches are durable — the v2 row carries activeWindowId, so a refresh lands back here.
    this.persistLastLayout()
  }

  private desktopPaneTarget(paneId: string): { windowId: string; paneId: string } | null {
    const metadata = this.view.workspaceMetadata
    if (!metadata) return null
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        if (window.panes.some((pane) => pane.id === paneId)) {
          return { windowId: window.id, paneId }
        }
      }
    }
    return null
  }

  /** The DESKTOP metadata pane id currently holding `sessionId`, or null when the metadata doesn't know the
   * session. The single-identity bridge (`pane identity contract`): every browser
   * structure keyed by pane identity keys by THIS id whenever the session has a desktop existence. */
  private desktopPaneIdForSession(sessionId: string): string | null {
    for (const project of this.view.workspaceMetadata?.projects ?? []) {
      for (const window of project.windows) {
        const pane = window.panes.find((p) => p.sessionId === sessionId)
        if (pane) return pane.id
      }
    }
    return null
  }

  /** The live session id for a desktop-metadata pane id, or null if unknown. Used to place a desktop pane into the
   * remote's own grid (bind the new browser pane to the desktop pane's session). */
  private desktopSessionForPane(paneId: string): string | null {
    const metadata = this.view.workspaceMetadata
    if (!metadata) return null
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        const pane = window.panes.find((p) => p.id === paneId)
        if (pane) return pane.sessionId
      }
    }
    return null
  }

  private desktopPaneIsStashed(paneId: string): boolean {
    const metadata = this.view.workspaceMetadata
    if (!metadata) return false
    for (const project of metadata.projects) {
      for (const window of project.windows) {
        const pane = window.panes.find((p) => p.id === paneId)
        if (pane) return Boolean(pane.stashed)
      }
    }
    return false
  }

  private desktopWindowExists(windowId: string): boolean {
    const metadata = this.view.workspaceMetadata
    if (!metadata) return false
    return metadata.projects.some((project) => project.windows.some((window) => window.id === windowId))
  }

  newWindowRemote(projectId: string, name?: string, opts: NewWindowOptions = {}, cols = 80, rows = 24): void {
    if (this.view.creatingSession) return
    if (!this.session?.isAuthenticated) return
    const project = this.view.workspaceMetadata?.projects.find((p) => p.id === projectId)
    if (!project) return
    const windowName = name?.trim() || `Window ${project.windows.length + 1}`
    const creation = this.beginRemoteCreation('new-window', 'new-window', cols, rows)
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.newWindow(creation.requestId, project.id, windowName, {
      ...this.createContext(),
      ...opts,
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  createProjectRemote(opts: ProjectEditOptions, cols = 80, rows = 24): void {
    if (this.view.creatingSession || !this.session?.isAuthenticated) return
    if (!opts.name?.trim() || !opts.root?.trim()) return
    const creation = this.beginRemoteCreation('project-create', 'project-create', cols, rows)
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.createProject(creation.requestId, {
      ...opts,
      cols: creation.geometry.cols,
      rows: creation.geometry.rows,
    })
  }

  updateProjectRemote(projectId: string, opts: ProjectEditOptions): void {
    if (this.view.creatingSession || !this.session?.isAuthenticated) return
    const project = this.view.workspaceMetadata?.projects.find((p) => p.id === projectId)
    if (!project) return
    if (!opts.name?.trim() && !opts.root?.trim() && !opts.icon?.trim() && !opts.accentColor?.trim() && !opts.agent && !opts.resumeMode && !opts.model?.trim() && opts.dangerouslySkipPermissions === undefined && opts.customCommand === undefined && opts.directories === undefined) return
    const mutation = this.beginRemoteMutation('project-update', 'project-update')
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    this.session.updateProject(mutation.requestId, project.id, opts)
  }

  deleteProjectRemote(projectId: string): boolean {
    if (this.view.creatingSession) return false
    if (!this.session?.isAuthenticated) {
      this.update({ desktopActionMessage: 'Delete project is unavailable while the desktop is disconnected.' })
      return false
    }
    const project = this.view.workspaceMetadata?.projects.find((p) => p.id === projectId)
    if (!project) {
      this.update({ desktopActionMessage: 'Delete project could not start because the project is no longer in the desktop snapshot.' })
      return false
    }
    const mutation = this.beginRemoteMutation('project-delete', 'project-delete')
    // Queue the destructive request BEFORE publishing `creatingSession`. Publishing view state can synchronously
    // rebuild the remote shell (including the project sidebar and its modal); the wire intent must not depend on
    // any DOM/controller callback surviving that rebuild. Other remote mutations happen to tolerate the old
    // update-then-send order, but Delete is the operation the owner observed becoming a silent no-op at this edge.
    this.session.deleteProject(mutation.requestId, project.id)
    this.update({ creatingSession: true, createSessionError: null, desktopActionMessage: null })
    return true
  }

  /** Close a pane; its sibling collapses into the split. No-op on the last pane. */
  closePane(paneId: string): void {
    const closing = findLeaf(this.view.paneLayout, paneId)
    const paneLayout = closePaneInLayout(this.view.paneLayout, paneId)
    if (paneLayout === this.view.paneLayout) return
    if (closing?.sessionId) this.detachSessionChannel(closing.sessionId)
    this.setActiveLayout(paneLayout)
    this.activatePaneSession(activeLeaf(paneLayout).sessionId)
    this.persistLastLayout() // the arrangement changed → keep the saved layout current
  }

  /** Close every pane EXCEPT `keepPaneId`, leaving a single pane holding that one. Reuses closePane per other
   * leaf so each session's detach/channel cleanup is correct. No-op for an unknown id or when already single. */
  closeOtherPanes(keepPaneId: string): void {
    if (!findLeaf(this.view.paneLayout, keepPaneId)) return
    // Snapshot the OTHER leaf ids up front (the layout is re-derived after each close). Closing collapses the
    // tree toward the kept pane regardless of order.
    const others = leaves(this.view.paneLayout.root).map((l) => l.id).filter((id) => id !== keepPaneId)
    if (others.length === 0) return
    for (const id of others) {
      if (findLeaf(this.view.paneLayout, id)) this.closePane(id)
    }
    // Make sure the surviving pane is the active input target.
    const survivor = findLeaf(this.view.paneLayout, keepPaneId) ?? activeLeaf(this.view.paneLayout)
    this.setActiveLayout(focusPaneInLayout(this.view.paneLayout, survivor.id))
    this.activatePaneSession(activeLeaf(this.view.paneLayout).sessionId)
  }

  /** Move pane focus. No-op for an unknown pane id. */
  focusPane(paneId: string): void {
    // No-op when this pane is ALREADY active — else every click on the focused pane makes a fresh paneLayout object →
    // full re-render → new canvas → a resize/refit on EVERY click (and it slows typing: each keystroke's repaint
    // competes with the rebuild). Only re-render when focus actually moves.
    if (this.view.paneLayout.activePaneId === paneId) return
    const paneLayout = focusPaneInLayout(this.view.paneLayout, paneId)
    this.setActiveLayout(paneLayout)
    this.activatePaneSession(activeLeaf(paneLayout).sessionId)
  }

  /** Desktop-parity: swap the SESSIONS of two panes (geometry unchanged, contents trade places), like the local
   * swap-pane. The active pane SLOT keeps focus, so its session may change → re-activate it. Live attaches are
   * unaffected (the sessions are already attached; only which pane shows which one moves). No-op for same/unknown
   * pane. Persists the new arrangement. */
  swapPanes(sourcePaneId: string, targetPaneId: string): void {
    const paneLayout = swapPaneSessions(this.view.paneLayout, sourcePaneId, targetPaneId)
    if (paneLayout === this.view.paneLayout) return // no-op (same pane / missing id)
    this.setActiveLayout(paneLayout)
    this.activatePaneSession(activeLeaf(paneLayout).sessionId) // the active slot may now hold a different session
    this.persistLastLayout()
  }

  /** Local-parity directional SWAP (the desktop's ← ↓ ↑ → move arrows): swap this pane with its neighbor in `dir`
   * (the two terminals trade slots; topology fixed). No-op at the window edge. */
  movePane(paneId: string, dir: EdgeDir): void {
    const neighbor = paneNeighbor(this.view.paneLayout, paneId, dir)
    if (!neighbor) return
    this.swapPanes(paneId, neighbor)
  }

  /** Local-parity SWALLOW (the desktop's ⇤ ⤓ ⤒ ⇥ arrows): the pane grows across `dir`, absorbing its neighbor into a
   * canonical layout where ALL panes survive (matches local's apply_swallow). Uses swallowCanonical, NOT the old
   * geometric swallowPane (which DROPPED the neighbor — one pane just vanished, the "swallow doesn't work" bug).
   * No-op when there's no neighbor that way. Persists. */
  swallowPaneInGrid(paneId: string, dir: EdgeDir): void {
    const paneLayout = swallowCanonical(this.view.paneLayout, paneId, dir)
    if (paneLayout === this.view.paneLayout) return
    this.setActiveLayout(paneLayout)
    this.activatePaneSession(activeLeaf(paneLayout).sessionId)
    this.persistLastLayout()
  }

  /** Desktop-parity: rebalance — snap every split back to an even ratio (the local Cmd+K). Ratios only; topology,
   * session bindings, active pane, and live attaches are all unchanged. No-op when already even. Persists. */
  rebalancePanes(): void {
    const paneLayout = rebalanceLayout(this.view.paneLayout)
    if (paneLayout === this.view.paneLayout) return // already even → nothing to do
    this.setActiveLayout(paneLayout)
    this.persistLastLayout()
  }

  /** Desktop-parity: divider drag — update one split ratio. The model clamps to the safe range; topology,
   * session bindings, active pane, and live attaches are unchanged. */
  setPaneSplitRatio(splitId: string, ratio: number): void {
    const paneLayout = setSplitRatio(this.view.paneLayout, splitId, ratio)
    if (paneLayout === this.view.paneLayout) return
    this.setActiveLayout(paneLayout)
    this.persistLastLayout()
  }

  /** Record (or clear) which session a leaf pane holds. Pure layout state — does NOT attach a renderer yet
   * (that's the next §4 slice). No-op for an unknown pane id. */
  setPaneSession(paneId: string, sessionId: string | null): void {
    this.setActiveLayout(setPaneSessionInLayout(this.view.paneLayout, paneId, sessionId))
  }

  /** Clear one pane without closing its split or killing the daemon session. If that session is attached in
   * the gated multi-pane path, detach only this browser's channel and leave the local session alive. */
  clearPaneSession(paneId: string): void {
    const leaf = findLeaf(this.view.paneLayout, paneId)
    if (!leaf?.sessionId) return
    const sessionId = leaf.sessionId
    this.detachSessionChannel(sessionId)
    const paneLayout = setPaneSessionInLayout(this.view.paneLayout, paneId, null)
    const activeSession = activeLeaf(paneLayout).sessionId
    this.setActiveLayout(paneLayout, { attachedSession: activeSession })
    this.activatePaneSession(activeSession)
  }
  detach(): void {
    connTrace.log(this.traceId, 'detach', 'start', 'ok', `sid=${short(this.view.attachedSession)}`)
    // Keep the browser's pane arrangement, but make this navigation authoritative for the current connection:
    // later session_list/workspace_update reconciles may refresh metadata, never reopen the terminal by inference.
    this.intentionalDetachGeneration = this.connectionGeneration
    this.resumeSessionId = null // intentional detach → don't auto-resume this session
    this.persistHints()
    this.cancelWinsizeRefresh()
    this.cancelAllWinsizeSettleRepushes(true)
    this.cancelPaneHydrationState()
    // Release EVERY confirmed browser attach exactly once, not only the currently-focused session. Pending
    // attaches have no wire ownership yet; clear their local watchdogs and let a late attach_ok prove ownership
    // before shouldAcceptAttach drains it. RemoteSession.detach() below then only clears held/sync state because the
    // active confirmed binding has already been released here.
    const confirmed = this.multiAttach.bindings()
    for (const sessionId of this.pendingWireAttaches) this.abandonedPendingAttaches.add(sessionId)
    const lifecycleSessions = new Set([
      ...confirmed.map((binding) => binding.sessionId),
      ...this.attachWatchdogs.keys(),
      ...this.pendingWireAttaches,
    ])
    for (const { sessionId, channel } of confirmed) {
      this.session?.detachSession(sessionId)
      this.multiAttach.detachSession(sessionId)
      this.multiPaneTerminal.detachPane(channel)
    }
    for (const sessionId of lifecycleSessions) this.clearAttachLifecycle(sessionId, true)
    this.clearAttachWatchdogs()
    this.clearPaneSwitchWatchdog()
    this.multiAttach.clear()
    this.multiPaneOutputEnabled = false
    this.session?.detach()
    this.update({ phase: 'sessions', attachedSession: null, terminalAcquisition: null })
    this.flushDeferredAgentSessionRefresh()
  }
  // WINSIZE OWNER (docs/architecture/terminal.md): the browser resizes the shared PTY ONLY when it is the owner
  // (winsizeOwner==='remote', set via the Local/Remote topbar toggle). Owner==='local' (default) → the browser NEVER
  // resizes; it scales the grid the desktop sized. One owner at a time → no ping-pong. Flipping the toggle hands the
  // pen over cleanly so Claude/TUIs redraw for whichever screen is the owner.
  private remoteOwnsWinsize(): boolean {
    return this.view.winsizeOwner === 'remote'
  }
  /** Set the winsize owner (the Local/Remote toggle). 'remote' lets this browser size the PTY (Claude redraws for the
   * phone); 'local' returns sizing to the desktop (browser scales). On switching TO 'remote', immediately push the
   * active pane's current size so the daemon reflows now. */
  setWinsizeOwner(owner: 'local' | 'remote'): void {
    const alreadyOwner = this.view.winsizeOwner === owner
    // Optimistic: flip the local flag now (snappy UI), tell the agent, and let its winsize_owner_changed reply
    // reconcile (the agent applies the serving>0 rule — e.g. it stays 'local' if no remote is actually connected).
    if (!alreadyOwner) this.update({ winsizeOwner: owner })
    this.session?.setWinsizeOwner(owner === 'remote')
    if (owner === 'local') this.cancelAllWinsizeSettleRepushes()
    if (owner === 'remote') {
      this.pushActivePaneResize()
      // Internal echo of the last known size — NOT a fresh app measurement (pushActivePaneResize above asks the
      // app to measure; when wired, its resize() call marks the viewport measured).
      this.applyResize(this.lastAttachSize.cols, this.lastAttachSize.rows)
      this.refreshActiveSessionAfterWinsizeClaim()
      this.schedulePlacedWinsizeSettleRepushes()
    }
  }
  /** Remote is the production viewport authority. Apply the ownership intent before attach/switch so the attach's
   * cols/rows are not treated as a one-off while local keeps owning the next repaint. Idempotent but deliberately
   * resends the owner intent; the agent handles it as state, not a toggle. */
  private ensureRemoteWinsize(cols: number, rows: number): void {
    if (this.view.winsizeOwner !== 'remote') this.update({ winsizeOwner: 'remote' })
    this.session?.setWinsizeOwner(true)
    this.lastAttachSize = { cols, rows }
  }
  /** Ask the app layer to re-measure + resend the active pane's size (used right after taking ownership). The app
   * wires this so it can read the real canvas box; a no-op until wired. */
  private pushResize: (() => void) | null = null
  onPushActivePaneResize(fn: () => void): void { this.pushResize = fn }
  private pushActivePaneResize(): void { this.pushResize?.() }

  /** Injected by the DOM host. Creation actions in app-shell historically passed a whole-window estimate; the
   * controller now asks the host for the actual mounted terminal/future-terminal slot at the moment of intent.
   * The returned source is retained only for this creation attempt, so a later local winsize claim is unaffected. */
  onMeasureRemoteCreationGeometry(
    fn: (request: RemoteCreationMeasurementRequest) => {
      cols: number
      rows: number
      source: 'remote-terminal-slot' | 'remote-shell-slot'
    } | null,
  ): void {
    this.measureRemoteCreationGeometry = fn
  }

  private captureRemoteCreationGeometry(
    cols: number,
    rows: number,
    kind: RemoteCreationKind,
    placement: RemoteCreationPlacement,
  ): PendingRemoteCreationGeometry {
    const callerFallback = normalizedRemoteCreationGeometry({ cols, rows }, 'legacy-fallback')
    const measured = this.measureRemoteCreationGeometry?.({
      kind,
      targetPaneId: placement.targetPaneId ?? null,
    }) ?? null
    if (measured && validRemoteCreationGrid(measured)) {
      this.viewportMeasured = true
      this.lastAttachSize = { cols: measured.cols, rows: measured.rows }
      return measured
    }
    if (this.viewportMeasured) {
      // A creation reply is bound to the pane captured at intent time, not whichever pane focus drifted to while
      // the request was being measured. Prefer that target's measured size; only target-less operations may use
      // the currently active pane as their cache source.
      if (placement.targetPaneId) {
        const targetSession =
          findLeaf(this.view.paneLayout, placement.targetPaneId)?.sessionId ?? null
        const targetCached = targetSession ? this.measuredWinsizes.get(targetSession) : null
        if (targetCached) {
          return normalizedRemoteCreationGeometry(targetCached, 'remote-measured-cache')
        }
        // An empty future pane has no session cache by definition. Preserve the caller's prospective slot
        // estimate instead of borrowing an unrelated focused pane's last measurement.
        return callerFallback
      }
      const activeSession = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
      const cached = activeSession ? this.measuredWinsizes.get(activeSession) : null
      const size = cached ?? this.lastAttachSize
      return normalizedRemoteCreationGeometry(size, 'remote-measured-cache')
    }
    return callerFallback
  }

  private nextRemoteMutationRequestId(requestPrefix: string): string {
    const count = (this.creationRequestCounts.get(requestPrefix) ?? 0) + 1
    this.creationRequestCounts.set(requestPrefix, count)
    return count === 1 ? requestPrefix : `${requestPrefix}:${count}`
  }

  private beginRemoteMutation(
    requestPrefix: string,
    kind: Exclude<RemoteDesktopMutationKind, RemoteCreationKind>,
  ): PendingRemoteMutation {
    const pending = { requestId: this.nextRemoteMutationRequestId(requestPrefix), kind } as const
    this.pendingRemoteMutation = pending
    return pending
  }

  private takeRemoteMutation(
    requestId: string,
    expectedKind: RemoteDesktopMutationKind | readonly RemoteDesktopMutationKind[],
  ): PendingRemoteMutation | null {
    const expected = Array.isArray(expectedKind) ? expectedKind : [expectedKind]
    const pending = this.pendingRemoteMutation
    if (!pending || pending.requestId !== requestId || !expected.includes(pending.kind)) {
      connTrace.log(this.traceId, 'mutation', 'stale_reply', 'warn', `request=${requestId || 'missing'}`)
      return null
    }
    this.pendingRemoteMutation = null
    return pending
  }

  /** Start one correlated remote creation. The first id keeps the legacy spelling for compatibility and readable
   * traces; retries gain a suffix so a late reply from an abandoned attempt cannot consume the next attempt's
   * geometry or pane target. Only one creation is intentionally allowed in flight by `creatingSession`. */
  private beginRemoteCreation(
    requestPrefix: string,
    kind: RemoteCreationKind,
    cols: number,
    rows: number,
    placement: RemoteCreationPlacement = {},
  ): PendingRemoteCreationAttempt {
    const requestId = this.nextRemoteMutationRequestId(requestPrefix)
    // In the stable sessions phase, first paint the same black Loading shell the live renderer will replace.
    // Its hidden chrome probe exposes the exact future terminal viewport, so the PTY is created at remote size
    // rather than at a whole-window estimate and corrected one frame later.
    if (this.view.phase === 'sessions' && this.view.terminalAcquisition === null) {
      this.update({ terminalAcquisition: 'loading' })
    }
    const geometry = this.captureRemoteCreationGeometry(cols, rows, kind, placement)
    const expectedTargetSessionId = placement.targetPaneId
      ? findLeaf(this.view.paneLayout, placement.targetPaneId)?.sessionId
      : undefined
    const attempt: PendingRemoteCreationAttempt = {
      requestId,
      kind,
      geometry,
      ...placement,
      ...(expectedTargetSessionId !== undefined ? { expectedTargetSessionId } : {}),
    }
    this.pendingRemoteCreations.set(requestId, attempt)
    this.pendingRemoteMutation = { requestId, kind }
    connTrace.log(
      this.traceId,
      'create_geometry',
      'captured',
      'ok',
      `request=${requestId} source=${geometry.source} cols=${geometry.cols} rows=${geometry.rows}`,
    )
    return attempt
  }

  /** Consume only the matching attempt. A stale/duplicate reply may describe a session that now exists on the
   * desktop, but it must never steal a newer attempt's geometry, pane target, or UI completion. A subsequent
   * authoritative session list will still discover that desktop session. */
  private takeRemoteCreation(
    requestId: string,
    expectedKind: RemoteCreationKind,
  ): PendingRemoteCreationAttempt | null {
    const attempt = requestId ? this.pendingRemoteCreations.get(requestId) : null
    if (!attempt || attempt.kind !== expectedKind) {
      connTrace.log(this.traceId, 'create_geometry', 'stale_reply', 'warn', `request=${requestId || 'missing'}`)
      return null
    }
    if (!this.takeRemoteMutation(requestId, expectedKind)) return null
    this.pendingRemoteCreations.delete(requestId)
    return attempt
  }

  private rejectRemoteCreationReply(requestId: string, expectedKind: RemoteCreationKind): boolean {
    return this.takeRemoteCreation(requestId, expectedKind) === null
  }

  private abandonRemoteCreations(): PendingRemoteCreationAttempt[] {
    const abandoned = [...this.pendingRemoteCreations.values()]
    this.pendingRemoteCreations.clear()
    this.pendingRemoteMutation = null
    return abandoned
  }

  resize(cols: number, rows: number): void {
    if (!this.remoteOwnsWinsize()) return // desktop owns the winsize; browser scales instead of resizing the PTY
    this.viewportMeasured = true // APP-layer measurement (public entry point) — see viewportMeasured
    const sessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    if (sessionId) this.measuredWinsizes.set(sessionId, { cols, rows })
    this.applyResize(cols, rows)
  }
  /** Internal resize (owner echo, e.g. setWinsizeOwner re-pushing lastAttachSize) — applies the size WITHOUT
   * claiming a fresh app-layer measurement, so the unmeasured 80×24 default can't masquerade as measured. */
  private applyResize(cols: number, rows: number): void {
    if (!this.remoteOwnsWinsize()) return
    const sessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    if (sessionId && (this.lastAttachSize.cols !== cols || this.lastAttachSize.rows !== rows)) {
      this.retirePaneScrollbackFlow(sessionId, true)
    }
    this.lastAttachSize = { cols, rows }
    this.activatePaneSession(activeLeaf(this.view.paneLayout).sessionId)
    this.session?.resize(cols, rows, true)
  }
  /** Resize a specific attached pane — only when this browser owns the winsize (else a no-op; the desktop owns it). */
  resizePane(sessionId: string, cols: number, rows: number): void {
    if (!this.remoteOwnsWinsize()) return // ping-pong avoidance: only the owner drives the shared PTY winsize
    this.viewportMeasured = true // APP-layer measurement (public entry point)
    this.measuredWinsizes.set(sessionId, { cols, rows })
    this.applyResizePane(sessionId, cols, rows)
  }
  private applyResizePane(sessionId: string, cols: number, rows: number): void {
    if (!this.remoteOwnsWinsize()) return
    const channel = this.multiAttach.channelForSession(sessionId)
    if (channel === null) return
    const bounds = this.multiPaneTerminal.gridBounds(sessionId)
    if (bounds && (bounds.cols !== cols || bounds.rows !== rows)) {
      // History rows are geometry-specific. A resize retires any old-geometry request/cache before the daemon's
      // replacement Grid; otherwise the bank can hold stale history indefinitely (or loop partial 256-row pages).
      this.retirePaneScrollbackFlow(sessionId, true)
    }
    const activeSession = activeLeaf(this.view.paneLayout).sessionId
    const viewed = activeSession === sessionId
    if (viewed) this.lastAttachSize = { cols, rows }
    // Session-addressed resize leaves the input channel untouched. Background geometry remains valid but cannot
    // claim viewed presence/winsize ownership on the agent.
    this.session?.resizeSession(sessionId, cols, rows, viewed)
  }
  /** Hand the canvas to the attached session for rendering. */
  attachRenderer(canvas: HTMLCanvasElement): void {
    this.session?.attachRenderer(canvas)
  }

  /** Production remote surface: one visible terminal, backed by RemoteSession's single-channel renderer/cache. */
  attachSingleRenderer(canvas: HTMLCanvasElement): void {
    this.multiPaneOutputEnabled = false
    this.session?.attachRenderer(canvas)
  }
  setTerminalSearchHighlights(spans: readonly HighlightSpan[]): void {
    const activeSessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    if (activeSessionId) this.multiPaneTerminal.setSearchHighlights(activeSessionId, spans)
    this.session?.setSearchHighlights(spans)
  }

  setPaneSearchQuery(sessionId: string, query: string): void {
    this.multiPaneTerminal.setSearchQuery(sessionId, query)
  }

  paneSearchStatus(sessionId: string): TerminalSearchStatus {
    return this.multiPaneTerminal.searchStatus(sessionId)
  }

  paneSearchMatches(sessionId: string): readonly TerminalSearchMatch[] {
    return this.multiPaneTerminal.searchMatches(sessionId)
  }

  activePaneSearchMatch(sessionId: string): TerminalSearchMatch | null {
    return this.multiPaneTerminal.activeSearchMatch(sessionId)
  }

  nextPaneSearchMatch(sessionId: string): TerminalSearchMatch | null {
    return this.multiPaneTerminal.nextSearchMatch(sessionId)
  }

  prevPaneSearchMatch(sessionId: string): TerminalSearchMatch | null {
    return this.multiPaneTerminal.prevSearchMatch(sessionId)
  }

  paneSearchHighlightSpans(sessionId: string, grid: { rows: number; cols: number }): readonly HighlightSpan[] {
    return highlightSpans(
      this.multiPaneTerminal.searchMatches(sessionId),
      this.multiPaneTerminal.activeSearchMatch(sessionId),
      grid,
    )
  }

  /** Compute a pane's COMBINED highlights (search matches + selection) from its last painted grid bounds and
   * push them to its renderer. No-op until that pane has painted. Called by the panes UI on search
   * input/next/prev AND on selection drag/clear so both stay live (mirrors the single-terminal path). */
  refreshPaneHighlights(sessionId: string): void {
    const bounds = this.multiPaneTerminal.gridBounds(sessionId)
    if (!bounds) return
    const combined = [
      ...this.paneSearchHighlightSpans(sessionId, bounds),
      ...this.multiPaneTerminal.selectionSpans(sessionId),
    ]
    this.multiPaneTerminal.setSearchHighlights(sessionId, combined)
  }

  /** @deprecated kept for back-compat — now refreshes the combined (search + selection) highlight set. */
  refreshPaneSearchHighlights(sessionId: string): void {
    this.refreshPaneHighlights(sessionId)
  }

  setPaneSelectionGeometry(sessionId: string, geometry: SelectionGeometry): void {
    this.multiPaneTerminal.setSelectionGeometry(sessionId, geometry)
  }

  /** The AUTHORITATIVE selection geometry for a pane: the daemon grid's real rows/cols + the renderer's
   * actual on-screen cell size under its contain transform. Null until the pane has painted. Mouse px→cell
   * mapping MUST use this — a hardcoded cell constant drifts by rows as soon as the grid is scaled to fit
   * the pane (the "selection lands two lines above" bug). */
  paneSelectionGeometryFor(sessionId: string): SelectionGeometry | null {
    const bounds = this.multiPaneTerminal.gridBounds(sessionId)
    const cell = this.multiPaneTerminal.screenCellPx(sessionId)
    if (!bounds || !cell) return null
    return { rows: bounds.rows, cols: bounds.cols, cellW: cell.cellW, cellH: cell.cellH }
  }

  beginPaneSelection(sessionId: string, point: PixelPoint): void {
    this.multiPaneTerminal.beginSelection(sessionId, point)
  }

  dragPaneSelection(sessionId: string, point: PixelPoint): void {
    this.multiPaneTerminal.dragSelection(sessionId, point)
  }

  endPaneSelection(sessionId: string): void {
    this.multiPaneTerminal.endSelection(sessionId)
  }

  clearPaneSelection(sessionId: string): void {
    this.multiPaneTerminal.clearSelection(sessionId)
  }

  paneSelectionRange(sessionId: string): SelectionRange | null {
    return this.multiPaneTerminal.selectionRange(sessionId)
  }

  paneSelectionSpans(sessionId: string): readonly HighlightSpan[] {
    return this.multiPaneTerminal.selectionSpans(sessionId)
  }

  paneSelectedText(sessionId: string): string {
    return this.multiPaneTerminal.selectedText(sessionId)
  }

  paneVisibleText(sessionId: string): string {
    return this.multiPaneTerminal.visibleText(sessionId)
  }

  shouldShowPaneSelectionCopy(sessionId: string): boolean {
    return this.multiPaneTerminal.shouldShowSelectionCopy(sessionId)
  }

  paneSelectionCopyAnchorPx(sessionId: string): PixelPoint | null {
    return this.multiPaneTerminal.selectionCopyAnchorPx(sessionId)
  }

  /** Gated ?panes=1 renderer path: render the current live attach through the multi-pane bridge. */
  attachPaneRenderer(canvas: HTMLCanvasElement): boolean {
    const sid = this.view.attachedSession
    const channel = sid ? (this.multiAttach.channelForSession(sid) ?? this.session?.channel) : this.session?.channel
    if (!sid || channel === null || channel === undefined) {
      this.attachSingleRenderer(canvas)
      return false
    }
    this.multiPaneOutputEnabled = true
    const renderer = this.multiPaneTerminal.rendererUsesCanvas(sid, canvas)
      ? null
      : new GridRenderer(canvas)
    this.multiPaneTerminal.attachPane(channel, sid, renderer)
    return true
  }

  /** §4 N-up: bind a pane canvas to a SPECIFIC attached session (not just the active one), so every live
   * pane leaf paints its own terminal. The session's channel is looked up in the multi-attach manager (it
   * was recorded on attach_ok). Returns false if that session isn't attached yet (no channel) so the caller
   * can fall back to a placeholder; never disturbs the default single-session path. */
  attachPaneRendererFor(sessionId: string, canvas: HTMLCanvasElement): boolean {
    const channel = this.multiAttach.channelForSession(sessionId)
      ?? (this.view.attachedSession === sessionId ? this.session?.channel ?? null : null)
    if (channel === null || channel === undefined) return false
    this.multiPaneOutputEnabled = true
    const renderer = this.multiPaneTerminal.rendererUsesCanvas(sessionId, canvas)
      ? null
      : new GridRenderer(canvas)
    this.multiPaneTerminal.attachPane(channel, sessionId, renderer)
    return true
  }

  /** §4 N-up adapter seam: bind any terminal-pane renderer to a specific attached session. Kept separate
   * from the canvas wrapper so controller-level tests can verify multi-channel routing without a DOM canvas. */
  attachPaneTerminalRendererFor(sessionId: string, renderer: TerminalPaneRenderer): boolean {
    const channel = this.multiAttach.channelForSession(sessionId)
      ?? (this.view.attachedSession === sessionId ? this.session?.channel ?? null : null)
    if (channel === null || channel === undefined) return false
    this.multiPaneOutputEnabled = true
    this.multiPaneTerminal.attachPane(channel, sessionId, renderer)
    return true
  }

  /** True when `sessionId` has a LIVE terminal channel — i.e. {@link attachPaneRendererFor} would succeed
   * right now. Read-only render probe (no attach side effects): the app's paneLayout-identity fast path uses
   * it to detect a PLACED pane whose canvas was skipped while its attach was still in flight (split adopt /
   * reconcile re-attach). Without this one-shot rebuild trigger, the attach_ok that finally arms the channel
   * changes NO layout identity, so the pane — often EVERY pane after a reconcile re-attach — stayed a blank
   * placeholder forever. */
  paneChannelReady(sessionId: string): boolean {
    const channel = this.multiAttach.channelForSession(sessionId)
      ?? (this.view.attachedSession === sessionId ? this.session?.channel ?? null : null)
    return channel !== null && channel !== undefined
  }
  /** The single-session (legacy) renderer's on-screen CSS-px cell size — the legacy analogue of
   * {@link paneSelectionGeometryFor}'s cell fields. Side-effect free (unlike the activeSession getter). */
  activeScreenCellPx(): { cellW: number; cellH: number } | null {
    const activeSessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    return (activeSessionId ? this.multiPaneTerminal.screenCellPx(activeSessionId) : null) ?? this.session?.screenCellPx() ?? null
  }

  /** Access the live session for input wiring (keydown/paste/scroll). */
  get activeSession(): RemoteSession | null {
    const active = activeLeaf(this.view.paneLayout).sessionId
    this.activatePaneSession(active)
    if (active && this.multiAttach.channelForSession(active) === null) return null
    return this.session
  }

  /**
   * SINGLE correct multi-pane scroll entry point. Scroll ONE pane's terminal by `deltaRows` (positive = UP into
   * history, negative = DOWN toward live) driven by that pane's OWN per-pane view state in the ChannelTerminalBank.
   *
   * The bug this fixes: the wheel handler used to call activeSession.scrollByRows, which reads the SINGLE
   * RemoteSession's viewOffset/historyLen — but in multi-pane the daemon's scrollback_rows replies are routed to
   * the bank (per-pane state), so the RemoteSession's historyLen stayed 0 and its offsets drifted from what the
   * bank actually painted → "can't scroll up". Now the offset comes from the bank (the same object that paints
   * the reply), and the request is sent for the pane's session id, so request + reply + paint all share one state.
   *
   * Falls back to the single-session path for a session that isn't a multi-pane pane (no channel), so callers can
   * route ALL wheel scroll through here.
   */
  scrollPaneBy(
    sessionId: string,
    deltaRows: number,
    pointerCell: { col: number; row: number } = { col: 0, row: 0 },
    modifiers: { shift?: boolean; alt?: boolean; ctrl?: boolean } = {},
  ): void {
    const channel = this.multiAttach.channelForSession(sessionId)
    if (!this.multiPaneOutputEnabled) {
      // A focus transition can retire/rebind a channel to make an unresolved request unambiguous. Until the fresh
      // attach_ok lands there is no valid scalar input/output owner; never let the previous pane's active channel
      // service this pane's wheel gesture.
      if (channel === null) return
      const existingFlow = this.paneScrollbackInFlight.get(sessionId)
      if (existingFlow && !existingFlow.sessionTraceOwned) {
        // The request was issued by the bank before the surface switched back to the scalar renderer. The scalar
        // has no matching trace and must not send a second request. Retire/rebind the channel; the fresh Grid
        // returns this surface to live and a later gesture starts from one unambiguous owner.
        this.reattachSessionFresh(sessionId)
        return
      }
      const modes = this.session?.liveModes() ?? null
      const altScreen = this.session?.isAltScreen() ?? false
      const mouseTracking = !!(modes && (modes.mouse_report || modes.mouse_drag || modes.mouse_motion))
      const wheelModes = modes && altScreen && !mouseTracking
        ? { ...modes, mouse_report: true, mouse_sgr: true }
        : modes
      if (wheelModes && altScreen) {
        const n = Math.min(6, Math.abs(deltaRows))
        const event = deltaRows > 0 ? ({ kind: 'wheelUp' } as const) : ({ kind: 'wheelDown' } as const)
        for (let i = 0; i < n; i++) {
          const seq = encodeMouse(event, pointerCell.col, pointerCell.row, wheelModes, modifiers)
          if (seq) this.session?.sendRawInput(new TextEncoder().encode(seq))
        }
        return
      }
      if (this.view.attachedSession === sessionId) this.session?.scrollByRows(deltaRows)
      return
    }
    const bankHasSession = this.multiPaneTerminal.hasSession(sessionId)
    // ALT-SCREEN + MOUSE REPORTING (Claude Code / vim): the app owns its own history — a real terminal encodes the wheel
    // as an SGR MOUSE REPORT (\x1b[<64;x;yM up / <65 down) so the APP scrolls its OWN content (NOT arrow keys, which
    // Claude reads as input-box cursor moves — the user confirmed the selection never leaves the input box). Local does
    // exactly this (maestro-renderer encode_mouse). deltaRows>0 = wheel up. One report per row (capped per notch).
    const modes = bankHasSession ? this.multiPaneTerminal.paneModes(sessionId) : this.session?.liveModes() ?? null
    // A full-screen app (Claude / vim) has NO daemon scrollback; instead it enables a mouse-tracking mode and expects
    // the wheel as an SGR mouse report, then scrolls its OWN viewport. Gate on ANY mouse mode (report/drag/motion) —
    // matching encodeMouse's mouse.any() and local's maestro-renderer (Claude uses motion/drag, not bare click 1000).
    const mouseTracking = !!(modes && (modes.mouse_report || modes.mouse_drag || modes.mouse_motion))
    const altScreen = bankHasSession ? this.multiPaneTerminal.isAltScreen(sessionId) : (this.session?.isAltScreen() ?? false)
    // Some full-screen agents redraw from mouse-wheel reports even when the grid snapshot has not yet reflected DECSET
    // mouse mode. If we fall back to daemon scrollback in alt-screen, the browser scroll is view-local and the next
    // app repaint snaps it back. Prefer PTY wheel input for all alt-screen panes; use SGR mouse reporting as the
    // compatibility default when the mode flags lag.
    const wheelModes = modes && altScreen && !mouseTracking
      ? { ...modes, mouse_report: true, mouse_sgr: true }
      : modes
    if (wheelModes && altScreen) {
      const n = Math.min(6, Math.abs(deltaRows))
      const event = deltaRows > 0 ? ({ kind: 'wheelUp' } as const) : ({ kind: 'wheelDown' } as const)
      for (let i = 0; i < n; i++) {
        const seq = encodeMouse(event, pointerCell.col, pointerCell.row, wheelModes, modifiers)
        if (!seq) continue
        if (channel !== null) this.session?.sendRawInputOn(sessionId, channel, seq)
        else this.session?.sendRawInput(new TextEncoder().encode(seq))
      }
      return
    }
    if (channel === null && !bankHasSession) {
      // Not a multi-pane pane (single-session path): use the RemoteSession's own scroll state.
      if (this.view.attachedSession === sessionId) this.session?.scrollByRows(deltaRows)
      return
    }
    const next = this.multiPaneTerminal.scrollBy(sessionId, deltaRows)
    if (next === null) return
    if (next === 0) {
      const pending = this.paneScrollbackInFlight.get(sessionId)
      if (pending) pending.latestOffset = 0
      this.multiPaneTerminal.jumpToLive(sessionId)
      return
    }
    const bounds = this.multiPaneTerminal.gridBounds(sessionId)
    const count = this.session?.scrollbackRequestCount(bounds?.rows ?? 24, bounds?.cols ?? 80)
      ?? (bounds?.rows ?? 24)
    this.sendPaneScrollbackRequest(sessionId, next, count)
  }

  /** Send a key to the current input target: the focused pane's session when present, else the attached
   * terminal. Used by shared controls like the mobile special-key bar that sit outside any one canvas. */
  sendKeyToActivePane(ev: KeyEvent): boolean {
    const activeSessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    if (activeSessionId) {
      this.activatePaneSession(activeSessionId)
      if (this.multiAttach.channelForSession(activeSessionId) === null) return false
    }
    if (!this.session) return false
    this.session.sendKey(ev)
    return true
  }

  /** Send one committed IME string to the current pane as literal interactive UTF-8 (never bracketed paste). */
  sendTextToActivePane(text: string): boolean {
    if (!text) return false
    const activeSessionId = activeLeaf(this.view.paneLayout).sessionId ?? this.view.attachedSession
    if (activeSessionId) {
      this.activatePaneSession(activeSessionId)
      if (this.multiAttach.channelForSession(activeSessionId) === null) return false
    }
    if (!this.session) return false
    this.session.sendText(text)
    return true
  }

  private activatePaneSession(sessionId: string | null): void {
    // Keep the OBSERVABLE active session in sync with the active pane. `attachedSession` drives the terminal
    // header label, single-terminal copy target, and diagnostics — so focusing/closing a pane that holds a
    // different session (or an empty one) must update it, not just the input channel. Only meaningful while
    // attached to a terminal; never resurrect the field after a full detach (phase left 'terminal').
    if (this.view.phase === 'terminal' && this.view.attachedSession !== sessionId) {
      this.update({ attachedSession: sessionId })
    }
    // Focusing a session means the user is now looking at it → it's read. Clear any unread flag.
    if (sessionId) this.clearUnread(sessionId)
    const previousSessionId = this.lastViewedSessionId
    if (previousSessionId && previousSessionId !== sessionId) {
      this.abandonPendingAttachOnDeparture(previousSessionId)
    }
    if (!sessionId) {
      if (
        previousSessionId
        && !this.multiPaneOutputEnabled
        && this.paneScrollbackInFlight.has(previousSessionId)
      ) {
        // Without protocol request ids an unresolved request cannot safely follow a reusable channel across a
        // single-surface focus departure. Retire that exact channel; on-demand focus may reacquire it later.
        this.releaseSessionForOnDemandReattach(previousSessionId)
      }
      this.lastViewedSessionId = null
      this.session?.setViewedChannel(null)
      return
    }
    const changed = previousSessionId !== sessionId
    this.lastViewedSessionId = sessionId
    if (
      changed
      && previousSessionId
      && !this.multiPaneOutputEnabled
      && this.paneScrollbackInFlight.has(previousSessionId)
    ) {
      this.releaseSessionForOnDemandReattach(previousSessionId)
    }
    this.multiAttach.setActive(sessionId)
    const channel = this.multiAttach.channelForSession(sessionId)
    if (channel !== null) this.session?.setActiveAttach(sessionId, channel)
    else this.session?.setViewedChannel(null)
    if (!changed) return
    // One ownership assertion per actual focus change (never per keystroke). If attach is in flight the explicit
    // Resize is ordered behind it, then onAttached repeats once to close the attach/focus race.
    if (this.activeHistoryWarm && this.activeHistoryWarm.sessionId !== sessionId) {
      clearTimeout(this.activeHistoryWarm.inactivityTimer)
      clearTimeout(this.activeHistoryWarm.absoluteTimer)
      this.activeHistoryWarm = null
    }
    this.ensureForegroundAttach(sessionId)
    this.schedulePaneHydration()
  }

  /** A non-active pane painted: flag it unread (content-blind, id only). No-op if it's the active session or
   * already flagged. */
  private noteSessionActivity(sessionId: string): void {
    if (sessionId === activeLeaf(this.view.paneLayout).sessionId) return // the focused pane is "read"
    if (this.view.unreadSessions.includes(sessionId)) return
    this.update({ unreadSessions: [...this.view.unreadSessions, sessionId] })
  }

  private clearUnread(sessionId: string): void {
    if (!this.view.unreadSessions.includes(sessionId)) return
    this.update({ unreadSessions: this.view.unreadSessions.filter((id) => id !== sessionId) })
  }

  // Scroll-view subscription (for the "jump to live" affordance). Kept OFF the view state so toggling it
  // never re-renders the DOM (which would destroy the live canvas).
  private scrollViewHandler: ((v: { atLive: boolean; offset: number; historyLen: number }) => void) | null = null
  onScrollView(handler: (v: { atLive: boolean; offset: number; historyLen: number }) => void): void {
    this.scrollViewHandler = handler
  }

  // Live structured-grid subscription for terminal search/highlight UI. Kept off view state so terminal
  // content is never persisted, logged, or pushed through the app shell render model.
  private gridSnapshotHandler: ((grid: GridSnapshot) => void) | null = null
  onGridSnapshot(handler: (grid: GridSnapshot) => void): void {
    this.gridSnapshotHandler = handler
  }

  // Raw-PTY output subscription (xterm.js renderer mode). Off the view state (no re-render).
  private rawOutputHandler: ((bytes: Uint8Array) => void) | null = null
  onRawOutput(handler: (bytes: Uint8Array) => void): void {
    this.rawOutputHandler = handler
  }
  get rendererMode(): 'grid' | 'xterm' {
    return this.deps.rendererMode ?? 'grid'
  }
  /** The app origin to redirect landing CTAs to (apex → app), or null when we ARE the app (run auth in-page). */
  get appRedirectOrigin(): string | null {
    return this.deps.appRedirectOrigin ?? null
  }

  /** Dev: record the browser's enrolled device id (the token subject / correct revoke target). */
  setBrowserDeviceId(id: string): void {
    this.update({ browserDeviceId: id })
  }

  // ---- reconnect / resume ----

  // The app sets this so the controller can auto-reattach (it needs the viewport cols/rows). Called on a
  // resume when the focused previously-attached session reappears in the list.
  private resumeAttachHandler: ((sessionId: string) => void) | null = null
  onResumeAttach(handler: (sessionId: string) => void): void {
    this.resumeAttachHandler = handler
  }

  /**
   * §4 resume on (re)connect: after a fresh `session_list_result`, preserve every pane binding that still exists,
   * but reacquire only the focused survivor. Sessions that ended while we were away are unbound and the user gets
   * the fixed, content-blind 'Session ended on desktop' notice. Other survivors remain on-demand and cache-hot once
   * the user focuses them.
   */
  /**
   * Dashboard parity: when a session list arrives and the browser is IDLE (no resume target, no pane-bound
   * session), pre-bind the active pane to a sensible default so resumePanes() attaches it and the user lands on
   * a live session — like the desktop app — instead of a bare list. Picks the last-opened session if it's still
   * live, else the first VISIBLE (non-hidden) session. Does nothing if a session is already bound/resuming or
   * none are visible (so "New session" remains the path when there's genuinely nothing to open).
   */
  private bindDefaultSessionIfIdle(sessions: string[], lastOpenedSessionId: string | null): void {
    if (this.intentionalDetachGeneration === this.connectionGeneration) return
    if (this.resumeSessionId) return // a resume target is already set
    if (leaves(this.view.paneLayout.root).some((l) => l.sessionId)) return // a pane is already bound
    // FIRST try to restore the desktop's saved MULTI-pane arrangement — reopen the same split workspace like the
    // desktop app. Only when it rehydrates to a real split with ≥1 still-live bound session; else fall through
    // to the single-default bind below.
    // ISOLATED GEOMETRY: land on ONE full-size pane; other local panes arrive STASHED to revive into the browser's
    // own geometry. Do NOT restore a saved/preset multi-pane split — that leaked local's pane COUNT into the browser
    // grid (2-pane local → 2-pane browser with an empty tile; closing local spread it). See
    // `pane existence contract`.
    const hidden = new Set(this.view.hiddenSessions)
    const live = new Set(sessions)
    // CONTAINMENT: the default bind must only place a session whose parent desktop window IS the active window
    // (the old bind was window-blind — a last-opened/first session from another window leaked into this grid).
    // Sessions the metadata doesn't know (or pre-window single-grid mode) have no containment info → allowed.
    const inActiveWindow = (sid: string) => this.sessionAllowedInActiveWindow(sid)
    const candidate =
      (lastOpenedSessionId && live.has(lastOpenedSessionId) && !hidden.has(lastOpenedSessionId) && inActiveWindow(lastOpenedSessionId)
        ? lastOpenedSessionId
        : sessions.find((s) => !hidden.has(s) && inActiveWindow(s))) ?? null
    if (!candidate) return // nothing visible to open IN THIS WINDOW → leave the grid empty (its own panes stay revivable)
    this.resumeSessionId = candidate // resumePanes() will attach it as the active session
    // Slice 2 ordering: this bind now runs AFTER the DB restore + reconcile, so the candidate usually sits in the
    // ACTIVE window's stash (keyed by its desktop pane id). Revive it through the canonical funnel — placed/stashed
    // stays a strict partition (invariant 1) and the leaf keeps the desktop pane id so a later stash/revive
    // round-trips on the same id. Plain active-pane bind stays the fallback (no stash entry — e.g. a metadata-less
    // agent where reconcile never ran).
    const ws = this.workspacePanes()
    const entry = ws.stashed.find((s) => s.sessionId === candidate)
    if (entry) {
      const next = reviveInWorkspace(ws, entry.paneId)
      if (next !== ws && next.layout) {
        this.applyWorkspace(next, { paneLayout: { ...next.layout, activePaneId: entry.paneId } })
        return
      }
    }
    const activePaneId = activeLeaf(this.view.paneLayout).id
    this.setActiveLayout(setPaneSessionInLayout(this.view.paneLayout, activePaneId, candidate))
  }

  private resumePanes(sessions: string[], ownsRestore?: () => boolean): void {
    const automaticAttachAllowed = this.intentionalDetachGeneration !== this.connectionGeneration
    const live = new Set(sessions)
    // every session we want back: the active resume target + each pane-bound session (deduped, order-stable).
    const wanted: string[] = []
    const want = (sid: string | null) => { if (sid && !wanted.includes(sid)) wanted.push(sid) }
    want(this.resumeSessionId)
    for (const leaf of leaves(this.view.paneLayout.root)) want(leaf.sessionId)

    if (wanted.length === 0) return // nothing was attached → nothing to resume

    const survivors = wanted.filter((sid) => live.has(sid))
    const ended = wanted.filter((sid) => !live.has(sid))

    // Preserve every surviving placement, then reacquire only the focused survivor at the right viewport size.
    // Slice 2 (DB placement is authoritative): when the (possibly restored) grid already shows live sessions,
    // an UNPLACED resume target — e.g. a stale hint for a session the durable layout keeps stashed — must not
    // steal the active pane; it stays stashed/revivable. An all-dead/empty grid keeps the classic behavior
    // (the resume target fills the active pane).
    // CONTAINMENT: a hint-resumed session bypasses the default bind's window filter — an empty grid must still
    // refuse to fill its active pane with a session that belongs to another desktop window.
    const placedSids = new Set(leaves(this.view.paneLayout.root).map((l) => l.sessionId).filter((s): s is string => s !== null))
    const gridHasLivePane = [...placedSids].some((sid) => live.has(sid))
    const resumable = gridHasLivePane
      ? survivors.filter((sid) => placedSids.has(sid))
      : survivors.filter((sid) => placedSids.has(sid) || this.sessionAllowedInActiveWindow(sid))
    // Restore only the focused pane now. Other placed survivors stay on-demand; no speculative wire attach runs.
    if (automaticAttachAllowed) {
      const focused = activeLeaf(this.view.paneLayout).sessionId
      const foreground = focused && resumable.includes(focused) ? focused : resumable[0]
      if (foreground && !this.abandonedPendingAttaches.has(foreground)) {
        if (!(this.attachWatchdogs.has(foreground) && this.multiAttach.channelForSession(foreground) === null)) {
          this.resumeAttachHandler?.(foreground)
          if (ownsRestore && !ownsRestore()) return
        }
      }
      this.schedulePaneHydration()
    }

    if (ended.length > 0) {
      // a wanted session ended on the desktop: unbind it from its pane(s) and clear a stale resume target.
      let paneLayout = this.view.paneLayout
      for (const leaf of leaves(paneLayout.root)) {
        if (leaf.sessionId && ended.includes(leaf.sessionId)) {
          paneLayout = setPaneSessionInLayout(paneLayout, leaf.id, null)
        }
      }
      if (this.resumeSessionId && ended.includes(this.resumeSessionId)) {
        this.resumeSessionId = survivors[0] ?? null
        this.persistHints() // saves the new (or null) resume session id — never chase a dead session on reload
      }
      const attachedSession = automaticAttachAllowed
        ? (this.view.attachedSession && live.has(this.view.attachedSession)
            ? this.view.attachedSession
            : survivors[0] ?? null)
        : null
      this.setActiveLayout(paneLayout, { attachedSession, error: 'Session ended on desktop' })
      if (ownsRestore && !ownsRestore()) return
      // Invariant 3 (Slice 4): the survivor fallback may not be PLACED in the active mirror (e.g. a resume
      // target the durable layout keeps stashed) — never leave an unplaced session attached.
      this.enforceAttachedSessionPlacement()
      if (ownsRestore && !ownsRestore()) return
      // DASHBOARD PARITY when the resume target died and nothing survived: without a fallback the user is
      // parked on the workspace placeholder tiles until they click a pane. Land them in a terminal instead —
      // bind the default live session (last-opened, else the first visible one in the active window; the same
      // containment-gated rule as a fresh connect) and attach it. The dead session itself is never attached
      // and the 'Session ended on desktop' note stays. No live session → nothing to open, the workspace stays.
      if (automaticAttachAllowed && resumable.length === 0 && !this.resumeSessionId) {
        this.bindDefaultSessionIfIdle(sessions, this.view.lastOpenedSessionId)
        if (ownsRestore && !ownsRestore()) return
        if (this.resumeSessionId) this.resumeAttachHandler?.(this.resumeSessionId)
      }
    }
  }

  /** Manual "Reconnect" — cancels backoff and reconnects now (resets the attempt counter). */
  async reconnect(trigger: 'manual' | 'online' | 'visible' = 'manual'): Promise<void> {
    this.clearReconnectTimer()
    this.stopReconnect = false
    this.reconnectAttempt = 0
    this.update({ nextRetryAtMs: undefined }) // G4: manual reconnect → no pending countdown
    await this.doReconnect(trigger)
  }

  /** Resume a bounded reconnect loop after the browser comes online or a sleeping/backgrounded page becomes
   * visible. This deliberately calls the public manual-reconnect path: it clears the exhausted counter and every
   * connect still mints fresh token/signaling state in connectTo(). Offline is the only eligible phase, so duplicate
   * online/visibility signals cannot replace a connecting or established owner. `stopReconnect` preserves the
   * deliberate passkey-authorization/revocation stop until the user explicitly taps Reconnect. */
  private wakeReconnectFromLifecycle(trigger: 'online' | 'visible'): void {
    if (
      this.disposed ||
      this.lifecycleReconnectInFlight ||
      this.stopReconnect ||
      this.view.phase !== 'offline' ||
      !this.view.selectedDevice ||
      this.view.reconnectingNow
    ) return

    this.lifecycleReconnectInFlight = true
    // Event listeners cannot await. Consume both outcomes so a rare dependency rejection cannot become an
    // unhandled page-level promise; connectTo owns the visible, content-blind connection error state.
    void this.reconnect(trigger).then(
      () => { this.lifecycleReconnectInFlight = false },
      () => { this.lifecycleReconnectInFlight = false },
    )
  }

  // Bounded exponential backoff. Stops on revoke/auth_refused-exhausted/no-selected-device.
  private scheduleReconnect(): void {
    // Every path into backoff is terminal for the current setup attempt, including pre-transport token failures.
    // Abort before the early-return gates so an exhausted/stopped loop cannot strand an owned cloud request.
    this.clearConnectWatchdog()
    if (this.stopReconnect || !this.view.selectedDevice) return
    if (this.reconnectAttempt >= RemoteClientController.RECONNECT_MAX) {
      // gave up → no next retry; drop the countdown so readiness shows the actionable "failed" state.
      this.update({ error: 'reconnect failed — tap Reconnect to retry', nextRetryAtMs: undefined })
      return
    }
    if (this.reconnectTimer) return // already scheduled
    // Bounded exponential backoff + jitter: cap the exponential growth (no unbounded delay) and spread retries
    // so a fleet of browsers dropping together (e.g. a relay restart) doesn't hammer signaling/relay in lockstep.
    const delay = reconnectDelayMs(this.reconnectAttempt, this.rand)
    this.reconnectAttempt++
    // G4: expose the real next-retry time so the readiness model can show an honest countdown. This does NOT
    // change the retry algorithm — `delay` is the same backoff that already drove the setTimeout.
    this.update({
      error: `reconnecting… (attempt ${this.reconnectAttempt})`,
      nextRetryAtMs: Date.now() + delay,
    })
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      void this.doReconnect('auto')
    }, delay)
  }

  private async doReconnect(trigger: 'manual' | 'auto' | 'online' | 'visible'): Promise<void> {
    if (this.stopReconnect) return
    const target = this.view.selectedDevice
    if (!target) return
    // G5: mark the manual/auto reconnect as actually in flight (button shows "Reconnecting…", disabled to
    // avoid a double-call). Cleared in finally so a failure that returns to offline re-enables the button.
    this.update({ reconnectingNow: true })
    try {
      await this.connectTo(target, { trigger }) // fresh signaling + bound token + auth, then list sessions
    } finally {
      this.update({ reconnectingNow: false })
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  /** Arm one owner-scoped progress deadline. A new connect aborts all requests owned by the previous scope. */
  private armConnectWatchdog(connectionGen = this.connectionGeneration): void {
    this.clearConnectWatchdog()
    let deadline!: ProgressDeadline
    deadline = new ProgressDeadline({
      inactivityMs: CONNECT_WATCHDOG_MS,
      absoluteMs: CONNECT_ABSOLUTE_WATCHDOG_MS,
      onExpire: () => {
        // Expiry aborts the scope before this callback. A bridge may synchronously publish `offline`; both paths
        // are generation-gated and scheduleReconnect de-duplicates the resulting backoff.
        if (this.connectDeadline?.deadline === deadline) this.connectDeadline = null
        this.onConnectWatchdog(connectionGen)
      },
    })
    this.connectDeadline = { generation: connectionGen, deadline }
  }

  private noteConnectProgress(stage: string, connectionGen = this.connectionGeneration): void {
    const owner = this.connectDeadline
    if (owner?.generation === connectionGen) owner.deadline.progress(stage)
  }

  /** Diagnostics are periodic snapshots. Only first observation of a real state transition is progress; unchanged
   * poll snapshots and timing ticks cannot keep an attempt alive. ProgressDeadline enforces uniqueness again. */
  private noteConnectDiagnostics(connectionGen: number, diagnostics: Diagnostics): void {
    if (diagnostics.signaling !== 'idle' && diagnostics.signaling !== 'dead') {
      this.noteConnectProgress(`bridge:signaling:${diagnostics.signaling}`, connectionGen)
    }
    if (diagnostics.ice !== 'new' && diagnostics.ice !== 'failed' && diagnostics.ice !== 'closed') {
      // The production bridge records this same canonical key at the source. Re-observing its diagnostic snapshot
      // therefore cannot buy a second inactivity window; fake/alternate transports can still report real progress.
      this.noteConnectProgress(`bridge:ice:${diagnostics.ice}`, connectionGen)
    }
    if (diagnostics.timing.toFirstRelayMs !== null) {
      this.noteConnectProgress('bridge:first-relay-candidate', connectionGen)
    }
  }

  /** Supersession/intentional leave: cancel the timer and abort every request carrying the old owner signal. */
  private clearConnectWatchdog(): void {
    const owner = this.connectDeadline
    this.connectDeadline = null
    owner?.deadline.abort()
  }

  /** Success or a transport-owned terminal result: disarm without recursively aborting the bridge callback that
   * is currently reporting that result. */
  private completeConnectWatchdog(): void {
    const owner = this.connectDeadline
    this.connectDeadline = null
    owner?.deadline.complete()
  }

  /** Guard the post-auth session_list wait (the "Loading its projects…" phase). If session_list doesn't arrive, we
   * re-request ONCE, then fall back to offline + the normal bounded reconnect — never hang on "Loading…" forever. */
  private armSessionListWatchdog(connectionGen = this.connectionGeneration): void {
    this.clearSessionListWatchdog()
    const timer = setTimeout(() => {
      if (this.sessionListWatchdog === timer) this.sessionListWatchdog = null
      if (this.connectionGeneration !== connectionGen) return
      // Only act if we're still waiting (phase hasn't advanced past connecting and no list has arrived).
      if (this.view.phase !== 'connecting' || this.view.lastSessionListAtMs !== undefined) return
      if (!this.sessionListRetried && this.session?.isAuthenticated) {
        this.sessionListRetried = true
        connTrace.log(this.traceId, 'session_list', 'retry', 'warn', 'no reply — re-requesting once')
        this.session.listSessions() // one more try — the first request may have been dropped mid-handshake
        this.armSessionListWatchdog(connectionGen)
        return
      }
      // Give up on this attempt: drop to offline so the bounded reconnect loop starts fresh signaling and mints a
      // new session-bound token instead of sitting on a dead "Loading…" screen.
      connTrace.log(this.traceId, 'session_list', 'timeout', 'error', 'no session_list after auth → offline+retry')
      this.update({ phase: 'offline', error: 'the desktop did not send its session list', nextRetryAtMs: undefined })
      this.scheduleReconnect()
    }, SESSION_LIST_WATCHDOG_MS)
    this.sessionListWatchdog = timer
  }

  private clearSessionListWatchdog(): void {
    if (this.sessionListWatchdog) {
      clearTimeout(this.sessionListWatchdog)
      this.sessionListWatchdog = null
    }
  }

  /** Arm a per-session attach watchdog. Replaces any previous timer for that session. */
  private sendAttachRequest(sessionId: string, cols: number, rows: number): void {
    const session = this.session
    if (!session?.isAuthenticated) return
    this.abandonedPendingAttaches.delete(sessionId)
    this.pendingWireAttaches.add(sessionId)
    const viewed = activeLeaf(this.view.paneLayout).sessionId === sessionId
    this.attachRequestSeq += 1
    const requestId = `attach-${this.connectionGeneration}-${this.attachRequestSeq}`
    session.attach(sessionId, cols, rows, this.rendererMode === 'xterm', requestId, viewed)
  }

  /** Reclaim a still-in-flight request after the user explicitly returns to the same pane. The original
   * attach_session remains authoritative; re-sending before its attach_ok would be rejected as already_attached.
   * Re-arm only the local materialization watchdog and adopt the original reply when it lands. */
  private reclaimPendingAttach(sessionId: string): boolean {
    if (!this.pendingWireAttaches.has(sessionId)) return false
    this.abandonedPendingAttaches.delete(sessionId)
    if (!this.attachWatchdogs.has(sessionId)) this.armAttachWatchdog(sessionId)
    return true
  }

  private armAttachWatchdog(sessionId: string): void {
    this.clearAttachWatchdog(sessionId)
    const connectionGen = this.connectionGeneration
    const timer = setTimeout(() => {
      this.onAttachWatchdog(sessionId, connectionGen, timer)
    }, ATTACH_WATCHDOG_MS)
    this.attachWatchdogs.set(sessionId, timer)
  }

  private beginPaneSwitch(sessionId: string): void {
    if (this.view.phase === 'terminal' || this.view.phase === 'sessions') {
      this.update({ phase: 'terminal', attachedSession: sessionId, desktopActionMessage: null })
    }
    this.clearPaneSwitchWatchdog()
    const connectionGen = this.connectionGeneration
    const timer = setTimeout(() => {
      this.onPaneSwitchWatchdog(sessionId, connectionGen, timer)
    }, PANE_SWITCH_REFRESH_MS)
    this.paneSwitchWatchdog = { sessionId, connectionGen, timer }
  }

  private clearPaneSwitchWatchdog(sessionId?: string): void {
    if (!this.paneSwitchWatchdog) return
    if (sessionId !== undefined && this.paneSwitchWatchdog.sessionId !== sessionId) return
    clearTimeout(this.paneSwitchWatchdog.timer)
    this.paneSwitchWatchdog = null
  }

  private onPaneSwitchWatchdog(
    sessionId: string,
    connectionGen = this.connectionGeneration,
    timer?: ReturnType<typeof setTimeout>,
  ): void {
    if (this.connectionGeneration !== connectionGen) return
    if (this.paneSwitchWatchdog?.sessionId !== sessionId) return
    if (this.paneSwitchWatchdog.connectionGen !== connectionGen) return
    if (timer !== undefined && this.paneSwitchWatchdog.timer !== timer) return
    this.clearPaneSwitchWatchdog(sessionId)
    if (this.view.attachedSession !== sessionId) return
    if (this.multiAttach.channelForSession(sessionId) !== null) return
    connTrace.log(this.traceId, 'pane_switch', 'refresh', 'warn', 'attach still pending after click')
    this.update({ desktopActionMessage: 'Refreshing pane state…' })
    this.session?.listSessions()
  }

  private clearAttachWatchdog(sessionId: string): void {
    const timer = this.attachWatchdogs.get(sessionId)
    if (!timer) return
    clearTimeout(timer)
    this.attachWatchdogs.delete(sessionId)
  }

  private clearAttachWatchdogs(): void {
    for (const timer of this.attachWatchdogs.values()) clearTimeout(timer)
    this.attachWatchdogs.clear()
  }

  /** Arm the creatingSession watchdog (armed/disarmed centrally by update() on the flag's flips). */
  private armCreatingWatchdog(): void {
    this.clearCreatingWatchdog()
    this.creatingWatchdog = setTimeout(() => {
      this.creatingWatchdog = null
      this.onCreatingWatchdog()
    }, CREATING_WATCHDOG_MS)
  }

  private clearCreatingWatchdog(): void {
    if (this.creatingWatchdog) {
      clearTimeout(this.creatingWatchdog)
      this.creatingWatchdog = null
    }
  }

  /** A desktop-authoritative mutation got NO ok/error reply in time. Unwedge the creation UI (clear the busy
   * flag every create/split/rename/… path guards on) and say so honestly. Also undoes a pending split's empty
   * browser tile — with no reply coming, nothing will ever fill it. Public for deterministic tests; a no-op
   * unless the flag is still set (a reply that raced the timer already cleared+disarmed it). */
  onCreatingWatchdog(): void {
    if (!this.view.creatingSession) return
    const abandoned = this.abandonRemoteCreations()
    for (const attempt of abandoned) this.rollbackPendingSplitPane(attempt.splitPaneId)
    this.update({
      creatingSession: false,
      terminalAcquisition: null,
      desktopActionMessage: 'The desktop did not reply — check the connection and try again.',
    })
    this.scheduleStartupHydrationOrHistory()
  }

  /** The connect didn't reach auth within the window. If we're still stuck in `connecting`, surface an
   * actionable error and fall into the bounded reconnect loop so the user isn't stranded at "Connecting…".
   * Public for deterministic testing (the timer just calls this); a no-op unless still `connecting`. */
  onConnectWatchdog(connectionGen = this.connectionGeneration): void {
    if (this.connectionGeneration !== connectionGen) return
    if (this.view.phase !== 'connecting') return // already progressed or left — nothing to do
    if (this.view.authState === 'authenticated') return // auth succeeded (sessions still arriving) — not a stall
    this.finishConnectionMetric(connectionGen, 'network_failure')
    this.update({
      phase: 'offline',
      connectionMode: 'unknown',
      error: "couldn't reach this desktop (it may be offline or unreachable) — retrying…",
    })
    this.scheduleReconnect()
  }

  /** A requested attach did not produce terminal data in time. Public for deterministic tests; the timer just
   * calls this. Keeps the desktop connection alive and returns to the sessions surface with a retryable,
   * content-blind error instead of leaving a blank terminal/pane. */
  onAttachWatchdog(
    sessionId: string,
    connectionGen = this.connectionGeneration,
    timer?: ReturnType<typeof setTimeout>,
  ): void {
    if (this.connectionGeneration !== connectionGen) return
    // A same-connection re-attach can replace the timer for this session. An already-queued older callback must
    // not consume the replacement's watchdog entry.
    if (timer !== undefined && this.attachWatchdogs.get(sessionId) !== timer) return
    if (!this.attachWatchdogs.has(sessionId)) return // already materialized/cleared or never armed
    this.clearAttachWatchdog(sessionId)
    const placed = leaves(this.view.paneLayout.root).some((leaf) => leaf.sessionId === sessionId)
    const boundedBackgroundFailure =
      this.backgroundAttachInFlight === sessionId && activeLeaf(this.view.paneLayout).sessionId !== sessionId
    if (boundedBackgroundFailure) {
      this.backgroundAttachInFlight = null
      this.backgroundHydrationSkipped.add(sessionId)
      if (this.pendingWireAttaches.has(sessionId)) {
        this.abandonedPendingAttaches.add(sessionId)
      } else if (this.multiAttach.isAttached(sessionId)) {
        this.detachSessionChannel(sessionId)
      } else {
        this.clearAttachLifecycle(sessionId, true)
      }
      this.schedulePaneHydration()
      return
    }
    if (this.intentionalDetachGeneration === this.connectionGeneration || !placed) {
      // The acquisition was abandoned locally. It must neither retry nor send a detach before attach_ok proves
      // the agent created a channel. A late attach_ok is handled by the pre-commit shouldAcceptAttach gate.
      this.clearAttachLifecycle(sessionId, true)
      this.settleTerminalAcquisitionIfIdle()
      this.flushDeferredAgentSessionRefresh()
      return
    }
    if (this.pendingWireAttaches.has(sessionId)) {
      // No attach_ok means there is still no confirmed channel to detach. Retrying attach_session here can race
      // the original request and produce already_attached/not_attached errors. Quarantine the original request,
      // surface the retryable state, and let its eventual attach_ok drain through shouldAcceptAttach. A later
      // explicit same-session attach can reclaim this request without duplicating it.
      this.abandonedPendingAttaches.add(sessionId)
      this.cancelWinsizeSettleRepush(sessionId, true)
      this.attachAutoRetried.delete(sessionId)
      if (this.view.attachedSession === sessionId) this.update({ phase: 'sessions', attachedSession: null })
      this.update({ error: "couldn't open this session — try again", recentSessionEnded: false })
      this.settleTerminalAcquisitionIfIdle()
      this.flushDeferredAgentSessionRefresh()
      return
    }
    if (!this.view.sessions.includes(sessionId)) {
      // A fresh list can prove the target ended while its attach was in flight. Clearing this watchdog removes
      // the final pending acquisition owner; settle now instead of leaving the passive Loading surface forever.
      this.cancelWinsizeSettleRepush(sessionId, true)
      this.attachAutoRetried.delete(sessionId)
      this.settleTerminalAcquisitionIfIdle()
      this.flushDeferredAgentSessionRefresh()
      return
    }
    // AUTOMATIC RECOVERY (one shot): attach_ok without any terminal data usually means the agent's daemon
    // leg dropped the attach or the restore grid (its backend attach is fire-and-forget — attach_ok can be
    // sent even when the daemon never delivered). A fresh detach+attach makes the daemon resend the restore
    // grid. Retry ONCE before surfacing the error; the pane placement + canvas stay (no phase bounce), so a
    // successful retry paints in place — the live "created pane stays an empty shell until refresh" case.
    if (!this.attachAutoRetried.has(sessionId)) {
      this.attachAutoRetried.add(sessionId)
      this.reattachSessionFresh(sessionId)
      return
    }
    this.attachAutoRetried.delete(sessionId) // a later manual retry gets its own automatic recovery again
    this.cancelWinsizeSettleRepush(sessionId, true)
    if (this.multiAttach.isAttached(sessionId)) {
      const active = this.view.attachedSession === sessionId
      const channel = this.multiAttach.channelForSession(sessionId)
      this.session?.detachSession(sessionId)
      this.multiAttach.detachSession(sessionId)
      if (channel !== null) this.multiPaneTerminal.detachPane(channel)
      if (active) this.update({ phase: 'sessions', attachedSession: null })
    }
    this.update({
      error: "couldn't open this session — try again",
      recentSessionEnded: false,
    })
    this.settleTerminalAcquisitionIfIdle()
    this.flushDeferredAgentSessionRefresh()
  }

  /** Persist the non-secret reconnect hints (no token). */
  private persistHints(): void {
    const acct = this.view.accountId
    const desk = this.view.selectedDevice
    if (!acct || !desk) return
    saveHints({ accountId: acct, desktopDeviceId: desk, sessionId: this.resumeSessionId, renderer: this.rendererMode })
  }

  /** Persist the remote's per-window pane arrangement (split trees + per-pane session ids for EVERY window) so a fresh
   * connect from ANY browser reopens the same workspace. Durable via the cloud (debounced ~1s in the dep). The active
   * window's live mirror is folded into the map first so an in-flight edit isn't lost. Content-blind (layout shape +
   * session ids only); best-effort (no-op without a device or the cloud dep). */
  private persistLastLayout(): void {
    const desk = this.view.selectedDevice
    if (!desk || !this.deps.remoteLayout) return
    // Slice 1 (S2-R1, invariant 4): NEVER persist before the cloud-restore continuation hydrated the map. The early
    // attach on refresh (resumePanes → attach → here) used to run with activeWindowId null + an empty map and PUT
    // "{}" over the durable row — the layout wipe behind the refresh-restore nondeterminism.
    if (!this.layoutHydrated) return
    const map = { ...(this.view.paneLayoutsByWindow ?? {}) }
    if (this.view.activeWindowId) map[this.view.activeWindowId] = this.workspacePanes()
    // R7/R8: a landing-PENDING window holds nothing user-built (by definition — any user action burns the
    // designation). Persisting its row would mark it KNOWN on the next refresh (the restore derives known ids
    // from the row) and silently burn the R7 landing mid-creation. Skip it; it re-derives as unknown → still
    // landing-eligible after a refresh (lifecycle: `landing-pending` survives refresh by re-derivation).
    for (const id of this.pendingLandingWindows) delete map[id]
    // Serialize the whole per-window map + the active window + the R13 known-id ledger in one v3 row
    // (matches the debounced single PUT). The ledger is already R14-pruned to existing entities.
    this.deps.remoteLayout.putLayout(desk, serializeRemoteLayout(this.view.activeWindowId ?? null, map, {
      projects: [...this.knownProjectIds],
      windows: [...this.knownWindowIds],
      panes: [...this.knownPaneIds],
    }))
  }

  private loadLabelsFor(desktopDeviceId: string): Record<string, string> {
    const acct = this.view.accountId
    return acct ? loadSessionLabels(acct, desktopDeviceId) : {}
  }

  private saveLabelsForCurrentDesktop(labels: Record<string, string>): void {
    const acct = this.view.accountId
    const desk = this.view.selectedDevice
    if (!acct || !desk) return
    saveSessionLabels(acct, desk, labels)
  }

  private loadFavoritesFor(desktopDeviceId: string): string[] {
    const acct = this.view.accountId
    return acct ? loadFavoriteSessions(acct, desktopDeviceId) : []
  }

  private saveFavoritesForCurrentDesktop(favorites: readonly string[]): void {
    const acct = this.view.accountId
    const desk = this.view.selectedDevice
    if (!acct || !desk) return
    saveFavoriteSessions(acct, desk, favorites)
  }

  private loadOrderFor(desktopDeviceId: string): string[] {
    const acct = this.view.accountId
    return acct ? loadSessionOrder(acct, desktopDeviceId) : []
  }

  private saveOrderForCurrentDesktop(order: readonly string[]): void {
    const acct = this.view.accountId
    const desk = this.view.selectedDevice
    if (!acct || !desk) return
    saveSessionOrder(acct, desk, order)
  }

  private loadHiddenFor(desktopDeviceId: string): string[] {
    const acct = this.view.accountId
    return acct ? loadHiddenSessions(acct, desktopDeviceId) : []
  }

  private saveHiddenForCurrentDesktop(hidden: readonly string[]): void {
    const acct = this.view.accountId
    const desk = this.view.selectedDevice
    if (!acct || !desk) return
    saveHiddenSessions(acct, desk, hidden)
  }

  private loadKnownSessionsForDevices(accountId: string, devices: readonly DesktopDevice[]): Record<string, string[]> {
    const out: Record<string, string[]> = {}
    for (const d of devices) {
      if (d.revoked) continue
      const sessions = loadKnownSessions(accountId, d.deviceId)
      if (sessions.length > 0) out[d.deviceId] = sessions
    }
    return out
  }

  private saveKnownSessionsFor(desktopDeviceId: string, sessions: readonly string[]): Record<string, string[]> {
    const acct = this.view.accountId
    if (!acct) return this.view.knownSessionsByDevice
    saveKnownSessions(acct, desktopDeviceId, sessions)
    const next = { ...this.view.knownSessionsByDevice }
    if (sessions.length > 0) next[desktopDeviceId] = [...sessions]
    else delete next[desktopDeviceId]
    return next
  }

  private loadLastOpenedFor(desktopDeviceId: string): string | null {
    const acct = this.view.accountId
    return acct ? loadLastOpenedSession(acct, desktopDeviceId) : null
  }

  private saveLastOpenedForCurrentDesktop(sessionId: string | null): void {
    const acct = this.view.accountId
    const desk = this.view.selectedDevice
    if (!acct || !desk) return
    saveLastOpenedSession(acct, desk, sessionId)
  }

  private commitLayoutPresetState(layoutPresetState: LayoutPresetState): void {
    if (layoutPresetState === this.view.layoutPresetState) return
    const acct = this.view.accountId
    if (!acct) return
    this.update({ layoutPresetState })
    saveLayoutPresetState(acct, layoutPresetState)
  }

  private nextLayoutPresetId(nowMs: number): string {
    this.layoutPresetIdSeq += 1
    return `layout-${nowMs.toString(36)}-${this.layoutPresetIdSeq.toString(36)}`
  }

  private pruneLastOpenedFor(desktopDeviceId: string, sessions: readonly string[]): string | null {
    const last = this.loadLastOpenedFor(desktopDeviceId)
    if (!last || sessions.includes(last)) return last
    const acct = this.view.accountId
    if (acct) saveLastOpenedSession(acct, desktopDeviceId, null)
    return null
  }

  /** True when this list update drops a recent-session marker the USER currently sees because that session is no
   * longer listed (it ended on the desktop) — distinct from a marker that was never set. Drives a one-shot
   * "your recent session ended" notice so the reopen affordance doesn't just silently vanish. Content-blind. */
  private recentSessionJustEnded(sessions: readonly string[]): boolean {
    const shown = this.view.lastOpenedSessionId
    return shown !== null && !sessions.includes(shown)
  }

  private pruneFavoritesFor(desktopDeviceId: string, sessions: readonly string[]): string[] {
    const favorites = this.loadFavoritesFor(desktopDeviceId).filter((id) => sessions.includes(id))
    const acct = this.view.accountId
    if (acct) saveFavoriteSessions(acct, desktopDeviceId, favorites)
    return favorites
  }

  private pruneOrderFor(desktopDeviceId: string, sessions: readonly string[]): string[] {
    const order = this.loadOrderFor(desktopDeviceId).filter((id) => sessions.includes(id))
    const acct = this.view.accountId
    if (acct) saveSessionOrder(acct, desktopDeviceId, order)
    return order
  }

  private pruneHiddenFor(desktopDeviceId: string, sessions: readonly string[]): string[] {
    const hidden = this.loadHiddenFor(desktopDeviceId).filter((id) => sessions.includes(id))
    const acct = this.view.accountId
    if (acct) saveHiddenSessions(acct, desktopDeviceId, hidden)
    return hidden
  }

  disconnect(): void {
    // Revoke callback ownership before closing: transports may deliver `closed` synchronously and queued callbacks
    // after close. Intentional leave owns the state transition below; the retired peer must stay inert.
    this.finishActiveConnectionMetric('cancelled')
    this.connectionGeneration++
    this.stopReconnect = true
    this.clearReconnectTimer()
    this.clearConnectWatchdog()
    this.clearSessionListWatchdog()
    this.clearAttachWatchdogs()
    this.cancelWinsizeRefresh()
    this.cancelAllWinsizeSettleRepushes(true)
    this.cancelPaneHydrationState()
    this.stopDeviceRefresh() // leaving the device list (into a session / signed out) → stop polling it
    this.resumeSessionId = null
    this.multiAttach.clear()
    this.pendingWireAttaches.clear()
    this.abandonedPendingAttaches.clear()
    this.deferredAgentSessionRefresh = false
    this.deferredAgentSessionFolderRefreshes.clear()
    this.multiPaneOutputEnabled = false
    this.multiPaneTerminal = new MultiPaneTerminalSession()
    this.pendingSelfCreated = new Map()
    clearHints()
    const previousSession = this.session
    this.session = null
    previousSession?.close()
    const abandoned = this.abandonRemoteCreations()
    for (const attempt of abandoned) this.rollbackPendingSplitPane(attempt.splitPaneId)
    this.update({
      nextRetryAtMs: undefined,
      reconnectingNow: false,
      connectionMode: 'unknown',
      diagnostics: defaultDiagnostics(),
      agentBuildGit: null,
      desktopAccess: UNKNOWN_DESKTOP_ACCESS,
      creatingSession: false,
      createSessionError: null,
      desktopActionMessage: null,
      terminalAcquisition: null,
    }) // G4/G5: leaving the flow → clear retry UI
  }
}
