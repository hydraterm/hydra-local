// Multi-attach state manager (roadmap §4). Today RemoteSession tracks ONE attachedSessionId/attachedChannel,
// so only one session can be attached at a time. ?panes=1 needs N concurrent attaches. This is the pure state
// model for that: it records every attached (sessionId ↔ channel) binding from multiple `attach_ok` results
// and tracks which session is ACTIVE (the input/resize target — keystrokes go to exactly one pane). Inbound
// terminal output is demuxed separately by ChannelRouter/MultiPaneTerminalSession, so EVERY attached channel
// keeps painting; only input is active-scoped. Pure + transport-free: the controller maps these to real
// attach/detach/resize sends. The default single-session path does not use this.

export interface AttachBinding {
  readonly sessionId: string
  readonly channel: number
}

export class MultiAttachManager {
  private bySession = new Map<string, number>() // sessionId → channel
  private byChannel = new Map<number, string>() // channel → sessionId
  private active: string | null = null // the input/resize target session

  /** Record an attach (from `attach_ok`). The newly-attached session becomes active (keystrokes follow the
   * just-opened pane). Re-attaching a session updates its channel. */
  onAttached(sessionId: string, channel: number): void {
    const prevChannel = this.bySession.get(sessionId)
    if (prevChannel !== undefined && prevChannel !== channel) this.byChannel.delete(prevChannel)
    this.bySession.set(sessionId, channel)
    this.byChannel.set(channel, sessionId)
    this.active = sessionId
  }

  /** Drop a binding by session id (a pane closed / its session detached). If it was active, focus falls to
   * the most-recently-remaining session (or null when none remain). */
  detachSession(sessionId: string): void {
    const channel = this.bySession.get(sessionId)
    if (channel === undefined) return
    this.bySession.delete(sessionId)
    this.byChannel.delete(channel)
    if (this.active === sessionId) {
      const remaining = [...this.bySession.keys()]
      this.active = remaining.length ? remaining[remaining.length - 1] : null
    }
  }

  /** Make an already-attached session the input/resize target. No-op for an unattached session. */
  setActive(sessionId: string): void {
    if (this.bySession.has(sessionId)) this.active = sessionId
  }

  /** The session that currently receives input/resize, or null when nothing is attached. */
  activeSession(): string | null {
    return this.active
  }

  /** The channel that currently receives input/resize, or null. */
  activeChannel(): number | null {
    return this.active !== null ? (this.bySession.get(this.active) ?? null) : null
  }

  channelForSession(sessionId: string): number | null {
    return this.bySession.get(sessionId) ?? null
  }

  sessionForChannel(channel: number): string | null {
    return this.byChannel.get(channel) ?? null
  }

  isAttached(sessionId: string): boolean {
    return this.bySession.has(sessionId)
  }

  get attachedCount(): number {
    return this.bySession.size
  }

  bindings(): AttachBinding[] {
    return [...this.bySession].map(([sessionId, channel]) => ({ sessionId, channel }))
  }

  clear(): void {
    this.bySession.clear()
    this.byChannel.clear()
    this.active = null
  }
}
