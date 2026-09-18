import { describe, it, expect } from 'vitest'
import {
  buildCloseWindow,
  buildCreateSession,
  buildFocusWindow,
  buildListAgentSessions,
  buildListDirectories,
  buildManageAgentSession,
  buildNewPane,
  buildNewWindow,
  buildPreviewAgentSession,
  buildProjectCreate,
  buildProjectDelete,
  buildProjectUpdate,
  buildRename,
  buildRemovePane,
  buildRevivePane,
  buildSplitPane,
  buildStartPaneSession,
  buildStashPane,
  normalizeProviderSessionId,
  parseAgentSessionPreviewReply,
  parseAgentSessionManageReply,
  parseAgentSessionsResult,
  parseCloseWindowReply,
  parseCreateSessionReply,
  parseDesktopAccessStatus,
  parseDirectoriesReply,
  parseDirectoriesResult,
  parseFocusWindowReply,
  parseNewWindowReply,
  parseProjectEditReply,
  parseRenameReply,
  parseRevivePaneReply,
  parseRemovePaneReply,
  parseSplitPaneReply,
  parseStashPaneReply,
  type AgentSessionManageReply,
  type AgentSessionsResultMsg,
  type AgentSessionPreviewMsg,
  type SessionCreatedMsg,
  type SessionCreateErrorMsg,
} from './control-messages'

describe('control-messages — create_session', () => {
  it('builds a create_session request with the given request_id', () => {
    expect(buildCreateSession('c1')).toEqual({ type: 'create_session', request_id: 'c1' })
  })

  it('parses a session_created reply', () => {
    const r = parseCreateSessionReply({ type: 'session_created', request_id: 'c1', session_id: 's-abc' })
    expect(r).toEqual({ type: 'session_created', request_id: 'c1', session_id: 's-abc' } satisfies SessionCreatedMsg)
  })

  it('parses a session_create_error reply with a known code', () => {
    const r = parseCreateSessionReply({ type: 'session_create_error', request_id: 'c1', code: 'revoked', message: 'device revoked' })
    expect(r).toEqual({ type: 'session_create_error', request_id: 'c1', code: 'revoked', message: 'device revoked' } satisfies SessionCreateErrorMsg)
  })

  it('preserves the fail-closed unsupported-provider code', () => {
    const r = parseCreateSessionReply({
      type: 'session_create_error',
      request_id: 'c1',
      code: 'unsupported_provider',
      message: 'unsupported agent provider',
    })
    expect(r).toEqual({
      type: 'session_create_error',
      request_id: 'c1',
      code: 'unsupported_provider',
      message: 'unsupported agent provider',
    } satisfies SessionCreateErrorMsg)
  })

  it('coerces an unknown error code to "internal" (defensive)', () => {
    const r = parseCreateSessionReply({ type: 'session_create_error', request_id: 'c1', code: 'weird', message: 'x' })
    expect((r as SessionCreateErrorMsg).code).toBe('internal')
  })

  it('returns null for non-create-session messages (so other handlers run)', () => {
    expect(parseCreateSessionReply({ type: 'attach_ok', request_id: 'a', session_id: 's1' })).toBeNull()
    expect(parseCreateSessionReply({ type: 'list_result', request_id: 'r', items: [] })).toBeNull()
  })

  it('returns null for malformed payloads (missing/!string fields)', () => {
    expect(parseCreateSessionReply({ type: 'session_created', request_id: 'c1' })).toBeNull() // no session_id
    expect(parseCreateSessionReply({ type: 'session_created', request_id: 1, session_id: 's' })).toBeNull()
    expect(parseCreateSessionReply(null)).toBeNull()
    expect(parseCreateSessionReply('nope')).toBeNull()
  })

  it('carries NO terminal payload — only ids/codes/short message', () => {
    const built = JSON.stringify(buildCreateSession('c1')).toLowerCase()
    for (const bad of ['stdout', 'pty', 'data', 'output', 'token', 'secret']) {
      expect(built).not.toContain(bad)
    }
  })
})

describe('control-messages — creation geometry', () => {
  const geometry = { cols: 132, rows: 41 }

  it('emits one exact paired cols/rows geometry on every session-creating request', () => {
    expect(buildCreateSession('c-geometry', geometry)).toEqual({
      type: 'create_session',
      request_id: 'c-geometry',
      cols: 132,
      rows: 41,
    })
    expect(buildSplitPane('s-geometry', 'win-1', 'pane-1', 'right', geometry)).toEqual({
      type: 'split_pane',
      request_id: 's-geometry',
      window_id: 'win-1',
      from_pane_id: 'pane-1',
      dir: 'right',
      cols: 132,
      rows: 41,
    })
    expect(buildNewPane('np-geometry', 'win-1', 'pane-1', geometry)).toEqual({
      type: 'new_pane',
      request_id: 'np-geometry',
      window_id: 'win-1',
      from_pane_id: 'pane-1',
      cols: 132,
      rows: 41,
    })
    expect(buildRevivePane('r-geometry', 'win-1', 'pane-1', geometry)).toEqual({
      type: 'revive_pane',
      request_id: 'r-geometry',
      window_id: 'win-1',
      pane_id: 'pane-1',
      cols: 132,
      rows: 41,
    })
    expect(buildStartPaneSession('st-geometry', 'win-1', 'pane-1', geometry)).toEqual({
      type: 'start_pane_session',
      request_id: 'st-geometry',
      window_id: 'win-1',
      pane_id: 'pane-1',
      cols: 132,
      rows: 41,
    })
    expect(buildNewWindow('nw-geometry', 'project-1', 'Window', geometry)).toEqual({
      type: 'new_window',
      request_id: 'nw-geometry',
      project_id: 'project-1',
      name: 'Window',
      cols: 132,
      rows: 41,
    })
    expect(buildProjectCreate('p-geometry', { name: 'Project', root: '/work', ...geometry })).toEqual({
      type: 'project_create',
      request_id: 'p-geometry',
      name: 'Project',
      root: '/work',
      cols: 132,
      rows: 41,
    })
  })

  it('preserves every legacy builder shape by omitting geometry when no pair is supplied', () => {
    const legacyMessages = [
      buildCreateSession('c-legacy'),
      buildSplitPane('s-legacy', 'win-1', 'pane-1', 'right'),
      buildNewPane('np-legacy', 'win-1', 'pane-1'),
      buildRevivePane('r-legacy', 'win-1', 'pane-1'),
      buildStartPaneSession('st-legacy', 'win-1', 'pane-1'),
      buildNewWindow('nw-legacy', 'project-1', 'Window'),
      buildProjectCreate('p-legacy', { name: 'Project', root: '/work' }),
    ]
    for (const msg of legacyMessages) {
      expect(msg).not.toHaveProperty('cols')
      expect(msg).not.toHaveProperty('rows')
    }
  })

  it.each([
    [{ cols: 80 }, 'unpaired cols'],
    [{ rows: 24 }, 'unpaired rows'],
    [{ cols: 0, rows: 24 }, 'zero'],
    [{ cols: 1, rows: 24 }, 'below viewport bound'],
    [{ cols: 80, rows: -1 }, 'negative'],
    [{ cols: 80.5, rows: 24 }, 'fractional'],
    [{ cols: Number.NaN, rows: 24 }, 'NaN'],
    [{ cols: 80, rows: Number.POSITIVE_INFINITY }, 'infinite'],
    [{ cols: 251, rows: 24 }, 'over column bound'],
    [{ cols: 80, rows: 101 }, 'over row bound'],
  ] as const)('omits both dimensions for %s (%s)', (invalid, _label) => {
    const messages = [
      buildCreateSession('c-invalid', invalid),
      buildSplitPane('s-invalid', 'win-1', 'pane-1', 'right', invalid),
      buildNewPane('np-invalid', 'win-1', 'pane-1', invalid),
      buildRevivePane('r-invalid', 'win-1', 'pane-1', invalid),
      buildStartPaneSession('st-invalid', 'win-1', 'pane-1', invalid),
      buildNewWindow('nw-invalid', 'project-1', 'Window', invalid),
      buildProjectCreate('p-invalid', { name: 'Project', root: '/work', ...invalid }),
    ]
    for (const msg of messages) {
      expect(msg).not.toHaveProperty('cols')
      expect(msg).not.toHaveProperty('rows')
    }
  })
})

describe('control-messages — project create/update (desktop project-form parity)', () => {
  it('builds project_create with name/root/icon/accent/agent', () => {
    expect(buildProjectCreate('p1', {
      name: ' Hydra ',
      root: ' /Users/test/home/Desktop/project-example ',
      icon: ' KP ',
      accentColor: ' #34d399 ',
      agent: 'codex',
      resumeMode: 'resume',
      model: ' gpt-5 ',
      dangerouslySkipPermissions: true,
      customCommand: ' claude --foo ',
      directories: [{ name: ' api ', path: ' /Users/test/home/api ' }, { name: 'empty', path: '   ' }],
    })).toEqual({
      type: 'project_create',
      request_id: 'p1',
      name: 'Hydra',
      root: '/Users/test/home/Desktop/project-example',
      icon: 'KP',
      accent_color: '#34d399',
      agent: 'codex',
      resume_mode: 'resume',
      model: 'gpt-5',
      dangerous: true,
      custom_command: 'claude --foo',
      directories: [{ name: 'api', path: '/Users/test/home/api' }],
    })
  })

  it('builds project_update with only supplied fields', () => {
    expect(buildProjectUpdate('p2', 'proj-hydra', {
      name: 'Hydra 2',
      accentColor: '#60a5fa',
      resumeMode: 'continue',
      model: 'claude-opus-4-8',
      dangerouslySkipPermissions: false,
      customCommand: '',
      directories: [],
    })).toEqual({
      type: 'project_update',
      request_id: 'p2',
      project_id: 'proj-hydra',
      name: 'Hydra 2',
      accent_color: '#60a5fa',
      resume_mode: 'continue',
      model: 'claude-opus-4-8',
      dangerous: false,
      custom_command: '',
      directories: [],
    })
  })

  it('carries the New Project resume TARGET (resume_session_id) and the desktop none policy', () => {
    expect(buildProjectCreate('p4', {
      name: 'Api',
      root: '/Users/test/home/api',
      resumeMode: 'resume',
      resumeSessionId: ' cl-9 ',
    })).toEqual({
      type: 'project_create',
      request_id: 'p4',
      name: 'Api',
      root: '/Users/test/home/api',
      resume_mode: 'resume',
      resume_session_id: 'cl-9',
    })
    // 'none' is desktop vocabulary — sent as-is; blank session ids are dropped.
    expect(buildProjectCreate('p5', { name: 'F', root: '/f', resumeMode: 'none', resumeSessionId: '  ' })).toEqual({
      type: 'project_create',
      request_id: 'p5',
      name: 'F',
      root: '/f',
      resume_mode: 'none',
    })
  })

  it("normalizes the legacy 'new' fresh policy to the desktop 'none' in BOTH builders", () => {
    expect(buildProjectCreate('p6', { name: 'L', root: '/l', resumeMode: 'new' }).resume_mode).toBe('none')
    expect(buildProjectUpdate('p7', 'proj-l', { resumeMode: 'new' }).resume_mode).toBe('none')
  })

  it('builds delete_project with the desktop project id', () => {
    expect(buildProjectDelete('p3', 'proj-hydra')).toEqual({
      type: 'delete_project',
      request_id: 'p3',
      project_id: 'proj-hydra',
    })
  })

  it('parses project_edit_ok / project_edit_error', () => {
    expect(parseProjectEditReply({ type: 'project_edit_ok', request_id: 'p1', project_id: 'proj-hydra' }))
      .toEqual({ type: 'project_edit_ok', request_id: 'p1', project_id: 'proj-hydra' })
    expect(parseProjectEditReply({ type: 'project_edit_error', request_id: 'p1', code: 'invalid_root', message: 'missing' }))
      .toEqual({ type: 'project_edit_error', request_id: 'p1', code: 'invalid_root', message: 'missing' })
    expect(parseProjectEditReply({ type: 'new_window_ok', request_id: 'n1', window_id: 'w', session_id: 's' })).toBeNull()
  })

  it('project_edit_ok passes the CREATE-seeded session_id through (auto-attach), tolerating absent/malformed ones', () => {
    // A project CREATE echoes the seeded pane's session id → parsed for the browser's auto-attach.
    expect(parseProjectEditReply({ type: 'project_edit_ok', request_id: 'p1', project_id: 'proj-x', session_id: 's-seed' }))
      .toEqual({ type: 'project_edit_ok', request_id: 'p1', project_id: 'proj-x', session_id: 's-seed' })
    // Updates / older agents omit it — the parsed reply carries NO session_id key (backward compatible).
    expect(parseProjectEditReply({ type: 'project_edit_ok', request_id: 'p2', project_id: 'proj-x' }))
      .not.toHaveProperty('session_id')
    // Defensive: a non-string / empty session_id is treated as absent, never crashes the parse.
    expect(parseProjectEditReply({ type: 'project_edit_ok', request_id: 'p3', project_id: 'proj-x', session_id: 42 }))
      .not.toHaveProperty('session_id')
    expect(parseProjectEditReply({ type: 'project_edit_ok', request_id: 'p4', project_id: 'proj-x', session_id: '' }))
      .not.toHaveProperty('session_id')
  })
})

describe('control-messages — agent session list (gap-doc Step 2a)', () => {
  it('builds a content-blind list_agent_sessions request', () => {
    expect(buildListAgentSessions('hist:codex', 'codex', ' /Users/test/home/app ')).toEqual({
      type: 'list_agent_sessions',
      request_id: 'hist:codex',
      agent: 'codex',
      cwd: '/Users/test/home/app',
    })
    expect(buildListAgentSessions('hist:claude', 'claude')).toEqual({
      type: 'list_agent_sessions',
      request_id: 'hist:claude',
      agent: 'claude',
    })
  })

  it('parses agent_sessions_result metadata without preview text', () => {
    const r = parseAgentSessionsResult({
      type: 'agent_sessions_result',
      request_id: 'hist:claude',
      sessions: [
        { id: 'abc', agent: 'claude', modified_at_ms: 1234, message_count: 7, in_use: true, first_message: 'secret' },
        { id: 'cop', agent: 'copilot', modified_at_ms: 2345, message_count: 8 },
        { id: 'agy', agent: 'antigravity', modified_at_ms: 3456, message_count: 9 },
        { id: 'kimi', agent: 'kimi', modified_at_ms: 4567, message_count: 10 },
        { id: 'kiro', agent: 'kiro', modified_at_ms: 5678, message_count: 11 },
        { id: 'cursor', agent: 'cursor', modified_at_ms: 6789, message_count: 12 },
      ],
    })
    expect(r).toEqual({
      type: 'agent_sessions_result',
      request_id: 'hist:claude',
      sessions: [
        { id: 'abc', agent: 'claude', modifiedAtMs: 1234, messageCount: 7, inUse: true },
        { id: 'cop', agent: 'copilot', modifiedAtMs: 2345, messageCount: 8 },
        { id: 'agy', agent: 'antigravity', modifiedAtMs: 3456, messageCount: 9 },
        { id: 'kimi', agent: 'kimi', modifiedAtMs: 4567, messageCount: 10 },
        { id: 'kiro', agent: 'kiro', modifiedAtMs: 5678, messageCount: 11 },
        { id: 'cursor', agent: 'cursor', modifiedAtMs: 6789, messageCount: 12 },
      ],
    } satisfies AgentSessionsResultMsg)
    expect(JSON.stringify(r)).not.toContain('secret')
  })

  it('returns null for malformed agent session results', () => {
    expect(parseAgentSessionsResult({ type: 'agent_sessions_result', request_id: 'x' })).toBeNull()
    expect(parseAgentSessionsResult({ type: 'session_created', request_id: 'x', session_id: 's' })).toBeNull()
  })

  it('rejects malformed or aliased provider identities instead of truncating them', () => {
    const tooLong = 'x'.repeat(257)
    const parsed = parseAgentSessionsResult({
      type: 'agent_sessions_result',
      request_id: 'hist:bad',
      sessions: [
        { id: 'safe', agent: 'claude' },
        { id: ' spaced ', agent: 'claude' },
        { id: 'line\nbreak', agent: 'claude' },
        { id: '-flag', agent: 'claude' },
        { id: tooLong, agent: 'claude' },
      ],
    })
    expect(parsed?.sessions).toEqual([{ id: 'safe', agent: 'claude' }])
    expect(normalizeProviderSessionId(tooLong)).toBeNull()
  })
})

describe('control-messages — directory browser', () => {
  it('builds a content-blind list_directories request', () => {
    expect(buildListDirectories('dirs:1', ' /Users/test/home/Desktop ')).toEqual({
      type: 'list_directories',
      request_id: 'dirs:1',
      path: '/Users/test/home/Desktop',
    })
    expect(buildListDirectories('dirs:home')).toEqual({
      type: 'list_directories',
      request_id: 'dirs:home',
    })
  })

  it('parses directories_result with directory names and paths only', () => {
    const r = parseDirectoriesResult({
      type: 'directories_result',
      request_id: 'dirs:1',
      path: '/Users/test/home',
      parent: '/Users',
      entries: [
        { name: 'Desktop', path: '/Users/test/home/Desktop', first_file: 'secret.txt' },
        { name: 7, path: '/skip' },
      ],
    })
    expect(r).toEqual({
      type: 'directories_result',
      request_id: 'dirs:1',
      path: '/Users/test/home',
      parent: '/Users',
      entries: [{ name: 'Desktop', path: '/Users/test/home/Desktop' }],
    })
    expect(JSON.stringify(r)).not.toContain('secret')
  })

  it('returns null for malformed directory results', () => {
    expect(parseDirectoriesResult({ type: 'directories_result', request_id: 'x' })).toBeNull()
    expect(parseDirectoriesResult({ type: 'agent_sessions_result', request_id: 'x', sessions: [] })).toBeNull()
  })

  it('parses the typed directories error without widening its shape', () => {
    expect(parseDirectoriesReply({
      type: 'directories_error',
      request_id: 'dirs:2',
      code: 'macos_full_disk_access_required',
      message: 'untrusted agent copy',
      path: '/must/not/cross',
    })).toEqual({
      type: 'directories_error',
      request_id: 'dirs:2',
      code: 'macos_full_disk_access_required',
      message: 'untrusted agent copy',
    })
  })
})

describe('control-messages — desktop access status', () => {
  it('accepts only the exact bounded status shape', () => {
    expect(parseDesktopAccessStatus({
      type: 'desktop_access_status',
      platform: 'macos',
      full_disk_access: 'required',
    })).toEqual({
      type: 'desktop_access_status',
      platform: 'macos',
      full_disk_access: 'required',
    })
    expect(parseDesktopAccessStatus({
      type: 'desktop_access_status',
      platform: 'windows',
      full_disk_access: 'required',
    })).toBeNull()
    expect(parseDesktopAccessStatus({
      type: 'desktop_access_status',
      platform: 'macos',
      full_disk_access: 'required',
      raw_path: '/Users/private',
    })).toBeNull()
  })
})

describe('control-messages — agent session preview (gap-doc Step 2b explicit content)', () => {
  it('builds a preview_agent_session request with bounded optional fields', () => {
    expect(buildPreviewAgentSession('preview:1', 'claude', ' sess-1 ', ' /Users/test/home/app ', 12.8)).toEqual({
      type: 'preview_agent_session',
      request_id: 'preview:1',
      agent: 'claude',
      session_id: 'sess-1',
      cwd: '/Users/test/home/app',
      max_lines: 12,
    })
    expect(buildPreviewAgentSession('preview:2', 'codex', 'sess-2')).toEqual({
      type: 'preview_agent_session',
      request_id: 'preview:2',
      agent: 'codex',
      session_id: 'sess-2',
    })
  })

  it('refuses malformed provider identities before building a preview request', () => {
    expect(() => buildPreviewAgentSession('preview:bad', 'claude', 'x'.repeat(257))).toThrow(RangeError)
    expect(() => buildPreviewAgentSession('preview:bad', 'claude', 'line\nbreak')).toThrow(RangeError)
  })

  it('parses preview lines as the deliberate transcript content reply', () => {
    const r = parseAgentSessionPreviewReply({
      type: 'agent_session_preview',
      request_id: 'preview:claude:s1',
      lines: [
        { role: 'user', text: 'inspect the dashboard' },
        { role: 'assistant', text: 'working' },
        { role: 3, text: 'skip malformed' },
      ],
    })
    expect(r).toEqual({
      type: 'agent_session_preview',
      request_id: 'preview:claude:s1',
      lines: [
        { role: 'user', text: 'inspect the dashboard' },
        { role: 'assistant', text: 'working' },
      ],
    } satisfies AgentSessionPreviewMsg)
  })

  it('parses preview errors and ignores unrelated messages', () => {
    expect(parseAgentSessionPreviewReply({ type: 'agent_session_preview_error', request_id: 'p', code: 'not_implemented', message: 'missing' }))
      .toEqual({ type: 'agent_session_preview_error', request_id: 'p', code: 'not_implemented', message: 'missing' })
    expect(parseAgentSessionPreviewReply({ type: 'agent_sessions_result', request_id: 'x', sessions: [] })).toBeNull()
  })
})

describe('control-messages — agent session manage (gap-doc §4.4 rename/hide/delete)', () => {
  it('builds rename/hide/delete requests with ids and labels only', () => {
    expect(buildManageAgentSession('m1', 'rename', 'claude', ' sess-1 ', { name: ' Literature ' })).toEqual({
      type: 'manage_agent_session',
      request_id: 'm1',
      action: 'rename',
      agent: 'claude',
      session_id: 'sess-1',
      name: 'Literature',
    })
    expect(buildManageAgentSession('m2', 'hide', 'codex', 'sess-2')).toEqual({
      type: 'manage_agent_session',
      request_id: 'm2',
      action: 'hide',
      agent: 'codex',
      session_id: 'sess-2',
    })
    expect(buildManageAgentSession('m3', 'delete', 'gemini', 'sess-3', { cwd: ' /Users/test/home/app ' })).toEqual({
      type: 'manage_agent_session',
      request_id: 'm3',
      action: 'delete',
      agent: 'gemini',
      session_id: 'sess-3',
      cwd: '/Users/test/home/app',
    })
  })

  it('refuses malformed provider identities before building a manage request', () => {
    expect(() => buildManageAgentSession('m-bad', 'hide', 'claude', '-flag')).toThrow(RangeError)
    expect(() => buildManageAgentSession('m-bad', 'hide', 'claude', 'x'.repeat(257))).toThrow(RangeError)
  })

  it('parses manage ok/error and ignores unrelated replies', () => {
    expect(parseAgentSessionManageReply({ type: 'agent_session_managed', request_id: 'm1' }))
      .toEqual({ type: 'agent_session_managed', request_id: 'm1' } satisfies AgentSessionManageReply)
    expect(parseAgentSessionManageReply({ type: 'agent_session_manage_error', request_id: 'm2', code: 'not_found', message: 'gone' }))
      .toEqual({ type: 'agent_session_manage_error', request_id: 'm2', code: 'not_found', message: 'gone' } satisfies AgentSessionManageReply)
    expect(parseAgentSessionManageReply({ type: 'agent_session_preview', request_id: 'p', lines: [] })).toBeNull()
  })

  it('does not carry transcript or terminal-shaped payload fields', () => {
    const built = JSON.stringify(buildManageAgentSession('m1', 'rename', 'claude', 'sess-1', { name: 'Clean name' })).toLowerCase()
    for (const bad of ['stdout', 'stderr', 'pty', 'output', 'transcript', 'message_count', 'first_message']) {
      expect(built).not.toContain(bad)
    }
  })
})

describe('control-messages — labels (F1)', () => {
  it('includes a non-empty label in the request, trimmed', () => {
    expect(buildCreateSession('c1', '  build logs ')).toEqual({ type: 'create_session', request_id: 'c1', label: 'build logs' })
  })

  it('includes desktop launch context when provided', () => {
    expect(buildCreateSession('c1', {
      label: '  API pane ',
      cwd: ' /Users/test/home/app ',
      agent: 'codex',
      launchFlags: { resumeMode: 'resume', resumeSessionId: 'abc', dangerouslySkipPermissions: true },
    })).toEqual({
      type: 'create_session',
      request_id: 'c1',
      label: 'API pane',
      cwd: '/Users/test/home/app',
      agent: 'codex',
      launch_flags: { resumeMode: 'resume', resumeSessionId: 'abc', dangerouslySkipPermissions: true },
    })
  })

  it('omits the label entirely when absent/blank (old-client wire shape)', () => {
    expect(buildCreateSession('c1')).toEqual({ type: 'create_session', request_id: 'c1' })
    expect(buildCreateSession('c1', '   ')).toEqual({ type: 'create_session', request_id: 'c1' })
  })

  it('parses a label from session_created when present', () => {
    const r = parseCreateSessionReply({ type: 'session_created', request_id: 'c1', session_id: 's-a', label: 'logs' })
    expect(r).toEqual({ type: 'session_created', request_id: 'c1', session_id: 's-a', label: 'logs' })
  })

  it('treats a missing/blank label as no label (back-compat)', () => {
    const r = parseCreateSessionReply({ type: 'session_created', request_id: 'c1', session_id: 's-a' })
    expect((r as { label?: string }).label).toBeUndefined()
    const r2 = parseCreateSessionReply({ type: 'session_created', request_id: 'c1', session_id: 's-a', label: '  ' })
    expect((r2 as { label?: string }).label).toBeUndefined()
  })
})

describe('control-messages — split_pane (gap-doc Step 3)', () => {
  it('builds a desktop-authoritative split request (window + from-pane + dir); agent/flags optional', () => {
    expect(buildSplitPane('s1', 'win-1', 'pane-2', 'right')).toEqual({
      type: 'split_pane', request_id: 's1', window_id: 'win-1', from_pane_id: 'pane-2', dir: 'right',
    })
    const withCtx = buildSplitPane('s2', 'win-1', 'pane-2', 'down', { agent: 'codex' })
    expect(withCtx.agent).toBe('codex')
    expect(withCtx.dir).toBe('down')
    // empty launch flags are omitted (no command on the wire either way)
    expect(buildSplitPane('s3', 'w', 'p', 'right', { launchFlags: {} }).launch_flags).toBeUndefined()
  })

  it('emits pane_name (trimmed, only when non-empty) and launch_flags with the model', () => {
    const msg = buildSplitPane('s4', 'w', 'p', 'right', {
      paneName: '  Build pane  ',
      launchFlags: { resumeMode: 'resume', resumeSessionId: 'cdx-1', model: 'gpt-5.2-codex' },
    })
    expect(msg.pane_name).toBe('Build pane')
    expect(msg.launch_flags).toEqual({ resumeMode: 'resume', resumeSessionId: 'cdx-1', model: 'gpt-5.2-codex' })
    // blank name is omitted, not sent as ''
    expect(buildSplitPane('s5', 'w', 'p', 'right', { paneName: '   ' }).pane_name).toBeUndefined()
    expect(buildSplitPane('s6', 'w', 'p', 'right', {}).pane_name).toBeUndefined()
  })

  it('builds a remote-layout new_pane request without a split direction', () => {
    expect(buildNewPane('np1', 'win-1', 'pane-2')).toEqual({
      type: 'new_pane',
      request_id: 'np1',
      window_id: 'win-1',
      from_pane_id: 'pane-2',
    })
    expect(buildNewPane('np2', 'win-1', 'pane-2', {
      agent: 'codex',
      cwd: ' /tmp/review ',
      paneName: '  Review  ',
      launchFlags: { model: 'gpt-5.2-codex' },
    })).toEqual({
      type: 'new_pane',
      request_id: 'np2',
      window_id: 'win-1',
      from_pane_id: 'pane-2',
      agent: 'codex',
      cwd: '/tmp/review',
      pane_name: 'Review',
      launch_flags: { model: 'gpt-5.2-codex' },
    })
  })

  it('parses split_pane_ok / split_pane_error; null for anything else', () => {
    expect(parseSplitPaneReply({ type: 'split_pane_ok', request_id: 's1', session_id: 's-new', tab_id: 'pane-9' }))
      .toEqual({ type: 'split_pane_ok', request_id: 's1', session_id: 's-new', tab_id: 'pane-9' })
    expect(parseSplitPaneReply({ type: 'split_pane_error', request_id: 's1', code: 'pane_limit', message: 'max 4' }))
      .toEqual({ type: 'split_pane_error', request_id: 's1', code: 'pane_limit', message: 'max 4' })
    expect(parseSplitPaneReply({ type: 'session_created', request_id: 's1', session_id: 'x' })).toBeNull()
    expect(parseSplitPaneReply(null)).toBeNull()
  })
})

describe('control-messages — revive_pane (gap-doc Step 3b)', () => {
  it('builds a desktop-authoritative revive request', () => {
    expect(buildRevivePane('r1', 'win-1', 'pane-old')).toEqual({
      type: 'revive_pane',
      request_id: 'r1',
      window_id: 'win-1',
      pane_id: 'pane-old',
    })
  })

  it('parses revive_pane_ok / revive_pane_error; null for anything else', () => {
    expect(parseRevivePaneReply({ type: 'revive_pane_ok', request_id: 'r1', session_id: 's-old' }))
      .toEqual({ type: 'revive_pane_ok', request_id: 'r1', session_id: 's-old' })
    expect(parseRevivePaneReply({ type: 'revive_pane_error', request_id: 'r1', code: 'pane_not_found', message: 'missing' }))
      .toEqual({ type: 'revive_pane_error', request_id: 'r1', code: 'pane_not_found', message: 'missing' })
    expect(parseRevivePaneReply({ type: 'split_pane_ok', request_id: 's1', session_id: 's-new', tab_id: 'pane-9' })).toBeNull()
    expect(parseRevivePaneReply(null)).toBeNull()
  })
})

describe('control-messages — stash_pane (desktop Close/stash)', () => {
  it('builds a desktop-authoritative stash request', () => {
    expect(buildStashPane('sp1', 'win-1', 'pane-live')).toEqual({
      type: 'stash_pane',
      request_id: 'sp1',
      window_id: 'win-1',
      pane_id: 'pane-live',
    })
  })

  it('parses stash_pane_ok / stash_pane_error; null for anything else', () => {
    expect(parseStashPaneReply({ type: 'stash_pane_ok', request_id: 'sp1' }))
      .toEqual({ type: 'stash_pane_ok', request_id: 'sp1' })
    expect(parseStashPaneReply({ type: 'stash_pane_error', request_id: 'sp1', code: 'pane_not_found', message: 'missing' }))
      .toEqual({ type: 'stash_pane_error', request_id: 'sp1', code: 'pane_not_found', message: 'missing' })
    expect(parseStashPaneReply({ type: 'revive_pane_ok', request_id: 'r1', session_id: 's-old' })).toBeNull()
    expect(parseStashPaneReply(null)).toBeNull()
  })
})

describe('control-messages — remove_pane (desktop Remove from shelf)', () => {
  it('builds a desktop-authoritative remove request', () => {
    expect(buildRemovePane('rp1', 'win-1', 'pane-stashed')).toEqual({
      type: 'remove_pane',
      request_id: 'rp1',
      window_id: 'win-1',
      pane_id: 'pane-stashed',
    })
  })

  it('parses remove_pane_ok / remove_pane_error; null for anything else', () => {
    expect(parseRemovePaneReply({ type: 'remove_pane_ok', request_id: 'rp1' }))
      .toEqual({ type: 'remove_pane_ok', request_id: 'rp1' })
    expect(parseRemovePaneReply({ type: 'remove_pane_error', request_id: 'rp1', code: 'pane_not_found', message: 'missing' }))
      .toEqual({ type: 'remove_pane_error', request_id: 'rp1', code: 'pane_not_found', message: 'missing' })
    expect(parseRemovePaneReply({ type: 'stash_pane_ok', request_id: 's1' })).toBeNull()
    expect(parseRemovePaneReply(null)).toBeNull()
  })
})

describe('control-messages — rename (desktop pane/window rename)', () => {
  it('builds pane and window rename requests', () => {
    expect(buildRename('rn1', 'win-1', ' Build pane ', 'pane-a')).toEqual({
      type: 'rename',
      request_id: 'rn1',
      window_id: 'win-1',
      pane_id: 'pane-a',
      name: 'Build pane',
    })
    expect(buildRename('rn2', 'win-1', ' Main window ')).toEqual({
      type: 'rename',
      request_id: 'rn2',
      window_id: 'win-1',
      name: 'Main window',
    })
  })

  it('parses rename_ok / rename_error; null for anything else', () => {
    expect(parseRenameReply({ type: 'rename_ok', request_id: 'rn1' }))
      .toEqual({ type: 'rename_ok', request_id: 'rn1' })
    expect(parseRenameReply({ type: 'rename_error', request_id: 'rn1', code: 'invalid_name', message: 'missing' }))
      .toEqual({ type: 'rename_error', request_id: 'rn1', code: 'invalid_name', message: 'missing' })
    expect(parseRenameReply({ type: 'stash_pane_ok', request_id: 'sp1' })).toBeNull()
  })
})

describe('control-messages — close_window (desktop destructive window remove)', () => {
  it('builds a desktop-authoritative close window request', () => {
    expect(buildCloseWindow('cw1', 'win-1')).toEqual({
      type: 'close_window',
      request_id: 'cw1',
      window_id: 'win-1',
    })
  })

  it('parses close_window_ok / close_window_error; null for anything else', () => {
    expect(parseCloseWindowReply({ type: 'close_window_ok', request_id: 'cw1' }))
      .toEqual({ type: 'close_window_ok', request_id: 'cw1' })
    expect(parseCloseWindowReply({ type: 'close_window_error', request_id: 'cw1', code: 'window_not_found', message: 'missing' }))
      .toEqual({ type: 'close_window_error', request_id: 'cw1', code: 'window_not_found', message: 'missing' })
    expect(parseCloseWindowReply({ type: 'rename_ok', request_id: 'rn1' })).toBeNull()
  })
})

describe('control-messages — focus_window (desktop window tab selection)', () => {
  it('builds and parses focus_window requests/replies', () => {
    expect(buildFocusWindow('fw1', 'win-main')).toEqual({
      type: 'focus_window',
      request_id: 'fw1',
      window_id: 'win-main',
    })
    expect(parseFocusWindowReply({ type: 'focus_window_ok', request_id: 'fw1' }))
      .toEqual({ type: 'focus_window_ok', request_id: 'fw1' })
    expect(parseFocusWindowReply({ type: 'focus_window_error', request_id: 'fw1', code: 'window_not_found', message: 'missing' }))
      .toEqual({ type: 'focus_window_error', request_id: 'fw1', code: 'window_not_found', message: 'missing' })
    expect(parseFocusWindowReply({ type: 'close_window_ok', request_id: 'cw1' })).toBeNull()
  })
})

describe('control-messages — new_window (gap-doc Step 4)', () => {
  it('builds a desktop-authoritative new window request', () => {
    expect(buildNewWindow('n1', 'proj-capacity', '  Experiment ', {
      cwd: ' /tmp/experiment ',
      agent: 'codex',
      launchFlags: { resumeMode: 'new' },
    })).toEqual({
      type: 'new_window',
      request_id: 'n1',
      project_id: 'proj-capacity',
      name: 'Experiment',
      cwd: '/tmp/experiment',
      agent: 'codex',
      launch_flags: { resumeMode: 'new' },
    })
    expect(buildNewWindow('n2', 'p1', '   ')).toEqual({
      type: 'new_window',
      request_id: 'n2',
      project_id: 'p1',
      name: 'Window',
    })
  })

  it('parses new_window_ok / new_window_error; null for anything else', () => {
    expect(parseNewWindowReply({ type: 'new_window_ok', request_id: 'n1', window_id: 'w-new', session_id: 's-new' }))
      .toEqual({ type: 'new_window_ok', request_id: 'n1', window_id: 'w-new', session_id: 's-new' })
    expect(parseNewWindowReply({ type: 'new_window_error', request_id: 'n1', code: 'project_not_found', message: 'missing' }))
      .toEqual({ type: 'new_window_error', request_id: 'n1', code: 'project_not_found', message: 'missing' })
    expect(parseNewWindowReply({ type: 'revive_pane_ok', request_id: 'r1', session_id: 's-old' })).toBeNull()
    expect(parseNewWindowReply(null)).toBeNull()
  })
})
