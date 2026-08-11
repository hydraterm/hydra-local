import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App } from './App'
import { mockDashboardModel } from './data/mock'
import type { DashboardModel } from './types/model'

type SidebarTestWindow = Window & {
  __HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?: (state: {
    width_logical_px: number
    last_expanded_width_logical_px: number
  }) => void
  __HYDRA_PENDING_SIDEBAR_STATE__?: {
    width_logical_px: number
    last_expanded_width_logical_px: number
  }
  __TEST_PUSH_DASHBOARD_MODEL__?: (model: DashboardModel) => void
}

let renderer: ReactTestRenderer | null = null

function createPointerTarget(): {
  captured: Set<number>
  target: {
    setPointerCapture: ReturnType<typeof vi.fn>
    hasPointerCapture: ReturnType<typeof vi.fn>
    releasePointerCapture: ReturnType<typeof vi.fn>
  }
} {
  const captured = new Set<number>()
  return {
    captured,
    target: {
      setPointerCapture: vi.fn((pointerId: number) => {
        captured.add(pointerId)
      }),
      hasPointerCapture: vi.fn((pointerId: number) => captured.has(pointerId)),
      releasePointerCapture: vi.fn((pointerId: number) => {
        captured.delete(pointerId)
      }),
    },
  }
}

function pointerEvent(
  currentTarget: ReturnType<typeof createPointerTarget>['target'],
  overrides: Partial<{
    pointerId: number
    isPrimary: boolean
    button: number
    buttons: number
    screenX: number
    clientX: number
  }> = {},
): Record<string, unknown> {
  return {
    pointerId: 7,
    isPrimary: true,
    button: 0,
    buttons: 1,
    screenX: 460,
    clientX: 460,
    currentTarget,
    preventDefault: vi.fn(),
    ...overrides,
  }
}

function installWindow(
  search: string,
  intents: Array<Record<string, unknown>>,
  initialModel: DashboardModel = structuredClone(mockDashboardModel),
): SidebarTestWindow {
  let model = initialModel
  let modelListener: ((model: DashboardModel) => void) | null = null
  const browserWindow = Object.assign(new EventTarget(), {
    location: { href: `hydra://localhost/index.html${search}`, search },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      getDashboardModel: () => structuredClone(model),
      postIntent: (intent: Record<string, unknown>) => intents.push(intent),
      onDashboardModel: (listener: (next: DashboardModel) => void) => {
        modelListener = listener
        return () => {
          if (modelListener === listener) modelListener = null
        }
      },
    },
  }) as unknown as SidebarTestWindow
  browserWindow.__TEST_PUSH_DASHBOARD_MODEL__ = (next) => {
    model = next
    modelListener?.(next)
  }
  const bodyClasses = new Set<string>()
  vi.stubGlobal('window', browserWindow)
  vi.stubGlobal('document', {
    body: {
      classList: {
        add: (...tokens: string[]) => tokens.forEach((token) => bodyClasses.add(token)),
        remove: (...tokens: string[]) => tokens.forEach((token) => bodyClasses.delete(token)),
        contains: (token: string) => bodyClasses.has(token),
      },
    },
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  })
  return browserWindow
}

async function mount(): Promise<void> {
  await act(async () => {
    renderer = create(<App />)
    await Promise.resolve()
  })
}

afterEach(() => {
  if (renderer) {
    act(() => renderer?.unmount())
    renderer = null
  }
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('native sidebar geometry and focus', () => {
  it('renders the Hydra brand as a code-native mark without an image asset', async () => {
    installWindow('?chrome=sidebar', [])
    await mount()

    expect(renderer!.root.findByProps({ className: 'sidebar__brand-letter' }).children).toEqual([
      'H',
    ])
    expect(
      renderer!.root.findByProps({ className: 'sidebar__brand-glyph' }).findAllByType('img'),
    ).toHaveLength(0)
  })

  it('shows an exact available version above New project and emits only the typed native action', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      update: {
        status: 'available',
        current_version: '0.2.6',
        latest_version: '0.2.7',
        release_git_sha: '0123456789abcdef0123456789abcdef01234567',
        published_at: '2026-07-30T12:34:56Z',
        download_artifact: 'macos-universal-dmg',
        download_sha256:
          '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        action_available: true,
      },
    }
    installWindow('?chrome=sidebar', intents, initialModel)
    await mount()

    const update = renderer!.root.findByProps({
      'aria-label': 'Download Hydra 0.2.7 update',
    })
    expect(renderer!.root.findByProps({ className: 'sidebar__update-title' }).children).toEqual([
      'Update available',
    ])
    expect(renderer!.root.findByProps({ className: 'sidebar__update-version' }).children.join('')).toBe(
      'v0.2.7 · current v0.2.6',
    )
    expect(renderer!.root.findByProps({ className: 'sidebar__new-project' })).toBeTruthy()

    act(() => update.props.onClick())
    expect(intents[intents.length - 1]).toEqual({ type: 'openAvailableUpdate' })
  })

  it('does not advertise an update without native validated availability', async () => {
    for (const update of [
      undefined,
      {
        status: 'up_to_date' as const,
        current_version: '0.2.6',
        latest_version: '0.2.6',
        release_git_sha: null,
        published_at: null,
        download_artifact: null,
        download_sha256: null,
        action_available: false,
      },
      {
        status: 'available' as const,
        current_version: '0.2.6',
        latest_version: '0.2.7',
        release_git_sha: null,
        published_at: null,
        download_artifact: null,
        download_sha256: null,
        action_available: false,
      },
    ]) {
      installWindow('?chrome=sidebar', [], {
        ...structuredClone(mockDashboardModel),
        update,
      })
      await mount()

      expect(renderer!.root.findAllByProps({ className: 'sidebar__update' })).toHaveLength(0)

      act(() => renderer?.unmount())
      renderer = null
      vi.unstubAllGlobals()
    }
  })

  it('politely announces an update that arrives after the sidebar is mounted', async () => {
    const browserWindow = installWindow('?chrome=sidebar', [])
    await mount()

    const status = renderer!.root.findByProps({ role: 'status' })
    expect(status.props['aria-live']).toBe('polite')
    expect(status.props['aria-atomic']).toBe('true')
    expect(status.children).toHaveLength(0)

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        update: {
          status: 'available',
          current_version: '0.2.6',
          latest_version: '0.2.7',
          release_git_sha: '0123456789abcdef0123456789abcdef01234567',
          published_at: '2026-07-30T12:34:56Z',
          download_artifact: 'macos-universal-dmg',
          download_sha256:
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          action_available: true,
        },
      })
      await Promise.resolve()
    })

    expect(renderer!.root.findByProps({ role: 'status' }).children.join('')).toBe(
      'Hydra 0.2.7 update available.',
    )
    expect(
      renderer!.root.findByProps({ 'aria-label': 'Download Hydra 0.2.7 update' }),
    ).toBeTruthy()
  })

  it('keeps Add Remote guidance correct for macOS, Linux, production, and staging builds', async () => {
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      enrolled: false,
      remote_open: false,
      enroll_error: null,
    }
    installWindow('?chrome=sidebar', [], initialModel)
    await mount()

    const copy = renderer!.root
      .findByProps({ className: 'sidebar__add-remote-hint' })
      .children.join('')
    expect(copy).toMatch(/Hydra web app/i)
    expect(copy).toMatch(/this computer/i)
    expect(copy).not.toMatch(/Mac|app\.hydraterms\.com/i)
  })

  it('auto-expands once per exact filesystem-migration notice and renders all ten reversible changes', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = installWindow('?chrome=sidebar', intents)
    await mount()

    act(() =>
      browserWindow.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?.({
        width_logical_px: 24,
        last_expanded_width_logical_px: 377,
      }),
    )
    expect(renderer!.root.findByProps({ 'aria-label': 'Expand sidebar' })).toBeTruthy()

    const notice = {
      notice_id: 'a'.repeat(64),
      phase: 'ready_to_apply' as const,
      changes: [
        {
          path: '/home/tester/.local',
          old_mode: '0775' as const,
          new_mode: '0755' as const,
          rollback_command: "chmod 0775 -- '/home/tester/.local'",
        },
        {
          path: '/home/tester/.local/share',
          old_mode: '0775' as const,
          new_mode: '0755' as const,
          rollback_command: "chmod 0775 -- '/home/tester/.local/share'",
        },
        {
          path: '/home/tester/.local/share/hydra-agent',
          old_mode: '0770' as const,
          new_mode: '0700' as const,
          rollback_command: "chmod 0770 -- '/home/tester/.local/share/hydra-agent'",
        },
        {
          path: '/home/tester/.config',
          old_mode: '0775' as const,
          new_mode: '0755' as const,
          rollback_command: "chmod 0775 -- '/home/tester/.config'",
        },
        {
          path: '/home/tester/.config/systemd',
          old_mode: '0775' as const,
          new_mode: '0755' as const,
          rollback_command: "chmod 0775 -- '/home/tester/.config/systemd'",
        },
        {
          path: '/home/tester/.config/systemd/user',
          old_mode: '0775' as const,
          new_mode: '0755' as const,
          rollback_command: "chmod 0775 -- '/home/tester/.config/systemd/user'",
        },
        {
          path: '/home/tester/.config/systemd/user/hydra-agent.service',
          old_mode: '0664' as const,
          new_mode: '0644' as const,
          rollback_command: "chmod 0664 -- '/home/tester/.config/systemd/user/hydra-agent.service'",
        },
        {
          path: '/home/tester/.local/state',
          old_mode: '0775' as const,
          new_mode: '0755' as const,
          rollback_command: "chmod 0775 -- '/home/tester/.local/state'",
        },
        {
          path: '/home/tester/.local/state/hydra-agent',
          old_mode: '0770' as const,
          new_mode: '0700' as const,
          rollback_command: "chmod 0770 -- '/home/tester/.local/state/hydra-agent'",
        },
        {
          path: '/home/tester/.local/state/hydra-agent/logs',
          old_mode: '0770' as const,
          new_mode: '0700' as const,
          rollback_command: "chmod 0770 -- '/home/tester/.local/state/hydra-agent/logs'",
        },
      ],
    }
    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        enrolled: false,
        filesystem_mode_migration: notice,
      })
      await Promise.resolve()
    })

    expect(intents[intents.length - 1]).toEqual({ type: 'setSidebarWidth', width: 377 })
    expect(renderer!.root.findByProps({ 'aria-label': 'Collapse sidebar' })).toBeTruthy()
    const alert = renderer!.root.findByProps({
      role: 'alert',
      'aria-label': 'Linux file and folder security update required',
    })
    expect(alert.props['data-notice-id']).toBe(notice.notice_id)
    expect(
      renderer!.root.findAllByProps({ className: 'sidebar__filesystem-migration-path' }).map(
        (node) => node.children.join(''),
      ),
    ).toEqual(notice.changes.map((change) => change.path))
    expect(
      renderer!.root.findAllByProps({ className: 'sidebar__filesystem-migration-modes' }).map(
        (node) => node.children.flatMap((child) =>
          typeof child === 'string' ? child : child.children,
        ).join(''),
      ),
    ).toEqual(notice.changes.map((change) => `${change.old_mode}→${change.new_mode}`))
    expect(
      renderer!.root
        .findAll(
          (node) =>
            typeof node.props['aria-label'] === 'string' &&
            node.props['aria-label'].startsWith('Rollback command for '),
        )
        .map((node) => node.props.value),
    ).toEqual(notice.changes.map((change) => change.rollback_command))
    expect(renderer!.root.findByProps({ className: 'sidebar__add-remote-btn' }).props.disabled).toBe(
      true,
    )

    // A deliberate collapse is respected within the same phase. The same exact notice advancing
    // Ready→Applied must expand again so the user sees the result and receipt at change time.
    act(() =>
      browserWindow.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?.({
        width_logical_px: 24,
        last_expanded_width_logical_px: 377,
      }),
    )
    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        filesystem_mode_migration: structuredClone(notice),
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Expand sidebar' })).toBeTruthy()

    const appliedNotice = {
      ...structuredClone(notice),
      phase: 'applied' as const,
      recovery_record_path: '/home/tester/.hydra-agent-authority-migration-v1.json',
    }
    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        filesystem_mode_migration: appliedNotice,
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Collapse sidebar' })).toBeTruthy()
    act(() =>
      browserWindow.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?.({
        width_logical_px: 24,
        last_expanded_width_logical_px: 377,
      }),
    )
    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        filesystem_mode_migration: structuredClone(appliedNotice),
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Expand sidebar' })).toBeTruthy()

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        filesystem_mode_migration: { ...structuredClone(notice), notice_id: 'b'.repeat(64) },
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Collapse sidebar' })).toBeTruthy()
    act(() =>
      browserWindow.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?.({
        width_logical_px: 377,
        last_expanded_width_logical_px: 377,
      }),
    )
  })

  it('emits only notice-id migration actions and keeps Remote closed through exact acknowledgement', async () => {
    const intents: Array<Record<string, unknown>> = []
    const writeText = vi.fn(async () => undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const browserWindow = installWindow('?chrome=sidebar', intents, {
      ...structuredClone(mockDashboardModel),
      enrolled: true,
      remote_open: false,
      filesystem_mode_migration: {
        notice_id: 'c'.repeat(64),
        phase: 'interrupted',
        changes: [
          {
            path: '/home/tester/.local/share/hydra-agent',
            old_mode: '0770',
            new_mode: '0700',
            rollback_command: "chmod 0770 -- '/home/tester/.local/share/hydra-agent'",
          },
        ],
        recovery_record_path: '/home/tester/.hydra-agent-authority-migration-v1.json',
      },
    })
    await mount()

    const openRemote = renderer!.root.findByProps({ 'aria-label': 'Open remote access' })
    expect(openRemote.props.disabled).toBe(true)
    expect(
      renderer!.root.findByProps({ className: 'sidebar__filesystem-migration-recovery' }).children.join(''),
    ).toMatch(/temporary recovery record/i)
    const secure = renderer!.root.findByProps({ className: 'sidebar__filesystem-migration-action' })
    expect(secure.children).toEqual(['Secure files and folders'])
    act(() => secure.props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'applyRemoteFilesystemMigration',
      notice_id: 'c'.repeat(64),
    })

    await act(async () => {
      renderer!.root
        .findByProps({
          'aria-label': 'Copy rollback command for /home/tester/.local/share/hydra-agent',
        })
        .props.onClick()
      await Promise.resolve()
    })
    expect(writeText).toHaveBeenCalledWith(
      "chmod 0770 -- '/home/tester/.local/share/hydra-agent'",
    )

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        enrolled: true,
        remote_open: false,
        filesystem_mode_migration: {
          notice_id: 'c'.repeat(64),
          phase: 'applied',
          changes: [
            {
              path: '/home/tester/.local/share/hydra-agent',
              old_mode: '0770',
              new_mode: '0700',
              rollback_command: "chmod 0770 -- '/home/tester/.local/share/hydra-agent'",
            },
          ],
          recovery_record_path: '/home/tester/.hydra-agent-authority-migration-v1.json',
        },
      })
      await Promise.resolve()
    })
    const gotIt = renderer!.root.findByProps({ className: 'sidebar__filesystem-migration-action' })
    expect(gotIt.children).toEqual(['Got it'])
    act(() => gotIt.props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'acknowledgeRemoteFilesystemMigration',
      notice_id: 'c'.repeat(64),
    })
    expect(
      renderer!.root.findByProps({
        role: 'alert',
        'aria-label': 'Linux file and folder security update required',
      }),
    ).toBeTruthy()

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...structuredClone(mockDashboardModel),
        enrolled: true,
        remote_open: false,
        filesystem_mode_migration: null,
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Open remote access' }).props.disabled).toBe(
      false,
    )
  })

  it('omits a malformed recovery action while keeping Remote fail closed', async () => {
    const malformedNotice = {
      notice_id: 'd'.repeat(64),
      phase: 'applied',
      changes: [
        {
          path: '/home/tester/.local',
          old_mode: '0775',
          new_mode: '0755',
          rollback_command: "chmod 0775 -- '/home/tester/.local'",
        },
      ],
      // Runtime JSON can violate the TypeScript union; an Applied notice without this path is not actionable.
      recovery_record_path: undefined,
    } as unknown as DashboardModel['filesystem_mode_migration']
    installWindow('?chrome=sidebar', [], {
      ...structuredClone(mockDashboardModel),
      enrolled: true,
      remote_open: false,
      filesystem_mode_migration: malformedNotice,
    })
    await mount()

    expect(
      renderer!.root.findAllByProps({
        role: 'alert',
        'aria-label': 'Linux file and folder security update required',
      }),
    ).toHaveLength(0)
    expect(renderer!.root.findByProps({ 'aria-label': 'Open remote access' }).props.disabled).toBe(
      true,
    )
  })

  it('hides every Remote control unless the private extension capability is negotiated', async () => {
    const intents: Array<Record<string, unknown>> = []
    const unavailableModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      remote_available: false,
      enrolled: true,
      account_id: 'acct_must_not_render',
      remote_open: true,
      enroll_error: 'must not render',
      desktop_access: {
        status: 'required',
        onboarding_acknowledged: false,
        required_error_code: 'macos_full_disk_access_required',
      },
    }
    const browserWindow = installWindow('?chrome=sidebar', intents, unavailableModel)
    await mount()

    expect(renderer!.root.findAllByProps({ 'aria-label': 'Enrollment code' })).toHaveLength(0)
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Full Disk Access required' })).toHaveLength(
      0,
    )
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Close remote access' })).toHaveLength(0)
    expect(renderer!.root.findAllByProps({ className: 'sidebar__enrolled' })).toHaveLength(0)
    expect(renderer!.root.findAllByProps({ role: 'alert' })).toHaveLength(0)
    expect(intents).toEqual([])

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...unavailableModel,
        remote_available: true,
        desktop_access: undefined,
        enroll_error: null,
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Close remote access' })).toBeTruthy()

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.(unavailableModel)
      await Promise.resolve()
    })
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Close remote access' })).toHaveLength(0)
    expect(intents).toEqual([])
  })

  it('blocks enrollment and emits only typed FDA actions while capability is required', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      enrolled: false,
      remote_open: false,
      enroll_error: null,
      desktop_access: {
        status: 'required',
        onboarding_acknowledged: false,
        required_error_code: 'macos_full_disk_access_required',
      },
    }
    installWindow('?chrome=sidebar', intents, initialModel)
    await mount()

    const card = renderer!.root.findByProps({ 'aria-label': 'Full Disk Access required' })
    expect(card.props['data-error-code']).toBe('macos_full_disk_access_required')
    expect(renderer!.root.findByProps({ 'aria-label': 'Enrollment code' }).props.disabled).toBe(true)
    expect(renderer!.root.findByProps({ className: 'sidebar__add-remote-btn' }).props.disabled).toBe(
      true,
    )

    act(() =>
      renderer!.root
        .findByProps({ className: 'sidebar__desktop-access-primary' })
        .props.onClick(),
    )
    act(() =>
      renderer!.root
        .findByProps({ className: 'sidebar__desktop-access-secondary' })
        .props.onClick(),
    )
    expect(intents.slice(-2)).toEqual([
      { type: 'openFullDiskAccessSettings' },
      { type: 'refreshDesktopAccess' },
    ])
  })

  it('keeps an acknowledged but unverified capability blocked', async () => {
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      enrolled: false,
      remote_open: false,
      enroll_error: null,
      desktop_access: {
        status: 'unknown',
        onboarding_acknowledged: true,
        required_error_code: 'macos_full_disk_access_required',
      },
    }
    installWindow('?chrome=sidebar', [], initialModel)
    await mount()

    expect(
      renderer!.root.findByProps({ className: 'sidebar__desktop-access-title' }).children,
    ).toEqual(['Full Disk Access still needed'])
    expect(renderer!.root.findByProps({ 'aria-label': 'Enrollment code' }).props.disabled).toBe(true)
  })

  it('does not alter Linux, older-host, or verified enrollment behavior', async () => {
    for (const desktop_access of [
      undefined,
      {
        status: 'not_applicable' as const,
        onboarding_acknowledged: false,
        required_error_code: 'macos_full_disk_access_required' as const,
      },
      {
        status: 'granted' as const,
        onboarding_acknowledged: true,
        required_error_code: 'macos_full_disk_access_required' as const,
      },
    ]) {
      const initialModel: DashboardModel = {
        ...structuredClone(mockDashboardModel),
        enrolled: false,
        remote_open: false,
        enroll_error: null,
        desktop_access,
      }
      installWindow('?chrome=sidebar', [], initialModel)
      await mount()

      expect(
        renderer!.root.findAllByProps({ 'aria-label': 'Full Disk Access required' }),
      ).toHaveLength(0)
      expect(renderer!.root.findByProps({ 'aria-label': 'Enrollment code' }).props.disabled).toBe(
        false,
      )

      act(() => renderer?.unmount())
      renderer = null
      vi.unstubAllGlobals()
    }
  })

  it('keeps the enrollment code while Add Remote is pending and after a failed result', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      enrolled: false,
      remote_open: false,
      enroll_error: null,
    }
    const browserWindow = installWindow('?chrome=sidebar', intents, initialModel)
    await mount()

    let input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Open remote access' })).toHaveLength(0)
    act(() => input.props.onChange({ target: { value: '  TEST-CODE  ' } }))
    input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    const preventDefault = vi.fn()
    act(() => input.props.onKeyDown({ key: 'Enter', preventDefault }))

    expect(preventDefault).toHaveBeenCalledOnce()
    expect(intents[intents.length - 1]).toEqual({ type: 'enrollDesktop', code: 'TEST-CODE' })
    input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    expect(input.props.value).toBe('  TEST-CODE  ')
    expect(input.props.disabled).toBe(true)
    const pendingButton = renderer!.root.findByProps({ className: 'sidebar__add-remote-btn' })
    expect(pendingButton.children).toEqual(['Adding…'])
    expect(pendingButton.props.disabled).toBe(true)
    act(() => pendingButton.props.onClick())
    expect(intents.filter((intent) => intent.type === 'enrollDesktop')).toHaveLength(1)

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...initialModel,
        enroll_error: 'That code could not be used.',
      })
      await Promise.resolve()
    })

    input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    expect(input.props.value).toBe('  TEST-CODE  ')
    expect(input.props.disabled).toBe(false)
    expect(renderer!.root.findByProps({ role: 'alert' }).children).toEqual([
      'That code could not be used.',
    ])

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...initialModel,
        enrolled: true,
        account_id: 'acct_fixture',
        remote_open: false,
        enroll_error: 'The desktop was added, but its service is not ready yet.',
      })
      await Promise.resolve()
    })

    const openRemote = renderer!.root.findByProps({ 'aria-label': 'Open remote access' })
    expect(openRemote.props.disabled).not.toBe(true)
    expect(renderer!.root.findByProps({ role: 'alert' }).children).toEqual([
      'The desktop was added, but its service is not ready yet.',
    ])

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.(initialModel)
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Enrollment code' }).props.value).toBe(
      '  TEST-CODE  ',
    )
  })

  it('publishes enrolled/open state after Add Remote and exposes a partial service failure honestly', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      enrolled: false,
      remote_open: false,
      enroll_error: null,
    }
    const browserWindow = installWindow('?chrome=sidebar', intents, initialModel)
    await mount()

    const input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    act(() => input.props.onChange({ target: { value: 'TEST-CODE' } }))
    act(() =>
      renderer!.root
        .find((node) => node.props.className === 'sidebar__add-remote-btn')
        .props.onClick(),
    )

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.({
        ...initialModel,
        enrolled: true,
        account_id: 'acct_fixture',
        remote_open: true,
        enroll_error: null,
      })
      await Promise.resolve()
    })

    expect(renderer!.root.findAllByProps({ 'aria-label': 'Enrollment code' })).toHaveLength(0)
    expect(renderer!.root.findByProps({ 'aria-label': 'Close remote access' })).toBeTruthy()

    await act(async () => {
      browserWindow.__TEST_PUSH_DASHBOARD_MODEL__?.(initialModel)
      await Promise.resolve()
    })
    expect(renderer!.root.findByProps({ 'aria-label': 'Enrollment code' }).props.value).toBe('')
  })

  it('re-enables Add Remote without clearing the code when native confirmation never arrives', async () => {
    vi.useFakeTimers()
    const intents: Array<Record<string, unknown>> = []
    const initialModel: DashboardModel = {
      ...structuredClone(mockDashboardModel),
      enrolled: false,
      remote_open: false,
      enroll_error: null,
    }
    installWindow('?chrome=sidebar', intents, initialModel)
    await mount()

    let input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    act(() => input.props.onChange({ target: { value: 'TEST-CODE' } }))
    act(() =>
      renderer!.root
        .find((node) => node.props.className === 'sidebar__add-remote-btn')
        .props.onClick(),
    )

    await act(async () => {
      await vi.advanceTimersByTimeAsync(70_000)
    })

    input = renderer!.root.findByProps({ 'aria-label': 'Enrollment code' })
    expect(input.props.value).toBe('TEST-CODE')
    expect(input.props.disabled).toBe(false)
    expect(renderer!.root.findByProps({ className: 'sidebar__add-remote-btn' }).children).toEqual([
      'Add Remote',
    ])
    expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toMatch(
      /could not confirm setup/i,
    )
  })

  it('mouse collapse removes the resizer and returns focus to the terminal', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const collapse = renderer!.root.findByProps({ 'aria-label': 'Collapse sidebar' })
    act(() => collapse.props.onClick({ detail: 1 }))

    expect(intents.slice(-2)).toEqual([
      { type: 'setSidebarWidth', width: 24 },
      { type: 'focusTerminal' },
    ])
    expect(renderer!.root.findAllByProps({ role: 'separator' })).toHaveLength(0)
    expect(renderer!.root.findByProps({ 'aria-label': 'Expand sidebar' })).toBeTruthy()
  })

  it('native recovery is authoritative and keyboard activation preserves rail focus', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = installWindow('?chrome=sidebar', intents)
    browserWindow.__HYDRA_PENDING_SIDEBAR_STATE__ = {
      width_logical_px: 24,
      last_expanded_width_logical_px: 377,
    }
    await mount()

    const expand = renderer!.root.findByProps({ 'aria-label': 'Expand sidebar' })
    act(() => expand.props.onClick({ detail: 0 }))

    expect(intents[intents.length - 1]).toEqual({ type: 'setSidebarWidth', width: 377 })
    expect(intents.some((intent) => intent.type === 'focusTerminal')).toBe(false)
    expect(renderer!.root.findByProps({ 'aria-label': 'Collapse sidebar' })).toBeTruthy()
  })

  it('full-shell collapsed mode uses two columns when the resizer is absent', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = installWindow('', intents)
    await mount()

    act(() =>
      browserWindow.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?.({
        width_logical_px: 24,
        last_expanded_width_logical_px: 460,
      }),
    )

    const shell = renderer!.root.find(
      (node) => typeof node.props.className === 'string' && node.props.className.includes('shell'),
    )
    expect(shell.props.className).toContain('is-sidebar-collapsed')
    expect(shell.props.style.gridTemplateColumns).toBe('24px 1fr')
    expect(renderer!.root.findAllByProps({ role: 'separator' })).toHaveLength(0)
  })

  it('exposes standard keyboard resize semantics and current width to accessibility', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = installWindow('?chrome=sidebar', intents)
    browserWindow.__HYDRA_PENDING_SIDEBAR_STATE__ = {
      width_logical_px: 460,
      last_expanded_width_logical_px: 460,
    }
    await mount()

    let separator = renderer!.root.findByProps({ role: 'separator' })
    expect(separator.props.tabIndex).toBe(0)
    expect(separator.props['aria-valuemin']).toBe(220)
    expect(separator.props['aria-valuemax']).toBe(560)
    expect(separator.props['aria-valuenow']).toBe(460)

    act(() => separator.props.onKeyDown({ key: 'ArrowLeft', preventDefault: vi.fn() }))
    expect(intents[intents.length - 1]).toEqual({ type: 'setSidebarWidth', width: 444 })
    separator = renderer!.root.findByProps({ role: 'separator' })
    expect(separator.props['aria-valuenow']).toBe(444)

    act(() => separator.props.onKeyDown({ key: 'Home', preventDefault: vi.fn() }))
    expect(intents[intents.length - 1]).toEqual({ type: 'setSidebarWidth', width: 220 })
    separator = renderer!.root.findByProps({ role: 'separator' })
    act(() => separator.props.onKeyDown({ key: 'End', preventDefault: vi.fn() }))
    expect(intents[intents.length - 1]).toEqual({ type: 'setSidebarWidth', width: 560 })
  })

  it('uses the owning pointer screen coordinate and deduplicates clamped resize intents', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const separator = renderer!.root.findByProps({ role: 'separator' })
    const pointer = createPointerTarget()
    act(() =>
      separator.props.onPointerDown(
        pointerEvent(pointer.target, { screenX: 800, clientX: 12 }),
      ),
    )
    expect(pointer.captured.has(7)).toBe(true)
    expect(document.body.classList.contains('is-resizing-sidebar')).toBe(true)

    act(() =>
      separator.props.onPointerMove(
        pointerEvent(pointer.target, { screenX: 840, clientX: 12 }),
      ),
    )
    act(() =>
      separator.props.onPointerMove(
        pointerEvent(pointer.target, { screenX: 2_000, clientX: 12 }),
      ),
    )
    act(() =>
      separator.props.onPointerMove(
        pointerEvent(pointer.target, { screenX: 2_100, clientX: 12 }),
      ),
    )

    expect(intents.filter((intent) => intent.type === 'setSidebarWidth')).toEqual([
      { type: 'setSidebarWidth', width: 500 },
      { type: 'setSidebarWidth', width: 560 },
    ])
    act(() => separator.props.onPointerUp(pointerEvent(pointer.target, { buttons: 0 })))
    expect(pointer.target.releasePointerCapture).toHaveBeenCalledWith(7)
    expect(document.body.classList.contains('is-resizing-sidebar')).toBe(false)
  })

  it('preserves pointer resizing in the full-shell desktop layout', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('', intents)
    await mount()

    const separator = renderer!.root.findByProps({ role: 'separator' })
    const pointer = createPointerTarget()
    act(() =>
      separator.props.onPointerDown(
        pointerEvent(pointer.target, { screenX: 800, clientX: 20 }),
      ),
    )
    act(() =>
      separator.props.onPointerMove(
        pointerEvent(pointer.target, { screenX: 820, clientX: 20 }),
      ),
    )
    act(() => separator.props.onPointerUp(pointerEvent(pointer.target, { buttons: 0 })))

    expect(intents.filter((intent) => intent.type === 'setSidebarWidth')).toEqual([
      { type: 'setSidebarWidth', width: 480 },
    ])
    expect(document.body.classList.contains('is-resizing-sidebar')).toBe(false)
  })

  it('drops a captured resize when New Project suppresses the sidebar WebView', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const separator = renderer!.root.findByProps({ role: 'separator' })
    const pointer = createPointerTarget()
    act(() => separator.props.onPointerDown(pointerEvent(pointer.target)))
    act(() => renderer!.root.findByProps({ className: 'sidebar__new-project' }).props.onClick())

    // GTK/WebKit releases capture when the native overlay makes this WebView insensitive.
    pointer.captured.delete(7)
    act(() =>
      separator.props.onLostPointerCapture(pointerEvent(pointer.target, { buttons: 0 })),
    )
    expect(document.body.classList.contains('is-resizing-sidebar')).toBe(false)

    act(() =>
      separator.props.onPointerMove(pointerEvent(pointer.target, { screenX: 520 })),
    )
    expect(intents.filter((intent) => intent.type === 'setSidebarWidth')).toHaveLength(0)
    expect(intents.filter((intent) => intent.type === 'openProjectDialog')).toHaveLength(1)
  })

  it('ignores foreign pointers and self-cancels when the owner loses its primary button', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const separator = renderer!.root.findByProps({ role: 'separator' })
    const invalid = createPointerTarget()
    act(() =>
      separator.props.onPointerDown(
        pointerEvent(invalid.target, { pointerId: 1, button: 2 }),
      ),
    )
    act(() =>
      separator.props.onPointerDown(
        pointerEvent(invalid.target, { pointerId: 2, isPrimary: false }),
      ),
    )
    expect(invalid.target.setPointerCapture).not.toHaveBeenCalled()

    const owner = createPointerTarget()
    act(() => separator.props.onPointerDown(pointerEvent(owner.target)))
    act(() =>
      separator.props.onPointerMove(
        pointerEvent(owner.target, { pointerId: 8, screenX: 520 }),
      ),
    )
    expect(owner.captured.has(7)).toBe(true)

    act(() =>
      separator.props.onPointerMove(
        pointerEvent(owner.target, { buttons: 0, screenX: 520 }),
      ),
    )
    expect(owner.target.releasePointerCapture).toHaveBeenCalledWith(7)
    expect(owner.captured.has(7)).toBe(false)
    expect(document.body.classList.contains('is-resizing-sidebar')).toBe(false)
    expect(intents.filter((intent) => intent.type === 'setSidebarWidth')).toHaveLength(0)
  })

  it('releases an active sidebar pointer capture when the dashboard unmounts', async () => {
    installWindow('?chrome=sidebar', [])
    await mount()

    const separator = renderer!.root.findByProps({ role: 'separator' })
    const pointer = createPointerTarget()
    act(() => separator.props.onPointerDown(pointerEvent(pointer.target)))

    act(() => renderer?.unmount())
    renderer = null
    expect(pointer.target.releasePointerCapture).toHaveBeenCalledWith(7)
    expect(document.body.classList.contains('is-resizing-sidebar')).toBe(false)
  })

  it('never echoes native sidebar recovery updates back into the owner loop', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = installWindow('?chrome=sidebar', intents)
    await mount()

    act(() => {
      for (let index = 0; index < 266; index += 1) {
        browserWindow.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?.({
          width_logical_px: index % 2 === 0 ? 220 : 560,
          last_expanded_width_logical_px: 460,
        })
      }
    })

    expect(intents.filter((intent) => intent.type === 'setSidebarWidth')).toHaveLength(0)
  })

  it('revives a stashed pane once from its label while keeping the row click target', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const reviveIntents = (): Array<Record<string, unknown>> =>
      intents.filter((intent) => intent.type === 'reviveSession')
    const label = renderer!.root.findByProps({ title: 'Click to revive; use the grip to drag' })
    const row = label.parent
    expect(row?.props.className).toContain('tree-row--pane')
    expect(row?.props.onClick).toBeTypeOf('function')

    const stopPropagation = vi.fn()
    act(() => label.props.onClick({ detail: 1, stopPropagation }))

    expect(stopPropagation).toHaveBeenCalledOnce()
    expect(reviveIntents()).toEqual([
      {
        type: 'reviveSession',
        session_id: 's-stashed-1',
        window_id: 'w-stash',
        tab_id: 'tab-stashed',
      },
    ])

    const preventDefault = vi.fn()
    const stopRowPropagation = vi.fn()
    act(() =>
      row!.props.onClick({
        target: { closest: () => null },
        preventDefault,
        stopPropagation: stopRowPropagation,
      }),
    )

    expect(preventDefault).toHaveBeenCalledOnce()
    expect(stopRowPropagation).toHaveBeenCalledOnce()
    expect(reviveIntents()).toHaveLength(2)
    expect(reviveIntents()[1]).toEqual(reviveIntents()[0])
  })

  it('treats a click on an exited visible pane as explicit reopen authority', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const label = renderer!.root.findByProps({ title: 'Exited — click to reopen' })
    expect(label.props['aria-label']).toMatch(/^Reopen /)
    expect(label.parent?.props.className).toContain('is-restartable')
    expect(label.findByProps({ className: 'tree-pane__exit-status' }).children).toEqual(['Reopen'])
    const stopPropagation = vi.fn()
    act(() => label.props.onClick({ detail: 1, stopPropagation }))

    expect(stopPropagation).toHaveBeenCalledOnce()
    expect(intents.filter((intent) => intent.type === 'reviveSession')).toEqual([
      {
        type: 'reviveSession',
        session_id: 's-exited-1',
        window_id: 'w-main',
        tab_id: 'tab-old',
      },
    ])
    expect(intents.some((intent) => intent.type === 'focusSessionOrPane')).toBe(false)
  })

  it('reopens every visible exited pane when the user clicks an exited window', async () => {
    vi.useFakeTimers()
    const intents: Array<Record<string, unknown>> = []
    const initialModel = structuredClone(mockDashboardModel)
    const window = initialModel.details.sample_workspace.windows.find((item) => item.window_id === 'w-main')!
    window.tabs.forEach((tab) => {
      if (!tab.stashed) tab.session_status = 'exited'
    })
    installWindow('?chrome=sidebar', intents, initialModel)
    await mount()

    const label = renderer!.root.findByProps({ title: 'Exited — click to reopen window' })
    expect(label.props['aria-label']).toMatch(/^Reopen /)
    expect(label.parent?.props.className).toContain('is-restartable')
    expect(label.findByProps({ className: 'tree-window__count' }).children).toEqual(['Reopen'])
    act(() => label.props.onClick())
    act(() => {
      vi.runAllTimers()
    })

    expect(intents.filter((intent) => intent.type === 'reviveSession')).toEqual(
      window.tabs.map((tab) => ({
        type: 'reviveSession',
        session_id: tab.session_id,
        window_id: window.window_id,
        tab_id: tab.tab_id,
      })),
    )
    expect(intents.some((intent) => intent.type === 'focusWindow')).toBe(false)
  })

  it('sends only the native delete-project contract from the wider confirmation draft', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow('?chrome=sidebar', intents)
    await mount()

    const projectActions = renderer!.root.findAllByProps({ title: 'Project actions' })[0]
    act(() => projectActions.props.onClick())

    const deleteMenuItem = renderer!.root.find(
      (node) => node.props.role === 'menuitem' && node.children.join('') === 'Delete project…',
    )
    act(() => deleteMenuItem.props.onClick())

    expect(
      renderer!.root.findAll(
        (node) => node.type === 'strong' && node.children.join('') === 'Delete agent session history',
      ),
    ).toHaveLength(0)
    expect(
      renderer!.root.findAll(
        (node) => node.type === 'strong' && node.children.join('') === 'Delete project instruction file',
      ),
    ).toHaveLength(0)

    const confirm = renderer!.root.find(
      (node) => node.props.className === 'sidebar-create__danger',
    )
    act(() => confirm.props.onClick())

    const deleteIntent = intents.find((intent) => intent.type === 'deleteProject')
    expect(deleteIntent).toEqual({
      type: 'deleteProject',
      project_id: 'sample_workspace',
      remove_record: true,
      keep_working_directory: true,
      close_open_windows: true,
    })
    expect(deleteIntent).not.toHaveProperty('name')
    expect(deleteIntent).not.toHaveProperty('root')
    expect(deleteIntent).not.toHaveProperty('runtime_label')
    expect(deleteIntent).not.toHaveProperty('open_count')
  })
})
