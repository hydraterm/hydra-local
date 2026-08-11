import { afterEach, describe, expect, it } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { AGENT_PROVIDERS } from '../model/agent-provider'
import type { AgentKind } from '../types/model'
import { AgentBadge } from './AgentBadge'

let renderer: ReactTestRenderer | null = null

afterEach(() => {
  if (renderer) {
    act(() => renderer?.unmount())
    renderer = null
  }
})

describe('AgentBadge', () => {
  it('renders the provider glyph at the requested size', () => {
    act(() => {
      renderer = create(<AgentBadge agent="claude" size={14} dim />)
    })

    const badge = renderer!.root.findByProps({ className: 'agent-badge' })
    expect(badge.props.title).toBe('Claude')
    expect(badge.props['data-agent']).toBe('claude')
    expect(badge.props.style).toMatchObject({ width: 14, height: 14, opacity: 0.5 })
    expect(badge.children).toEqual([AGENT_PROVIDERS.claude.glyph])
    expect(renderer!.root.findAllByType('img')).toHaveLength(0)
  })

  it('renders every provider and Shell without assigning or rendering an image', () => {
    const agents = [...Object.keys(AGENT_PROVIDERS), 'shell'] as AgentKind[]
    for (const agent of agents) {
      act(() => {
        renderer = create(<AgentBadge agent={agent} size={12} />)
      })

      expect(renderer!.root.findAllByType('img')).toHaveLength(0)
      expect(renderer!.root.findByProps({ className: 'agent-badge' }).children).toEqual([
        agent === 'shell' ? AGENT_PROVIDERS.terminal.glyph : AGENT_PROVIDERS[agent].glyph,
      ])

      act(() => renderer?.unmount())
      renderer = null
    }
  })
})
