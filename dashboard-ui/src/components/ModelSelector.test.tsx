import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { ModelSelector, agentModelOptions, modelDeprecation } from './ModelSelector'
import type { ModelCatalog } from '../types/model'

const catalog: ModelCatalog = {
  agents: { claude: ['sonnet', 'future-model'] },
  deprecations: {
    claude: {
      sonnet: {
        since_revision: 7,
        message: 'Sonnet is leaving the stable catalog.',
      },
      'future-model': {
        since_revision: 8,
        message: 'Future model is being retired.',
        replacement: 'next-model',
      },
    },
    unknown: {
      sonnet: {
        since_revision: 9,
        message: 'Must not leak into Claude.',
      },
    },
  },
}

let renderer: ReactTestRenderer | null = null

afterEach(() => {
  if (renderer) {
    act(() => renderer?.unmount())
    renderer = null
  }
})

describe('model selector deprecations', () => {
  it('preserves option order and marks built-in and downloaded deprecated models', () => {
    const options = agentModelOptions('claude', catalog)
    expect(options.filter((option) => option.value === 'sonnet')).toEqual([
      { value: 'sonnet', label: 'sonnet (deprecated)' },
    ])
    expect(options[options.length - 1]).toEqual({
      value: 'future-model',
      label: 'future-model (deprecated)',
    })
    expect(options.filter((option) => option.value === 'sonnet')).toHaveLength(1)
  })

  it('renders bounded catalog messages as text with and without replacement guidance', () => {
    const onValue = vi.fn()
    act(() => {
      renderer = create(
        <ModelSelector
          agent="claude"
          catalog={catalog}
          value="sonnet"
          ariaLabel="Test model"
          onValue={onValue}
        />,
      )
    })
    let notice = renderer!.root.findByProps({ role: 'note' })
    expect(notice.children.join('')).toBe('Sonnet is leaving the stable catalog.')
    expect(renderer!.root.findAllByType('a')).toHaveLength(0)

    act(() => {
      renderer!.update(
        <ModelSelector
          agent="claude"
          catalog={catalog}
          value="future-model"
          ariaLabel="Test model"
          onValue={onValue}
        />,
      )
    })
    notice = renderer!.root.findByProps({ role: 'note' })
    expect(notice.children.join('')).toBe(
      'Future model is being retired. Suggested replacement: next-model.',
    )
    expect(renderer!.root.findAllByType('a')).toHaveLength(0)
  })

  it('keeps missing and unrelated metadata out of the selected provider', () => {
    expect(modelDeprecation('claude', 'opus', undefined)).toBeNull()
    const unrelatedCatalog: ModelCatalog = {
      deprecations: { unknown: catalog.deprecations!.unknown },
    }
    expect(modelDeprecation('claude', 'sonnet', unrelatedCatalog)).toBeNull()

    act(() => {
      renderer = create(
        <ModelSelector
          agent="claude"
          catalog={null}
          value="sonnet"
          ariaLabel="Test model"
          onValue={() => undefined}
        />,
      )
    })
    expect(renderer!.root.findAllByProps({ role: 'note' })).toHaveLength(0)
  })
})
