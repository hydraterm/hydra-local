import { describe, expect, it } from 'vitest'
import sidebarSource from './Sidebar.tsx?raw'
import dashboardStyles from '../styles.css?raw'

describe('Sidebar native dialog boundary', () => {
  it('does not carry the retired inline project/window forms or synthetic session projections', () => {
    for (const retiredSource of [
      'showCreateProject',
      'ProjectCreateDraft',
      'newWindowDraft',
      'NewWindowDraft',
      'Math.max(24',
      '* 137',
      '17 * 60_000',
    ]) {
      expect(sidebarSource).not.toContain(retiredSource)
    }
  })

  it('does not carry CSS families that belonged only to the retired forms', () => {
    for (const retiredSelector of [
      '.sidebar-field',
      '.sidebar-dir-',
      '.sidebar-agent',
      '.sidebar-pill',
      '.sidebar-check',
      '.sidebar-launch-preview',
      '.sidebar-icon',
      '.sidebar-color',
      '.sidebar-create__primary',
      '.session-picker__preview',
    ]) {
      expect(dashboardStyles).not.toContain(retiredSelector)
    }
  })
})
