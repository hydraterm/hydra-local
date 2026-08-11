import type { DashboardModel } from '../types/model'
import type { DashboardHost, Intent } from './bridge'

export async function installDevHost(): Promise<void> {
  if (!import.meta.env.DEV) return

  const params = new URLSearchParams(window.location.search)
  if (params.get('host') !== '1') return

  const { mockDashboardModel } = await import('../data/mock')
  let model = mockDashboardModel
  const listeners = new Set<(next: DashboardModel) => void>()

  const publish = (): void => {
    for (const listener of listeners) listener(model)
  }

  const host: DashboardHost = {
    async getDashboardModel() {
      return model
    },

    postIntent(intent: Intent) {
      // eslint-disable-next-line no-console
      console.info('[dev native host intent]', intent.type)

      if (intent.type === 'preflightLaunch') {
        window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(intent.request_id, true, null)
      }

      if (intent.type === 'updateProjectOrder') {
        const byId = new Map(model.projects.map((project) => [project.project_id, project]))
        const projects = intent.ordered_project_ids
          .map((id) => byId.get(id))
          .filter((project): project is (typeof model.projects)[number] => Boolean(project))
        model = { ...model, projects }
        publish()
      }
      if (intent.type === 'updateProject') {
        model = {
          ...model,
          projects: model.projects.map((project) =>
            project.project_id === intent.project_id
              ? {
                  ...project,
                  name: intent.name ?? project.name,
                  icon: intent.icon ?? project.icon,
                  accent_color: intent.accent_color ?? project.accent_color,
                }
              : project,
          ),
          details: {
            ...model.details,
            [intent.project_id]: {
              ...model.details[intent.project_id],
              name: intent.name ?? model.details[intent.project_id]?.name,
              root: intent.root ?? model.details[intent.project_id]?.root,
              icon: intent.icon ?? model.details[intent.project_id]?.icon,
              accent_color:
                intent.accent_color ?? model.details[intent.project_id]?.accent_color,
            },
          },
        }
        publish()
      }
      if (intent.type === 'deleteProject') {
        model = {
          ...model,
          projects: model.projects.filter((project) => project.project_id !== intent.project_id),
          details: Object.fromEntries(
            Object.entries(model.details).filter(([id]) => id !== intent.project_id),
          ),
        }
        publish()
      }
    },

    onDashboardModel(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
  }

  window.hydraDashboard = host
}
