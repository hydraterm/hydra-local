export function LoadingState(): JSX.Element {
  return (
    <div className="fullscreen">
      <div className="spinner" aria-hidden />
      <div className="fullscreen__label">Loading dashboard…</div>
    </div>
  )
}

export function ErrorState({ message }: { message: string }): JSX.Element {
  return (
    <div className="fullscreen fullscreen--error">
      <div className="fullscreen__icon">⚠</div>
      <div className="fullscreen__label">Failed to load dashboard</div>
      <pre className="fullscreen__detail">{message}</pre>
    </div>
  )
}

export function EmptyState({ title, hint }: { title: string; hint: string }): JSX.Element {
  return (
    <div className="empty">
      <div className="empty__title">{title}</div>
      <div className="empty__hint">{hint}</div>
    </div>
  )
}
