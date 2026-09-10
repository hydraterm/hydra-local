import { useEffect, useRef, useState } from 'react'
import { bridge } from '../ipc/bridge'
import { useDeferredFocusLoss } from './useDeferredFocusLoss'

type Props = {
  projectId: string
  windowId: string
  name: string
  onFinish: (restoreFocus: boolean) => void
}

export function InlineWindowRename({ projectId, windowId, name, onFinish }: Props): JSX.Element {
  const [draft, setDraft] = useState(name)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const editorRef = useRef<HTMLSpanElement>(null)
  const pendingRef = useRef(false)
  const finishedRef = useRef(false)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    inputRef.current?.focus()
    inputRef.current?.select()
    return () => {
      mountedRef.current = false
    }
  }, [])

  const finish = (restoreFocus: boolean): void => {
    focusLoss.cancel()
    finishedRef.current = true
    onFinish(restoreFocus)
  }
  const commit = (restoreFocus: boolean, explicit = false): void => {
    focusLoss.cancel()
    if (finishedRef.current || pendingRef.current || (error && !explicit)) return
    const value = draft.trim()
    if (!value || value === name) {
      finish(restoreFocus)
      return
    }
    pendingRef.current = true
    setSaving(true)
    setError(null)
    void bridge
      .renameWindow({ project_id: projectId, window_id: windowId, name: value })
      .then((result) => {
        if (!mountedRef.current || finishedRef.current) return
        pendingRef.current = false
        setSaving(false)
        if (result.ok) finish(restoreFocus)
        else setError(result.message || 'Window rename was declined. Your draft is kept.')
      })
  }
  const focusLoss = useDeferredFocusLoss(
    JSON.stringify([projectId, windowId]),
    editorRef,
    () => commit(false),
  )

  useEffect(() => {
    const outside = (event: PointerEvent): void => {
      if (!editorRef.current?.contains(event.target as Node)) commit(false)
    }
    document.addEventListener('pointerdown', outside, true)
    return () => document.removeEventListener('pointerdown', outside, true)
  })

  return (
    <span ref={editorRef} className={`window-tab__rename ${error ? 'has-error' : ''}`}>
      <input
        ref={inputRef}
        aria-label={`Rename ${name}`}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? 'window-rename-error' : undefined}
        aria-busy={saving}
        title="Enter saves; Escape cancels. Tab stays in the editor."
        value={draft}
        readOnly={saving}
        onChange={(event) => {
          setDraft(event.target.value)
          setError(null)
        }}
        onBlur={focusLoss.schedule}
        onKeyDown={(event) => {
          event.stopPropagation()
          if (event.key === 'Tab') event.preventDefault()
          if (event.nativeEvent.isComposing) return
          if (event.key === 'Enter') {
            event.preventDefault()
            commit(true, true)
          }
          if (event.key === 'Escape') {
            event.preventDefault()
            finish(true)
          }
        }}
      />
      {saving && (
        <span className="window-tab__rename-status" role="status">Saving…</span>
      )}
      {error && (
        <span id="window-rename-error" className="window-tab__rename-status" role="alert" title={error}>
          {error}
        </span>
      )}
    </span>
  )
}
