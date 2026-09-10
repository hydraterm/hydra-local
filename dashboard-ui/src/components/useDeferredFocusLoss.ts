import { useCallback, useEffect, useRef, type RefObject } from 'react'

/** Keep a native accessibility focus round-trip from tearing down its own input. */
export function useDeferredFocusLoss(
  identity: string | null,
  editorRef: RefObject<HTMLElement>,
  onCommit: () => void,
): { schedule: () => void; cancel: () => void } {
  const latestRef = useRef({ identity, onCommit })
  latestRef.current = { identity, onCommit }
  const timerRef = useRef<number | null>(null)
  const generationRef = useRef(0)

  const cancel = useCallback((): void => {
    generationRef.current++
    if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    timerRef.current = null
  }, [])

  const schedule = useCallback((): void => {
    if (identity === null || timerRef.current !== null) return
    const generation = generationRef.current
    // AT-SPI briefly clears focus before restoring it. WebKit can crash if a blur handler
    // removes that input synchronously; use the next event-loop task, not a microtask.
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null
      if (generation !== generationRef.current || identity !== latestRef.current.identity) return
      const editor = editorRef.current
      if (!editor || (document.hasFocus() && editor.contains(document.activeElement))) return
      latestRef.current.onCommit()
    }, 0)
  }, [identity, editorRef])

  useEffect(() => {
    if (identity === null) return cancel
    // Native terminal focus leaves the WebView, not the DOM. WebKit emits window blur
    // without the input focusout event React uses for onBlur at this boundary.
    window.addEventListener('blur', schedule)
    return () => {
      window.removeEventListener('blur', schedule)
      cancel()
    }
  }, [identity, schedule, cancel])

  return { schedule, cancel }
}
