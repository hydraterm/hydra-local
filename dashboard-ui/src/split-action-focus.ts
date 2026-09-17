import type { MouseEvent } from 'react'

/** Keep an editor's pending pre-click input on that editor, without delaying the action. */
export function preserveSplitEditorMouseFocus(
  event: MouseEvent<HTMLButtonElement>,
  composingEditor: EventTarget | null,
): void {
  const button = event.currentTarget
  if (
    event.defaultPrevented ||
    event.button !== 0 ||
    event.altKey || event.ctrlKey || event.metaKey || event.shiftKey ||
    button.disabled
  ) return

  const editor = button.ownerDocument.activeElement
  if (!(editor instanceof HTMLInputElement || editor instanceof HTMLTextAreaElement)) return
  if (
    editor instanceof HTMLInputElement &&
    !['text', 'search', 'email', 'url', 'tel', 'password'].includes(editor.type)
  ) return
  if (editor.disabled || editor.readOnly || editor === composingEditor) return
  const dialog = button.closest('[role="dialog"]')
  if (!dialog || editor.closest('[role="dialog"]') !== dialog) return

  // Only cancel the mouse-down focus default. Click/keyboard activation stays untouched.
  // During IME composition retain the existing blur/commit path instead.
  event.preventDefault()
}
